"""Sandbox shared by the lifecycle and upgrade black-box suites.

A sandbox is an isolated Onebox installation under one temporary directory:
every path override points inside it, ``ONEBOX_INIT=none`` makes Onebox run
its own daemon supervisor instead of an init system, and the ``PATH`` the
suite gives Onebox contains only *recorder* helpers
(``_lifecycle_fixtures``). Each helper logs its argv to ``commands.jsonl``
and then emulates a host tool against files inside the sandbox (``ip``,
``ufw``, ``firewall-cmd``, ``nft``, ``iptables``/``ip6tables``, ``crontab``,
``tail``, an offline ``curl``), passes a read-only tool through (``openssl``,
``uname``, ``id``, ``getent``) or refuses: package managers, init tools,
``wget``, shells, interpreters, ``sysctl``, and every emulated tool called
with arguments it does not emulate, print ``BLOCKED …``, are logged to
``refused.jsonl`` and exit 97. :meth:`Sandbox.forbidden_calls` reports all
of them.

That PATH does not reach everything: Onebox also searches the fixed
``SAFE_PATH`` and starts its daemons and oneshots with ``PATH=SAFE_PATH``.
``_lifecycle_host`` covers that gap: each sandbox snapshots the host firewall
and root's crontab when it is created and fails its cleanup when they
changed, and a suite running as root first masks the host-changing programs
of ``SAFE_PATH`` with logging tripwires (:func:`_lifecycle_host.seal`).

Changes from the v2 helpers (tests/native_lifecycle.py):
- the start-failure counter lives next to the configuration
  (``<ONEBOX_DIR>/../fail-start``): v3 daemons never inherit the caller's
  environment (v2 bug E-8.1#3), so ``ONEBOX_TEST_START_FAILURES`` cannot
  reach them;
- ``commands.jsonl`` rows are objects ``{"argv": [...], "caller": ...}``
  naming the executable that ran the command (v2 or v3), and refused calls
  are reported even when Onebox tolerated the failure;
- ``curl`` is an offline network instead of a blocked program: public-address
  probes fail like a host without connectivity, and only URLs registered with
  ``Sandbox.serve_downloads`` are "downloaded" (the v2 self-update flow);
- ``id``/``getent`` pass through (the v2 subscription needs the nginx worker
  identity); a *hang point* freezes one helper call so a suite can crash an
  apply at a deterministic stage;
- the host itself is guarded (above);
- cleanup kills every process whose executable or command line lies inside
  the sandbox (v2 only matched the core).
"""
from __future__ import annotations

import contextlib
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import socket
import subprocess
import sys
import time
import urllib.parse
from typing import Iterable, Iterator, Mapping, Sequence

import _lifecycle_fixtures as fx
from _lifecycle_fixtures import BLOCKED
import _lifecycle_host as host

# Address probes Onebox may attempt (they fail offline and are tolerated).
ADDRESS_PROBES = ("https://api.ipify.org", "https://api6.ipify.org")

# Path overrides (relative to the sandbox root). v2 ignores the ones it does
# not know (BBR).
LAYOUT = {
    "ONEBOX_DIR": "etc",
    "ONEBOX_BIN_DIR": "bin",
    "ONEBOX_LOG_DIR": "log",
    "ONEBOX_RUN_DIR": "run",
    "ONEBOX_SITE_ROOT": "www",
    "ONEBOX_SYSTEMD_DIR": "systemd",
    "ONEBOX_INITD_DIR": "initd",
    "ONEBOX_EXE": "manager/onebox",
    "ONEBOX_FRPS_DIR": "frp/etc",
    "ONEBOX_FRPS_BIN_DIR": "frp/bin",
    "ONEBOX_FRPS_WEB_VAR": "frp/www",
    "ONEBOX_FRPS_LOG_DIR": "frp/log",
    "ONEBOX_FRPS_RUN_DIR": "frp/run",
    "ONEBOX_BBR_DIR": "bbr",
    "ONEBOX_BBR_CONF": "sysctl.d/99-onebox-bbr.conf",
}
# Variables never inherited from the caller (besides every ONEBOX_*).
STRIPPED = ("GH_PROXY", "GH_TOKEN", "GITHUB_TOKEN", "BASH_ENV", "ENV", "CF_Token", "CF_Account_ID",
            "CF_Key", "CF_Email", "ACME_HOME", "TMPDIR", "NO_COLOR", "LANG", "LC_ALL", "LANGUAGE")
# sun_path is 108 bytes; v2 refuses socket paths over 100 bytes.
SOCKET_PATH_MAX = 100
# File descriptor of an inherited node lock (v2 update-script protocol).
INHERITED_LOCK_FD = 198
REPOSITORY = "mutsuki14/Sing-xray-onebox"


class SandboxError(AssertionError):
    """A sandbox expectation failed."""


def require_full() -> bool:
    """ONEBOX_TEST_REQUIRE_FULL=1 turns every skip into a failure (CI)."""
    return os.environ.get("ONEBOX_TEST_REQUIRE_FULL") == "1"


def skip_or_fail(reason: str) -> None:
    """Print a skip, or fail under ONEBOX_TEST_REQUIRE_FULL=1."""
    if require_full():
        raise SandboxError(f"ONEBOX_TEST_REQUIRE_FULL=1 but {reason}")
    print(f"SKIP {reason}")


def full_run_blocker() -> str | None:
    """Why the root-only phases cannot run here, or None."""
    if os.geteuid() != 0:
        return "the full phase requires root"
    if not proc_matches(os.getpid(), sys.executable):
        return "the PID namespace and the mounted /proc do not match"
    return None


def seal_host(work: Path) -> host.Tripwire | None:
    """Mask the host programs (``_lifecycle_host.seal``) for the rest of
    this process; None (a skip, or a failure under
    ONEBOX_TEST_REQUIRE_FULL=1) when this host cannot."""
    try:
        return host.seal(work)
    except host.SealUnavailable as reason:
        skip_or_fail(f"host programs are not masked: {reason}")
        return None


def proc_matches(pid: int, executable: str | os.PathLike) -> bool:
    """True when /proc/PID/exe is EXECUTABLE."""
    try:
        return Path(f"/proc/{pid}/exe").resolve() == Path(executable).resolve()
    except OSError:
        return False


def executable(value: str | None, what: str) -> Path | None:
    """VALUE as an existing executable file, None when unset."""
    if not value:
        return None
    path = Path(value).resolve()
    if not path.is_file() or not os.access(path, os.X_OK):
        raise SandboxError(f"{what} is not an executable file: {path}")
    return path


def free_port(used: set[int], start: int = 22000, end: int = 32000) -> int:
    """A port free for TCP and UDP on all addresses, outside USED."""
    for port in range(start, end):
        if port in used:
            continue
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as tcp, \
                    socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                tcp.bind(("0.0.0.0", port))
                udp.bind(("0.0.0.0", port))
        except OSError:
            continue
        used.add(port)
        return port
    raise SandboxError("no free test port")


def port_open(port: int) -> bool:
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=0.2):
            return True
    except OSError:
        return False


def wait_listening(port: int, expected: bool = True, timeout: float = 8.0) -> None:
    """Wait until 127.0.0.1:PORT accepts (or refuses) TCP connections."""
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if port_open(port) == expected:
            return
        time.sleep(0.05)
    raise SandboxError(f"port {port}: expected listening={expected}")


def http_get(url: str, timeout: float = 5.0) -> tuple[int, bytes]:
    """Plain HTTP GET (no proxy): (status, body)."""
    import http.client

    parts = urllib.parse.urlsplit(url)
    if parts.scheme != "http" or not parts.hostname:
        raise SandboxError(f"not a plain HTTP URL: {url}")
    conn = http.client.HTTPConnection(parts.hostname, parts.port or 80, timeout=timeout)
    try:
        conn.request("GET", parts.path or "/")
        response = conn.getresponse()
        return response.status, response.read()
    finally:
        conn.close()


def wait_http(url: str, status: int = 200, timeout: float = 8.0) -> bytes:
    """Poll URL until it answers STATUS; returns the body."""
    end = time.monotonic() + timeout
    last: object = None
    while time.monotonic() < end:
        try:
            got, body = http_get(url)
            if got == status:
                return body
            last = got
        except OSError as error:
            last = error
        time.sleep(0.1)
    raise SandboxError(f"{url}: expected HTTP {status}, last result {last!r}")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_file(path: Path) -> str:
    return sha256_bytes(path.read_bytes())


def tree_digest(root: Path, exclude: Iterable[str] = ()) -> dict[str, str]:
    """Relative path → kind, mode and content digest for a whole tree.

    EXCLUDE holds relative paths (files or whole subtrees) that change
    legitimately; symlinks are recorded by target.
    """
    skipped = tuple(exclude)
    result: dict[str, str] = {}
    if not root.exists():
        return result
    for path in sorted(root.rglob("*")):
        rel = path.relative_to(root).as_posix()
        if any(rel == s or rel.startswith(s + "/") for s in skipped):
            continue
        mode = oct(path.lstat().st_mode & 0o7777)
        if path.is_symlink():
            result[rel] = f"link {os.readlink(path)}"
        elif path.is_dir():
            result[rel] = f"dir {mode}"
        elif path.is_socket():
            result[rel] = f"socket {mode}"
        else:
            result[rel] = f"file {mode} {sha256_file(path)}"
    return result


def describe_diff(before: Mapping[str, str], after: Mapping[str, str]) -> str:
    """One line per path whose entry differs."""
    lines = [f"  {key}: {before.get(key)} -> {after.get(key)}"
             for key in sorted(set(before) | set(after)) if before.get(key) != after.get(key)]
    return "\n".join(lines)


def assert_same_tree(before: Mapping[str, str], after: Mapping[str, str], what: str) -> None:
    if before != after:
        raise SandboxError(f"{what} changed:\n{describe_diff(before, after)}")


def release_arch() -> str:
    """Release asset architecture of this machine (v2/v3 naming)."""
    machine = platform.machine()
    names = {"x86_64": "amd64", "amd64": "amd64", "aarch64": "arm64", "arm64": "arm64",
             "i686": "386", "i586": "386", "i386": "386", "armv7l": "armv7"}
    if machine not in names:
        raise SandboxError(f"no release asset for {machine}")
    return names[machine]


class Sandbox:
    """One isolated Onebox installation (see the module documentation).

    TRIPWIRE is the suite's :func:`seal_host` result (None when unsealed);
    HOST_PROBES replaces the host-state probes (tests).
    """

    def __init__(self, root: Path, binary: Path, core: Path, *, front: Path | None = None,
                 tripwire: host.Tripwire | None = None,
                 host_probes: Sequence[Sequence[str]] | None = None):
        self.root, self.binary, self.core = root, binary, core
        self.tripwire = tripwire
        self._tripwire_seen = len(tripwire.calls()) if tripwire else 0
        self._host_probes = host.host_probes() if host_probes is None else host_probes
        self._host_before = host.host_state(self._host_probes)
        root.mkdir(parents=True)
        for rel in ("tmp", "home"):
            (root / rel).mkdir(mode=0o700)
        socket_path = self.run_dir / "subscription.sock"
        if len(str(socket_path).encode()) > SOCKET_PATH_MAX:
            raise SandboxError(f"sandbox path too long for Unix sockets: {socket_path} "
                               "(use a shorter TMPDIR)")
        self.env = self._environment(front)
        self.helpers.mkdir()
        fx.install_recorders(self.helpers, self.root)

    def _environment(self, front: Path | None) -> dict[str, str]:
        env = {k: v for k, v in os.environ.items()
               if not k.startswith("ONEBOX_") and k not in STRIPPED}
        env.update({k: str(self.root / v) for k, v in LAYOUT.items()})
        env.update(
            ONEBOX_INIT="none",
            ONEBOX_AUTO="1",
            ONEBOX_SINGBOX_BIN=str(self.core),
            HOME=str(self.root / "home"),
            TMPDIR=str(self.root / "tmp"),
            NO_COLOR="1",
            LANG="C.UTF-8",
            PATH=str(self.helpers),
        )
        if front:
            env["ONEBOX_NGINX_BIN"] = str(front)
        return env

    # ----- layout -------------------------------------------------------

    @property
    def helpers(self) -> Path:
        return self.root / "helpers"

    @property
    def etc(self) -> Path:
        return self.root / "etc"

    @property
    def run_dir(self) -> Path:
        return self.root / "run"

    @property
    def exe(self) -> Path:
        return self.root / "manager/onebox"

    @property
    def state_path(self) -> Path:
        return self.etc / "state.json"

    @property
    def journal_dir(self) -> Path:
        return self.etc / ".transaction"

    @property
    def lock_path(self) -> Path:
        return self.etc / ".apply.lock"

    # ----- running Onebox ----------------------------------------------

    def run(self, *args: str, success: bool | None = True, binary: Path | None = None,
            env: Mapping[str, str] | None = None, pass_fds: Sequence[int] = (),
            timeout: float = 180) -> subprocess.CompletedProcess:
        """Run Onebox (v3 unless BINARY) with --yes appended.

        SUCCESS: True requires exit 0, False a non-zero exit, None anything.
        """
        program = binary or self.binary
        argv = [str(program), *args, "--yes"]
        proc = subprocess.run(argv, env=dict(self.env, **(env or {})), stdin=subprocess.DEVNULL,
                              capture_output=True, text=True, timeout=timeout,
                              pass_fds=tuple(pass_fds))
        label = f"{program.name} {' '.join(args)}"
        if success is True and proc.returncode:
            raise SandboxError(f"{label} failed ({proc.returncode}):\n"
                               f"{proc.stderr[-6000:]}\n{proc.stdout[-2000:]}")
        if success is False and not proc.returncode:
            raise SandboxError(f"{label} unexpectedly succeeded:\n"
                               f"{proc.stderr[-3000:]}\n{proc.stdout[-2000:]}")
        return proc

    def spawn(self, *args: str, binary: Path | None = None,
              pass_fds: Sequence[int] = ()) -> subprocess.Popen:
        """Start Onebox in the background (crash tests)."""
        program = binary or self.binary
        return subprocess.Popen([str(program), *args, "--yes"], env=self.env,
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True, pass_fds=tuple(pass_fds))

    @contextlib.contextmanager
    def hold_node_lock(self) -> Iterator[dict[str, str]]:
        """Hold ROOT/.apply.lock on fd 198, as v2's update-script does.

        Yields the environment entry announcing the inherited lock; pass it
        with ``pass_fds=(INHERITED_LOCK_FD,)``.
        """
        fd = os.open(self.lock_path, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            os.dup2(fd, INHERITED_LOCK_FD, inheritable=True)
            try:
                yield {"ONEBOX_INHERITED_LOCK_FD": str(INHERITED_LOCK_FD)}
            finally:
                os.close(INHERITED_LOCK_FD)
        finally:
            os.close(fd)

    def install_exe(self, binary: Path) -> None:
        """Atomically replace the installed manager (as a self-update does)."""
        temp = self.exe.with_name(".onebox-test-new")
        shutil.copyfile(binary, temp)
        temp.chmod(0o755)
        os.replace(temp, self.exe)

    # ----- observations -------------------------------------------------

    def state(self) -> dict:
        return json.loads(self.state_path.read_text())

    def _rows(self, name: str) -> list[dict]:
        log = self.root / name
        if not log.exists():
            return []
        return [json.loads(line) for line in log.read_text().splitlines() if line]

    def commands(self) -> list[dict]:
        """Every call of a helper (``commands.jsonl``)."""
        return self._rows("commands.jsonl")

    def refused(self) -> list[dict]:
        """Every call a helper refused (``refused.jsonl``)."""
        return self._rows("refused.jsonl")

    def tripwire_calls(self) -> list[dict]:
        """Host programs reached since this sandbox was created (read-only
        probes, which the tripwire refuses quietly, left out)."""
        calls = self.tripwire.calls()[self._tripwire_seen:] if self.tripwire else []
        return [row for row in calls if not row.get("probe")]

    def take_tripwire_calls(self) -> list[list[str]]:
        """The host programs reached so far, acknowledged: later checks no
        longer report them (for a deliberate escape, see lifecycle.py)."""
        calls = [row["argv"] for row in self.tripwire_calls()]
        self._tripwire_seen = len(self.tripwire.calls()) if self.tripwire else 0
        return calls

    def forbidden_calls(self) -> list[list[str]]:
        """Calls that must never happen: blocked programs, refused calls of
        emulated programs, curl for anything but an address probe or a served
        download, and host programs reached through a tripwire."""
        served_file = self.root / "downloads.json"
        served = json.loads(served_file.read_text()) if served_file.exists() else {}
        bad = []
        for row in self.commands():
            argv = row["argv"]
            if argv[0] in BLOCKED:
                bad.append(argv)
            elif argv[0] == "curl" and argv[-1] not in ADDRESS_PROBES and argv[-1] not in served:
                bad.append(argv)
        # A blocked program is refused too; it is already listed above.
        bad += [row["argv"] for row in self.refused() if row["argv"][0] not in BLOCKED]
        bad += [["(host)", *row["argv"]] for row in self.tripwire_calls()]
        return bad

    def crontab(self) -> list[str]:
        table = self.root / "crontab.txt"
        return table.read_text().splitlines() if table.exists() else []

    def firewall_rules(self) -> dict[str, list]:
        return {p.name: json.loads(p.read_text()) for p in sorted(self.root.glob("ip*tables-*.json"))}

    def assert_proxy_ports_open(self, ports: Iterable[int]) -> None:
        """Each TCP PORT has an ``onebox-proxy-*`` ACCEPT rule in every
        emulated iptables filter table, recorded under the same token in the
        ``firewall-v2.json`` ledger (ARCH §7.4: v2 and v3 share it)."""
        ledger = json.loads((self.etc / "firewall-v2.json").read_text())["rules"]
        tables = {name: rows for name, rows in self.firewall_rules().items()
                  if name.endswith("-filter.json")}
        if not tables:
            raise SandboxError("no iptables filter rules at all")
        for name, rows in tables.items():
            accepted = {}
            for row in rows:
                if row[-2:] != ["-j", "ACCEPT"] or "--comment" not in row or "--dport" not in row:
                    continue
                token = row[row.index("--comment") + 1]
                first, _, last = row[row.index("--dport") + 1].partition(":")
                if token.startswith("onebox-proxy-") and "tcp" in row:
                    accepted.update({p: token for p in range(int(first), int(last or first) + 1)})
            for port in ports:
                token = accepted.get(port)
                if token is None:
                    raise SandboxError(f"{name}: TCP port {port} is not opened: {rows}")
                if not any(r["token"] == token and r["port"] <= port <= r["end"] and not r["udp"]
                           for r in ledger):
                    raise SandboxError(f"firewall-v2.json does not record {token} (port {port})")

    def logs(self) -> list[str]:
        """Names of the files in ``log/`` (one per service that ran)."""
        log = self.root / "log"
        return sorted(p.name for p in log.iterdir()) if log.is_dir() else []

    def pid_record(self, service: str) -> dict | None:
        """The supervisor's PID record of SERVICE, None when absent."""
        try:
            raw = json.loads((self.run_dir / f"{service}.pid").read_text())
        except (OSError, ValueError):
            return None
        return raw if isinstance(raw, dict) else {"pid": raw}

    def service_pid(self, service: str) -> int | None:
        """PID of SERVICE when its record names a live process."""
        record = self.pid_record(service)
        if not record:
            return None
        pid = int(record.get("pid", 0))
        fields = _stat_fields(pid)
        if not fields or fields[0] == "Z":
            return None
        if "start" in record and int(fields[19]) != int(record["start"]):
            return None
        return pid

    def process_exe(self, pid: int) -> Path:
        return Path(os.readlink(f"/proc/{pid}/exe").removesuffix(" (deleted)"))

    # ----- fault injection ---------------------------------------------

    def fail_starts(self, count: int) -> None:
        """Make the next COUNT fixture-core starts exit 74."""
        (self.root / "fail-start").write_text(str(count))

    @contextlib.contextmanager
    def hang(self, program: str, *args: str) -> Iterator:
        """Freeze the next call of PROGRAM (with leading ARGS).

        Yields ``wait(timeout) -> pid`` returning once a helper is frozen;
        leaving the block removes the hang point and kills that helper.
        """
        marker, pidfile = self.root / "hang-point", self.root / "hang.pid"
        pidfile.unlink(missing_ok=True)
        marker.write_text(" ".join((program, *args)))

        def wait(timeout: float = 60) -> int:
            end = time.monotonic() + timeout
            while time.monotonic() < end:
                with contextlib.suppress(OSError, ValueError):
                    return int(pidfile.read_text())
                time.sleep(0.05)
            raise SandboxError(f"hang point {program} {' '.join(args)} never reached")

        try:
            yield wait
        finally:
            marker.unlink(missing_ok=True)
            with contextlib.suppress(OSError, ValueError):
                os.kill(int(pidfile.read_text()), signal.SIGKILL)
            pidfile.unlink(missing_ok=True)

    def serve_downloads(self, files: Mapping[str, Path]) -> None:
        """Let the curl helper "download" FILES (exact URL → local file)."""
        (self.root / "downloads.json").write_text(json.dumps({k: str(v) for k, v in files.items()}))

    def publish_release(self, binary: Path, version: str) -> None:
        """Serve a GitHub release of BINARY as the latest stable Onebox."""
        tag, name = f"v{version}", f"onebox-linux-{release_arch()}-musl"
        url = f"https://github.com/{REPOSITORY}/releases/download/{tag}/{name}"
        data = binary.read_bytes()
        release = {
            "tag_name": tag, "draft": False, "prerelease": False,
            "body": f"Onebox {version} (sandbox fixture release)",
            "assets": [{"name": name, "browser_download_url": url, "size": len(data),
                        "digest": "sha256:" + sha256_bytes(data)}],
        }
        meta = self.root / "release.json"
        meta.write_text(json.dumps(release))
        self.serve_downloads({
            f"https://api.github.com/repos/{REPOSITORY}/releases/latest": meta,
            url: binary,
        })

    # ----- cleanup -----------------------------------------------------

    def processes(self) -> list[int]:
        """PIDs whose executable or command line lies inside the sandbox
        (whole path components: ``<root>-v1`` is another sandbox)."""
        exact = str(self.root).encode()
        inside = exact + b"/"
        found = []
        for entry in Path("/proc").iterdir():
            if not entry.name.isdigit() or int(entry.name) == os.getpid():
                continue
            try:
                cmdline = (entry / "cmdline").read_bytes()
                exe = os.readlink(entry / "exe").encode()
            except OSError:
                continue
            if exe.startswith(inside) or inside in cmdline or exact in cmdline.split(b"\0"):
                found.append(int(entry.name))
        return found

    def cleanup(self) -> None:
        """Terminate every sandbox process (SIGTERM, then SIGKILL), then
        fail if the host changed or a host program was reached."""
        for sig in (signal.SIGTERM, signal.SIGKILL):
            pids = self.processes()
            for pid in pids:
                with contextlib.suppress(OSError):
                    os.kill(pid, sig)
            end = time.monotonic() + 3
            while pids and time.monotonic() < end:
                pids = [p for p in pids if (f := _stat_fields(p)) and f[0] != "Z"]
                time.sleep(0.05)
        self.check_host()

    def check_host(self) -> None:
        """Fail when the host state differs from the sandbox's creation or a
        process reached a host program through a tripwire."""
        problems = host.state_changes(self._host_before, host.host_state(self._host_probes))
        problems += [f"host program called: {row}" for row in self.tripwire_calls()]
        if problems:
            raise SandboxError(f"sandbox {self.root.name} reached the host:\n" + "\n".join(problems))


def _stat_fields(pid: int) -> list[str] | None:
    """/proc/PID/stat fields after the command name (state first)."""
    try:
        return Path(f"/proc/{pid}/stat").read_text().rsplit(")", 1)[1].split()
    except (OSError, IndexError):
        return None
