#!/usr/bin/env python3
"""Base helpers of the black-box suites in tests/e2e (not a suite itself).

Every suite drives the real ``onebox`` binary and real proxy cores against
loopback-only fixtures. The shared helpers are split into modules whose
names start with ``_`` (CI runs every other file in tests/e2e as a suite):

* ``_harness`` (this module): the CI tool contract (:func:`tool`,
  :data:`REQUIRE_FULL`, :func:`resolve_tools`), :class:`Results` (PASS /
  FAIL / SKIP records, summary line, JSON report, exit status),
  :func:`run`, :class:`Workspace`, :class:`Ports` and :class:`Process`;
* ``_fixtures``: throw-away PKI, marker HTTP/TLS/UDP servers, the DNS
  fixture, the SOCKS5 client and direct TLS checks;
* ``_yaml``: a strict reader for exactly the YAML subset the v3 mihomo
  renderer emits;
* ``_node``: the isolated Onebox layout, :func:`run_onebox` and
  :class:`FixtureNode` (one node as a v2 ``{"values"}`` or v3 schema-3
  state);
* ``_bench``: proxy-core configurations and :class:`Bench`, the fixtures a
  proxy suite shares;
* ``_selftest``: runs every module's self-tests (``python3
  tests/e2e/_selftest.py``); each suite also runs them first and records
  ``harness/self-test``, so they run under the CI suite contract.

Contract with CI: ``ONEBOX_TEST_BINARY``, ``ONEBOX_TEST_SINGBOX``,
``ONEBOX_TEST_XRAY`` and ``ONEBOX_TEST_MIHOMO`` name executables; with
``ONEBOX_TEST_REQUIRE_FULL=1`` a missing tool, privilege or other skip
reason is a failure, never a skip; a suite exits non-zero on any failure
and always prints its summary line. Python 3.8 or later.
"""
from __future__ import annotations

import argparse
import contextlib
import dataclasses
import io
import json
import os
import random
import shutil
import signal
import socket
import subprocess
import tempfile
import time
import unittest
import unittest.mock
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
REQUIRE_FULL = os.environ.get("ONEBOX_TEST_REQUIRE_FULL") == "1"
VERBOSE = os.environ.get("VERBOSE") == "1"
LOOPBACK = "127.0.0.1"


# ---------------------------------------------------------------------------
# Tool contract and results


class Unavailable(Exception):
    """A prerequisite (tool, privilege) is missing: skip, or fail under REQUIRE_FULL."""


class Misconfigured(Exception):
    """A tool variable is set but does not name an executable: always a failure."""


def tool(env_var: str, *, path_names: tuple[str, ...] = (), default: str | None = None) -> str:
    """Return the executable named by ``env_var`` (absolute, resolved).

    A set but unusable variable raises :class:`Misconfigured`. An unset
    variable falls back to ``default`` and then to ``path_names`` on
    ``PATH`` unless ``ONEBOX_TEST_REQUIRE_FULL=1``, where CI must name every
    tool explicitly. Raises :class:`Unavailable` when nothing is found.
    """
    value = os.environ.get(env_var)
    if value:
        path = Path(value).expanduser().resolve()
        if not path.is_file() or not os.access(path, os.X_OK):
            raise Misconfigured(f"{env_var} is not an executable file: {value}")
        return str(path)
    if REQUIRE_FULL:
        raise Unavailable(f"{env_var} is not set (ONEBOX_TEST_REQUIRE_FULL=1)")
    candidates = [default] if default else []
    candidates += [found for name in path_names if (found := shutil.which(name))]
    for candidate in candidates:
        path = Path(candidate).resolve()
        if path.is_file() and os.access(path, os.X_OK):
            return str(path)
    raise Unavailable(f"set {env_var} to an executable")


def onebox_binary() -> str:
    """``ONEBOX_TEST_BINARY``, default ``<repo>/target/debug/onebox``."""
    return tool("ONEBOX_TEST_BINARY", default=str(REPO / "target/debug/onebox"))


class Results:
    """Ordered check results of one suite run."""

    def __init__(self, title: str):
        self.title = title
        self.entries: list[dict] = []

    def record(self, name: str, ok: bool, detail: str = "") -> bool:
        self.entries.append({"name": name, "ok": bool(ok), "detail": detail})
        line = f"{'PASS' if ok else 'FAIL'} {name}" + (f": {detail}" if detail else "")
        print(line, flush=True)
        return bool(ok)

    def skip(self, name: str, reason: str) -> None:
        """A skipped check; a failure under ``ONEBOX_TEST_REQUIRE_FULL=1``."""
        if REQUIRE_FULL:
            self.record(name, False, f"skipped under ONEBOX_TEST_REQUIRE_FULL=1: {reason}")
            return
        self.entries.append({"name": name, "ok": True, "skipped": True, "detail": reason})
        print(f"SKIP {name}: {reason}", flush=True)

    def attempt(self, name: str, action) -> bool:
        """Run ``action()``; any exception is a failure of ``name``."""
        try:
            action()
        except Exception as error:  # noqa: BLE001 - every error fails this check
            return self.record(name, False, describe(error))
        return self.record(name, True)

    @contextlib.contextmanager
    def guard(self, name: str):
        """Record an exception escaping the block as the failure ``name``.

        Suites wrap their whole body in it, so an unexpected error still
        ends in the summary line and the report.
        """
        try:
            yield
        except Exception as error:  # noqa: BLE001 - recorded, never swallowed silently
            self.record(name, False, describe(error))

    @property
    def failures(self) -> int:
        return sum(not entry["ok"] for entry in self.entries)

    @property
    def skipped(self) -> int:
        return sum(bool(entry.get("skipped")) for entry in self.entries)

    def finish(self, report: Path | None = None, **extra) -> int:
        """Print the summary, write the report and return the exit status."""
        checks = len(self.entries) - self.skipped
        print(f"{self.title}: {checks} checks, {self.failures} failures, "
              f"{self.skipped} skipped", flush=True)
        if report:
            write_json(report, {"schema": 1, "suite": self.title, "total": checks,
                                "failures": self.failures, "skipped": self.skipped,
                                **extra, "results": self.entries})
        return int(self.failures > 0 or not self.entries)


# Core name → (CI variable, names looked up on PATH outside REQUIRE_FULL).
TOOL_VARIABLES = {
    "singbox": ("ONEBOX_TEST_SINGBOX", ("sing-box",)),
    "xray": ("ONEBOX_TEST_XRAY", ("xray",)),
    "mihomo": ("ONEBOX_TEST_MIHOMO", ("mihomo",)),
}


def resolve_tools(results: Results, required, optional=()) -> dict[str, str] | None:
    """``onebox`` plus the named cores (keys of :data:`TOOL_VARIABLES`).

    A missing required tool or any misconfigured variable is recorded as
    the failure ``prerequisites`` (``None`` is returned); a missing optional
    tool is a skip (a failure under REQUIRE_FULL) and is left out.
    """
    tools = {}
    try:
        tools["onebox"] = onebox_binary()
        for name in required:
            variable, names = TOOL_VARIABLES[name]
            tools[name] = tool(variable, path_names=names)
        for name in optional:
            variable, names = TOOL_VARIABLES[name]
            try:
                tools[name] = tool(variable, path_names=names)
            except Unavailable as error:
                results.skip(f"{name}-tool", str(error))
    except (Unavailable, Misconfigured) as error:
        results.record("prerequisites", False, str(error))
        return None
    return tools


def comma_list(allowed):
    """argparse type: a non-empty comma list of values from ``allowed``.

    Repeated values are dropped (the first occurrence keeps its place):
    each value names one case directory.
    """
    def parse(text: str) -> list[str]:
        values = list(dict.fromkeys(v for v in text.split(",") if v))
        if not values or any(v not in allowed for v in values):
            raise argparse.ArgumentTypeError(f"choose from {','.join(allowed)}")
        return values
    return parse


def describe(error: BaseException) -> str:
    text = str(error) or type(error).__name__
    return text if isinstance(error, AssertionError) else f"{type(error).__name__}: {text}"


class Workspace:
    """``umask 077`` and a private temporary root, removed unless ``KEEP=1``."""

    def __init__(self, prefix: str):
        self.prefix = prefix
        self.root: Path | None = None

    def __enter__(self) -> Path:
        os.umask(0o077)
        self.root = Path(tempfile.mkdtemp(prefix=self.prefix))
        return self.root

    def __exit__(self, *_):
        if self.root is None:
            return
        if os.environ.get("KEEP") == "1":
            print(f"Preserved fixture directory: {self.root}", flush=True)
        else:
            shutil.rmtree(self.root, ignore_errors=True)


# Host variables that would change what the program does.
_LEAKY = ("GH_PROXY", "BASH_ENV", "ENV")


def clean_env(**extra: str) -> dict[str, str]:
    """``os.environ`` without ``ONEBOX_*`` / proxy-mirror variables, plus ``NO_COLOR=1``."""
    env = {k: v for k, v in os.environ.items()
           if not k.startswith("ONEBOX_") and k not in _LEAKY}
    env["NO_COLOR"] = "1"
    env.update(extra)
    return env


# ---------------------------------------------------------------------------
# Commands and files


class CommandFailed(AssertionError):
    """A checked command exited non-zero."""


@dataclasses.dataclass
class Completed:
    argv: list[str]
    code: int
    stdout: str
    stderr: str

    @property
    def ok(self) -> bool:
        return self.code == 0


def run(argv, *, env=None, timeout: float = 30, check: bool = True,
        input: bytes | None = None, cwd=None) -> Completed:
    """Run a command with captured, UTF-8 decoded output (stdin closed or ``input``)."""
    args = [str(a) for a in argv]
    result = subprocess.run(args, env=env, cwd=cwd, capture_output=True, timeout=timeout, check=False,
                            input=input, stdin=None if input is not None else subprocess.DEVNULL)
    done = Completed(args, result.returncode, result.stdout.decode(errors="replace"),
                     result.stderr.decode(errors="replace"))
    if check and not done.ok:
        raise CommandFailed(f"{Path(args[0]).name} {' '.join(args[1:3])} failed ({done.code}): "
                            f"{done.stderr[-3000:]}{done.stdout[-1000:]}")
    return done


def write_json(path: Path, value, mode: int = 0o600) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n")
    path.chmod(mode)


# ---------------------------------------------------------------------------
# Ports


def ephemeral_range() -> tuple[int, int]:
    try:
        low, high = map(int, Path("/proc/sys/net/ipv4/ip_local_port_range").read_text().split())
        return low, high
    except (OSError, ValueError):
        return 32768, 60999


class Ports:
    """Loopback ports free for TCP and UDP, never in the ephemeral range.

    Outgoing connections take source ports from the ephemeral range; a
    listener allocated there could be taken by a core's own connection
    between allocation and bind.
    """

    def __init__(self, low: int = 10240):
        start, end = ephemeral_range()
        self.used: set[int] = set()
        self.candidates = [p for p in range(low, 65536) if not start <= p <= end]
        random.SystemRandom().shuffle(self.candidates)

    def get(self) -> int:
        while self.candidates:
            port = self.candidates.pop()
            if port not in self.used and self.bindable(port):
                self.used.add(port)
                return port
        raise AssertionError("no non-ephemeral loopback ports are free")

    @staticmethod
    def bindable(port: int) -> bool:
        try:
            with socket.socket() as tcp, socket.socket(type=socket.SOCK_DGRAM) as udp:
                tcp.bind((LOOPBACK, port))
                udp.bind((LOOPBACK, port))
        except OSError:
            return False
        return True


# ---------------------------------------------------------------------------
# Processes


class Process:
    """A child in a new session; :meth:`close` terminates its process group.

    Output goes to ``<directory>/<name>.log`` (shown by :meth:`tail` in
    failure details).
    """

    def __init__(self, argv, directory: Path, env, name: str = "process"):
        self.log_path = directory / f"{name}.log"
        self.log = self.log_path.open("wb")
        try:
            self.child = subprocess.Popen([str(a) for a in argv], cwd=directory, env=env,
                                          stdin=subprocess.DEVNULL, stdout=self.log,
                                          stderr=self.log, start_new_session=True)
        except Exception:
            self.log.close()
            raise

    def alive(self) -> bool:
        return self.child.poll() is None

    def wait_tcp(self, port: int, timeout: float = 8, host: str = LOOPBACK) -> None:
        """Wait until ``host:port`` accepts TCP; the child must stay alive."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self.alive():
                raise AssertionError("process exited during startup: " + self.tail())
            try:
                with socket.create_connection((host, port), timeout=0.1):
                    return
            except OSError:
                time.sleep(0.03)
        raise AssertionError(f"process did not open {host}:{port}: " + self.tail())

    def wait_file(self, path: Path, content: str, timeout: float = 8) -> None:
        """Wait until ``path`` holds exactly ``content`` (a readiness marker)."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if not self.alive():
                raise AssertionError("process exited before finishing startup: " + self.tail())
            with contextlib.suppress(OSError):
                if path.is_file() and path.read_text() == content:
                    return
            time.sleep(0.01)
        raise AssertionError("process did not finish startup: " + self.tail())

    def stay_alive(self, seconds: float) -> None:
        """Startup check for UDP-only listeners: still running after ``seconds``."""
        time.sleep(seconds)
        if not self.alive():
            raise AssertionError("process exited during startup: " + self.tail())

    def tail(self, size: int = 3000) -> str:
        with contextlib.suppress(ValueError):
            self.log.flush()
        return self.log_path.read_text(errors="replace")[-size:]

    def close(self) -> None:
        # Only a live leader is signalled: after it has been reaped its PID
        # (and so the process-group ID) may belong to an unrelated session.
        if self.child.poll() is None:
            with contextlib.suppress(ProcessLookupError):
                os.killpg(self.child.pid, signal.SIGTERM)
            try:
                self.child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(self.child.pid, signal.SIGKILL)
                self.child.wait(timeout=3)
        self.log.close()

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close()


# ---------------------------------------------------------------------------
# Self-tests (python3 tests/e2e/_selftest.py runs every module's)


class ToolContractTests(unittest.TestCase):
    def test_set_but_unusable_variable_is_misconfigured(self):
        with unittest.mock.patch.dict(os.environ, {"ONEBOX_TEST_X": "/nonexistent/x"}), \
                self.assertRaises(Misconfigured):
            tool("ONEBOX_TEST_X")

    def test_unset_variable(self):
        with unittest.mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("ONEBOX_TEST_X", None)
            if REQUIRE_FULL:
                with self.assertRaises(Unavailable):
                    tool("ONEBOX_TEST_X", path_names=("sh",))
            else:
                self.assertTrue(tool("ONEBOX_TEST_X", path_names=("sh",)).endswith("sh"))
                with self.assertRaises(Unavailable):
                    tool("ONEBOX_TEST_X", path_names=("onebox-no-such-tool",))

    def test_misconfiguration_is_a_recorded_prerequisite_failure(self):
        sh = shutil.which("sh") or "/bin/sh"
        cases = [
            ({"ONEBOX_TEST_BINARY": sh, "ONEBOX_TEST_XRAY": "/nonexistent/xray"}, ["xray"], []),
            ({"ONEBOX_TEST_BINARY": sh, "ONEBOX_TEST_MIHOMO": "/nonexistent/mihomo"}, [], ["mihomo"]),
            ({"ONEBOX_TEST_BINARY": "/nonexistent/onebox"}, [], []),
        ]
        for variables, required, optional in cases:
            with self.subTest(variables=variables), \
                    unittest.mock.patch.dict(os.environ, variables), \
                    contextlib.redirect_stdout(io.StringIO()) as out:
                results = Results("t")
                self.assertIsNone(resolve_tools(results, required, optional))
                self.assertEqual([(e["name"], e["ok"]) for e in results.entries],
                                 [("prerequisites", False)])
                results.finish()
            self.assertIn("t: 1 checks, 1 failures", out.getvalue())

    def test_clean_env_drops_onebox_variables(self):
        with unittest.mock.patch.dict(os.environ, {"ONEBOX_DIR": "/etc/x", "GH_PROXY": "p"}):
            env = clean_env(A="1")
        self.assertNotIn("ONEBOX_DIR", env)
        self.assertNotIn("GH_PROXY", env)
        self.assertEqual((env["NO_COLOR"], env["A"]), ("1", "1"))

    def test_comma_list_drops_repeats(self):
        parse = comma_list(("a", "b", "c"))
        self.assertEqual(parse("b,a,b,,a"), ["b", "a"])
        for bad in ("", ",", "a,d"):
            with self.subTest(text=bad), self.assertRaises(argparse.ArgumentTypeError):
                parse(bad)


class ResultsTests(unittest.TestCase):
    def test_exit_status(self):
        cases = [([], 1), ([("a", True)], 0), ([("a", True), ("b", False)], 1)]
        for records, expected in cases:
            results = Results("t")
            with contextlib.redirect_stdout(io.StringIO()):
                for name, ok in records:
                    results.record(name, ok)
                self.assertEqual(results.finish(), expected)

    def test_guard_records_escaping_errors(self):
        results = Results("t")
        with contextlib.redirect_stdout(io.StringIO()):
            with results.guard("suite"):
                raise FileExistsError("case directory")
            with results.guard("quiet"):
                pass
        self.assertEqual(results.entries, [{"name": "suite", "ok": False,
                                            "detail": "FileExistsError: case directory"}])

    def test_skips_fail_only_under_require_full(self):
        results = Results("t")
        with contextlib.redirect_stdout(io.StringIO()):
            results.skip("x", "missing")
        self.assertEqual((results.failures, results.skipped),
                         (1, 0) if REQUIRE_FULL else (0, 1))


class PortsTests(unittest.TestCase):
    def test_ports_avoid_ephemeral_range(self):
        low, high = ephemeral_range()
        ports = Ports()
        values = {ports.get() for _ in range(5)}
        self.assertEqual(len(values), 5)
        self.assertTrue(all(not low <= p <= high and p >= 10240 for p in values))


if __name__ == "__main__":
    unittest.main()
