#!/usr/bin/env python3
"""Fetch the pinned official test tools listed in tests/tools.json.

    python3 tests/fetch_tools.py DEST     download, verify and install every tool into DEST
    python3 tests/fetch_tools.py --check  validate the manifest only (no network)

Each release asset must carry a GitHub API ``digest`` (sha256). The downloaded
bytes must match it and the API size before anything is extracted; only the
named binaries are taken, by basename, from regular archive members, and they
are installed atomically with mode 0755. GH_TOKEN, when set, authenticates
api.github.com requests only (never forwarded on redirects).
"""
import argparse
import gzip
import hashlib
import http.client
import io
import json
import os
import re
import stat
import sys
import tarfile
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from pathlib import Path, PurePosixPath

MANIFEST = Path(__file__).resolve().with_name('tools.json')
API = 'https://api.github.com'
USER_AGENT = 'onebox-ci-fetch-tools'
TIMEOUT = 90
ATTEMPTS = 3
MAX_METADATA = 16 << 20
MAX_ASSET = 256 << 20
MAX_BINARY = 256 << 20
KEYS = {'repo', 'tag', 'asset', 'binaries'}
REPO = re.compile(r'[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+')
TAG = re.compile(r'v[0-9A-Za-z._-]+')
NAME = re.compile(r'[A-Za-z0-9_.+-]+')
DIGEST = re.compile(r'sha256:([0-9a-f]{64})')
ARCHIVES = ('.tar.gz', '.zip', '.gz')


class FetchError(Exception):
    """A tool could not be fetched or failed verification."""


def load_manifest(path):
    """Return the validated manifest entries; any deviation is an error."""
    try:
        entries = json.loads(path.read_text())
    except (OSError, ValueError) as error:
        raise FetchError(f'{path}: {error}') from error
    if not isinstance(entries, list) or not entries:
        raise FetchError(f'{path}: expected a non-empty JSON array')
    seen = set()
    for index, entry in enumerate(entries):
        where = f'{path}[{index}]'
        if not isinstance(entry, dict) or set(entry) != KEYS:
            raise FetchError(f'{where}: expected exactly the keys {sorted(KEYS)}')
        repo, tag, asset, binaries = (entry[key] for key in ('repo', 'tag', 'asset', 'binaries'))
        for value, pattern, label in ((repo, REPO, 'repo'), (tag, TAG, 'tag'), (asset, NAME, 'asset')):
            if not isinstance(value, str) or not pattern.fullmatch(value) or '..' in value:
                raise FetchError(f'{where}: invalid {label} {value!r}')
        if not asset.endswith(ARCHIVES):
            raise FetchError(f'{where}: unsupported archive type {asset!r}')
        if not isinstance(binaries, list) or not binaries:
            raise FetchError(f'{where}: binaries must be a non-empty list')
        if asset.endswith('.gz') and not asset.endswith('.tar.gz') and len(binaries) != 1:
            raise FetchError(f'{where}: a plain .gz asset holds exactly one binary')
        for binary in binaries:
            if not isinstance(binary, str) or not NAME.fullmatch(binary) or binary.startswith('.'):
                raise FetchError(f'{where}: invalid binary name {binary!r}')
            if binary in seen:
                raise FetchError(f'{where}: binary {binary!r} is listed twice')
            seen.add(binary)
    return entries


class HttpsOnlyRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        if urllib.parse.urlsplit(newurl).scheme != 'https':
            raise FetchError(f'{req.full_url}: refusing a redirect to non-HTTPS {newurl}')
        return super().redirect_request(req, fp, code, msg, headers, newurl)


OPENER = urllib.request.build_opener(HttpsOnlyRedirect())


def get(url, limit, api=False):
    """GET url (HTTPS only) and return at most `limit` bytes, retrying transient failures."""
    if urllib.parse.urlsplit(url).scheme != 'https':
        raise FetchError(f'refusing non-HTTPS URL {url}')
    for attempt in range(1, ATTEMPTS + 1):
        request = urllib.request.Request(url, headers={'User-Agent': USER_AGENT})
        if api:
            request.add_header('Accept', 'application/vnd.github+json')
            token = os.environ.get('GH_TOKEN', '').strip()
            if token:
                # Unredirected headers are dropped if the API ever redirects.
                request.add_unredirected_header('Authorization', f'Bearer {token}')
        try:
            with OPENER.open(request, timeout=TIMEOUT) as response:
                declared = response.headers.get('Content-Length')
                if declared is not None and declared.isdigit() and int(declared) > limit:
                    raise FetchError(f'{url}: response of {declared} bytes exceeds {limit}')
                data = response.read(limit + 1)
        except urllib.error.HTTPError as error:
            if error.code in (429, 500, 502, 503, 504) and attempt < ATTEMPTS:
                time.sleep(2 * attempt)
                continue
            hint = ' (GitHub API rate limit? set GH_TOKEN)' if api and error.code in (403, 429) else ''
            raise FetchError(f'{url}: HTTP {error.code} {error.reason}{hint}') from error
        except (urllib.error.URLError, http.client.HTTPException, OSError) as error:
            if attempt < ATTEMPTS:
                time.sleep(2 * attempt)
                continue
            raise FetchError(f'{url}: {error}') from error
        if len(data) > limit:
            raise FetchError(f'{url}: response exceeds {limit} bytes')
        return data
    raise FetchError(f'{url}: no attempt left')


def release_asset(repo, tag, asset):
    """Return (download URL, size, sha256 hex) for the unique release asset."""
    url = f'{API}/repos/{repo}/releases/tags/{urllib.parse.quote(tag)}'
    try:
        release = json.loads(get(url, MAX_METADATA, api=True))
    except ValueError as error:
        raise FetchError(f'{url}: invalid JSON: {error}') from error
    if not isinstance(release, dict) or release.get('tag_name') != tag:
        raise FetchError(f'{repo} {tag}: the API did not return that release')
    if release.get('draft') is not False:
        raise FetchError(f'{repo} {tag}: the release is a draft')
    matches = [item for item in release.get('assets') or [] if isinstance(item, dict) and item.get('name') == asset]
    if len(matches) != 1:
        raise FetchError(f'{repo} {tag}: expected exactly one asset named {asset}, found {len(matches)}')
    meta = matches[0]
    digest = meta.get('digest')
    found = DIGEST.fullmatch(digest) if isinstance(digest, str) else None
    if found is None:
        raise FetchError(f'{asset}: missing or malformed upstream sha256 digest {digest!r}')
    size = meta.get('size')
    if not isinstance(size, int) or isinstance(size, bool) or not 0 < size <= MAX_ASSET:
        raise FetchError(f'{asset}: invalid size {size!r}')
    expected_url = f'https://github.com/{repo}/releases/download/{tag}/{asset}'
    if meta.get('browser_download_url') != expected_url:
        raise FetchError(f'{asset}: unexpected download URL {meta.get("browser_download_url")!r}')
    return expected_url, size, found.group(1)


def read_capped(stream, name):
    content = stream.read(MAX_BINARY + 1)
    if not content or len(content) > MAX_BINARY:
        raise FetchError(f'{name}: empty or larger than {MAX_BINARY} bytes')
    return content


def unique(members, binary, asset):
    if len(members) != 1:
        raise FetchError(f'{asset}: expected exactly one regular file named {binary}, found {len(members)}')
    return members[0]


def extract(asset, data, binaries):
    """Return {binary: bytes} taken by basename from regular members only."""
    result = {}
    try:
        if asset.endswith('.tar.gz'):
            with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
                members = archive.getmembers()
                for binary in binaries:
                    member = unique([m for m in members if m.isreg() and PurePosixPath(m.name).name == binary],
                                    binary, asset)
                    if member.size > MAX_BINARY:
                        raise FetchError(f'{asset}: {binary} is larger than {MAX_BINARY} bytes')
                    result[binary] = read_capped(archive.extractfile(member), binary)
        elif asset.endswith('.zip'):
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for binary in binaries:
                    member = unique([i for i in archive.infolist() if not i.is_dir()
                                     and stat.S_IFMT(i.external_attr >> 16) in (0, stat.S_IFREG)
                                     and PurePosixPath(i.filename).name == binary], binary, asset)
                    if member.file_size > MAX_BINARY:
                        raise FetchError(f'{asset}: {binary} is larger than {MAX_BINARY} bytes')
                    with archive.open(member) as stream:
                        result[binary] = read_capped(stream, binary)
        else:
            with gzip.GzipFile(fileobj=io.BytesIO(data)) as stream:
                result[binaries[0]] = read_capped(stream, binaries[0])
    except (tarfile.TarError, zipfile.BadZipFile, OSError, EOFError) as error:
        raise FetchError(f'{asset}: corrupt archive: {error}') from error
    for binary, content in result.items():
        if not content.startswith(b'\x7fELF'):
            raise FetchError(f'{asset}: {binary} is not an ELF executable')
    return result


def install(dest, name, content):
    """Write dest/name atomically with mode 0755 (never through a symlink)."""
    temporary = dest / f'.{name}.tmp-{os.getpid()}'
    fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o700)
    try:
        with os.fdopen(fd, 'wb') as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        os.chmod(temporary, 0o755)
        os.replace(temporary, dest / name)
    except BaseException:
        temporary.unlink(missing_ok=True)
        raise


def fetch(entry, dest):
    repo, tag, asset, binaries = (entry[key] for key in ('repo', 'tag', 'asset', 'binaries'))
    url, size, digest = release_asset(repo, tag, asset)
    data = get(url, size)
    if len(data) != size:
        raise FetchError(f'{asset}: got {len(data)} bytes, the API lists {size}')
    actual = hashlib.sha256(data).hexdigest()
    if actual != digest:
        raise FetchError(f'{asset}: sha256 {actual} does not match the upstream digest {digest}')
    for binary, content in extract(asset, data, binaries).items():
        install(dest, binary, content)
    print(f'{repo} {tag}: verified sha256:{digest} -> {", ".join(binaries)}', flush=True)


def main(argv):
    parser = argparse.ArgumentParser(description='Fetch the pinned test tools (tests/tools.json).')
    parser.add_argument('dest', nargs='?', type=Path, help='directory that receives the binaries')
    parser.add_argument('--check', action='store_true', help='only validate the manifest')
    parser.add_argument('--manifest', type=Path, default=MANIFEST, help=argparse.SUPPRESS)
    args = parser.parse_args(argv)
    if args.check == (args.dest is not None):
        parser.error('give either DEST or --check')
    try:
        entries = load_manifest(args.manifest)
        if args.check:
            for entry in entries:
                print(f'{entry["repo"]} {entry["tag"]}: {entry["asset"]} -> {", ".join(entry["binaries"])}')
            return 0
        args.dest.mkdir(parents=True, exist_ok=True)
        for entry in entries:
            fetch(entry, args.dest)
    except FetchError as error:
        print(f'fetch_tools: {error}', file=sys.stderr)
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
