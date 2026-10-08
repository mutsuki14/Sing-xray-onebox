#!/usr/bin/env python3
"""Fetch fixed official test tools; verify release asset digests before extraction."""
import gzip
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tarfile
import urllib.request
import zipfile

TOOLS = [
    ('SagerNet/sing-box', 'v1.14.2', 'sing-box-1.14.2-linux-amd64.tar.gz', ['sing-box']),
    ('XTLS/Xray-core', 'v26.3.27', 'Xray-linux-64.zip', ['xray']),
    ('MetaCubeX/mihomo', 'v1.19.32', 'mihomo-linux-amd64-v1.19.32.gz', ['mihomo']),
    ('fatedier/frp', 'v0.71.0', 'frp_0.71.0_linux_amd64.tar.gz', ['frps', 'frpc']),
]

def get(url):
    headers = {'User-Agent': 'onebox-native-ci'}
    if url.startswith('https://api.github.com/') and os.environ.get('GH_TOKEN'):
        headers['Authorization'] = 'Bearer ' + os.environ['GH_TOKEN']
    with urllib.request.urlopen(urllib.request.Request(url, headers=headers), timeout=90) as r:
        return r.read()

def main():
    dest = Path(sys.argv[1]); dest.mkdir(parents=True, exist_ok=True)
    for repo, tag, name, binaries in TOOLS:
        release = json.loads(get(f'https://api.github.com/repos/{repo}/releases/tags/{tag}'))
        asset, = [a for a in release['assets'] if a['name'] == name]
        digest = asset.get('digest', '')
        if not digest.startswith('sha256:') or len(digest) != 71:
            raise RuntimeError(f'{name}: missing upstream SHA256 digest')
        data = get(asset['browser_download_url'])
        assert hashlib.sha256(data).hexdigest() == digest[7:], name
        if name.endswith('.tar.gz'):
            with tarfile.open(fileobj=io.BytesIO(data), mode='r:gz') as archive:
                for binary in binaries:
                    member, = [m for m in archive.getmembers() if Path(m.name).name == binary and m.isfile()]
                    (dest / binary).write_bytes(archive.extractfile(member).read())
        elif name.endswith('.zip'):
            with zipfile.ZipFile(io.BytesIO(data)) as archive:
                for binary in binaries:
                    member, = [n for n in archive.namelist() if Path(n).name == binary]
                    (dest / binary).write_bytes(archive.read(member))
        else:
            (dest / binaries[0]).write_bytes(gzip.decompress(data))
        for binary in binaries:
            (dest / binary).chmod(0o755)
        print(f'{repo} {tag}: verified {digest}', flush=True)

if __name__ == '__main__':
    main()
