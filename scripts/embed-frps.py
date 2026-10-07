#!/usr/bin/env python3
"""Embed FRP helpers into the single-file installer; CI checks source parity."""
import pathlib
import sys

root = pathlib.Path(__file__).resolve().parent.parent
script = root / "onebox.sh"
start = "# BEGIN embedded-frps\n"
end = "# END embedded-frps\n"
files = ["frps.sh", "frps-domain.sh", "frps-firewall.sh", "frps-ui.sh"]
block = start + "\n".join((root / "lib" / name).read_text().rstrip() + "\n" for name in files) + end
old = script.read_text()
if start in old:
    new = old[:old.index(start)] + block + old[old.index(end) + len(end):]
else:
    marker = "# BEGIN embedded-client-runtime\n"
    assert marker in old
    new = old.replace(marker, block + "\n" + marker)
if "--check" in sys.argv:
    if new != old:
        sys.exit("Run python3 scripts/embed-frps.py")
else:
    script.write_text(new)
