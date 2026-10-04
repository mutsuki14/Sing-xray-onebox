#!/usr/bin/env python3
"""Keep the distributed onebox.sh self-contained. --check is used by CI."""
import pathlib
import sys

root = pathlib.Path(__file__).resolve().parent.parent
script = root / "onebox.sh"
start = "# BEGIN embedded-client-runtime\n"
end = "# END embedded-client-runtime\n"
source = (root / "lib/client_runtime.py").read_text()
block = start + "_client_runtime() {\n\tpython3 - \"$@\" <<'ONEBOX_CLIENT_PY'\n" + source + "ONEBOX_CLIENT_PY\n}\n" + end
old = script.read_text()
if start in old:
    new = old[:old.index(start)] + block + old[old.index(end) + len(end):]
else:
    marker = '# ONEBOX_SOURCE_ONLY=1 时仅加载函数 (供测试使用)'
    assert marker in old
    new = old.replace(marker, block + "\n" + marker)
if "--check" in sys.argv:
    if new != old:
        sys.exit("Run python3 scripts/embed-runtime.py")
else:
    script.write_text(new)
