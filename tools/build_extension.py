"""Package extension/ into web/vaultly-extension.zip (served by the app for download).
Copies web/crypto.js into the extension first, so both always use the same crypto code."""
import shutil
import zipfile
from pathlib import Path

root = Path(__file__).resolve().parent.parent
ext = root / "extension"
shutil.copyfile(root / "web" / "crypto.js", ext / "crypto.js")
out = root / "web" / "vaultly-extension.zip"
with zipfile.ZipFile(out, "w", zipfile.ZIP_DEFLATED) as z:
    for f in sorted(ext.iterdir()):
        if f.is_file() and not f.name.startswith("."):
            info = zipfile.ZipInfo("vaultly-extension/" + f.name, date_time=(2026, 1, 1, 0, 0, 0))  # stable bytes for the same sources
            info.compress_type = zipfile.ZIP_DEFLATED
            z.writestr(info, f.read_bytes())
print(out, out.stat().st_size, "bytes")
