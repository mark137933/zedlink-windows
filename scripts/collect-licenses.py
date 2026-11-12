"""Include local dependency notices without downloading extra build tools."""
from pathlib import Path
import json
import hashlib
import shutil
import subprocess
import sys

destination = Path(sys.argv[1])
destination.mkdir(parents=True, exist_ok=True)
records = {}
for manifest in sys.argv[2:]:
    metadata = json.loads(subprocess.check_output(
        ["cargo", "+1.98.1", "metadata", "--format-version", "1", "--locked", "--filter-platform", "x86_64-pc-windows-msvc", "--manifest-path", manifest],
        text=True, encoding="utf-8",
    ))
    for package in metadata["packages"]:
        suffix = hashlib.sha256(package['id'].encode()).hexdigest()[:8]
        identity = f"{package['name']}-{package['version']}-{suffix}"
        if identity in records:
            continue
        root = Path(package["manifest_path"]).parent
        output = destination / identity
        output.mkdir(exist_ok=True)
        candidates = {path for pattern in ("LICENSE*", "LICENCE*", "COPYING*", "NOTICE*", "Copyright*") for path in root.glob(pattern) if path.is_file()}
        if package.get("license_file"):
            candidates.add(root / package["license_file"])
        for path in candidates:
            if path.is_file() and path.resolve().is_relative_to(root.resolve()):
                shutil.copyfile(path, output / path.name)
        # Retain attribution/source metadata even for packages whose notice is in a README.
        for path in root.glob("README*"):
            if path.is_file():
                shutil.copyfile(path, output / path.name)
        records[identity] = {key: package.get(key) for key in ("name", "version", "license", "repository", "homepage", "authors")}
        records[identity]["notice_files"] = sorted(path.name for path in output.iterdir())

(destination / "index.json").write_text(json.dumps(records, indent=2, ensure_ascii=False), encoding="utf-8")
print(f"Collected notices for {len(records)} source packages")
