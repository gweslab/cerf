import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path


def main() -> int:
    temp = Path(os.environ["RUNNER_TEMP"])
    archive = temp / "ce-tools.zip"
    unpacked = temp / "ce-tools"
    subprocess.run(["curl", "-fsSL", os.environ["CE_TOOLCHAIN_URL"], "-o", str(archive)], check=True)
    with zipfile.ZipFile(archive) as zip_file:
        zip_file.extractall(unpacked)
    sdk = next((Path(root) / "STANDARDSDK" for root, dirs, _ in os.walk(unpacked) if "STANDARDSDK" in dirs),
               None)
    if sdk is None:
        print("CE toolchain zip has no STANDARDSDK folder", file=sys.stderr)
        return 1
    target = Path("third_party") / "wince"
    target.parent.mkdir(exist_ok=True)
    if target.exists():
        shutil.rmtree(str(target))
    shutil.move(str(sdk.parent), str(target))
    print("CE toolchain ready at third_party/wince")
    return 0


if __name__ == "__main__":
    sys.exit(main())
