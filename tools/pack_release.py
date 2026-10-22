from __future__ import annotations

import os
import stat
import sys
import time
import zipfile
from pathlib import Path
from typing import List

ZIP_HOST_UNIX = 3


def _link_info(path: Path, arcname: str) -> zipfile.ZipInfo:
    info = zipfile.ZipInfo(arcname, date_time=time.localtime(path.lstat().st_mtime)[:6])
    info.create_system = ZIP_HOST_UNIX
    info.external_attr = (stat.S_IFLNK | 0o777) << 16
    return info


def pack(source: Path, out: Path) -> None:
    out.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(str(out), "w", zipfile.ZIP_DEFLATED) as archive:
        for directory, dirnames, filenames in os.walk(str(source)):
            dirnames.sort()
            base = Path(directory)
            for name in sorted(dirnames + filenames):
                path = base / name
                arcname = path.relative_to(source).as_posix()
                if path.is_symlink():
                    archive.writestr(_link_info(path, arcname), os.readlink(str(path)))
                elif path.is_file():
                    archive.write(str(path), arcname)


def main(argv: List[str]) -> int:
    if len(argv) != 2:
        print("usage: pack_release.py <out.zip> <directory>", file=sys.stderr)
        return 2
    pack(Path(argv[1]), Path(argv[0]))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
