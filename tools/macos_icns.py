from __future__ import annotations

import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

ICONSET_POINTS = (16, 32, 128, 256, 512)


class IcnsError(Exception):
    pass


def make_icns(source: Path, out: Path) -> None:
    work = Path(tempfile.mkdtemp(prefix="cerf_icns_"))
    try:
        iconset = work / "cerf.iconset"
        iconset.mkdir()
        for points in ICONSET_POINTS:
            for scale, suffix in ((1, ""), (2, "@2x")):
                pixels = str(points * scale)
                png = iconset / "icon_{0}x{0}{1}.png".format(points, suffix)
                if subprocess.run(["sips", "-z", pixels, pixels, str(source), "--out", str(png)],
                                  stdout=subprocess.DEVNULL, check=False).returncode != 0:
                    raise IcnsError("sips could not write {}".format(png))
        out.parent.mkdir(parents=True, exist_ok=True)
        if subprocess.run(["iconutil", "-c", "icns", "-o", str(out), str(iconset)],
                          check=False).returncode != 0:
            raise IcnsError("iconutil could not write {}".format(out))
    finally:
        shutil.rmtree(str(work), ignore_errors=True)


def main(argv) -> int:
    if len(argv) != 2:
        print("usage: macos_icns.py <source.png> <out.icns>", file=sys.stderr)
        return 2
    try:
        make_icns(Path(argv[0]), Path(argv[1]))
    except IcnsError as exc:
        print("macos_icns: {}".format(exc), file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
