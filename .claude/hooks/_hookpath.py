import re

_MSYS_DRIVE_RE = re.compile(r"^/([A-Za-z])(/.*)?$")


def normalize(path: str) -> str:
    if not path:
        return path
    m = _MSYS_DRIVE_RE.match(path)
    if not m:
        return path
    return m.group(1).upper() + ":" + (m.group(2) or "/")
