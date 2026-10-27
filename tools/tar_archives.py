from __future__ import annotations

import tarfile
from pathlib import Path


def extract(archive: Path, destination: Path) -> None:
    with tarfile.open(str(archive)) as tar:
        if hasattr(tarfile, "data_filter"):
            tar.extractall(str(destination), filter="data")
        else:
            tar.extractall(str(destination))
