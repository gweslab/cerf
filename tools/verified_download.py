from __future__ import annotations

import hashlib
import http.client
import shutil
import time
import urllib.request
from pathlib import Path
from typing import Callable

DOWNLOAD_ATTEMPTS = 3
RETRY_DELAY_S = 10
TIMEOUT_S = 120
CHUNK_BYTES = 1 << 20

Say = Callable[[str], None]
Transport = Callable[[str, Path, Say], None]
Digest = Callable[[Path], str]


class DownloadError(Exception):
    pass


def file_sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(CHUNK_BYTES), b""):
            digest.update(chunk)
    return digest.hexdigest()


def partial_path(destination: Path) -> Path:
    return destination.with_name(destination.name + ".part")


def download(url: str, destination: Path, say: Say) -> None:
    destination.parent.mkdir(parents=True, exist_ok=True)
    partial = partial_path(destination)
    for attempt in range(1, DOWNLOAD_ATTEMPTS + 1):
        say("Downloading {}".format(url))
        try:
            with urllib.request.urlopen(url, timeout=TIMEOUT_S) as response, partial.open("wb") as out:
                shutil.copyfileobj(response, out, CHUNK_BYTES)
            partial.replace(destination)
            return
        except (OSError, http.client.HTTPException) as exc:
            partial.unlink(missing_ok=True)
            if attempt == DOWNLOAD_ATTEMPTS:
                raise DownloadError("{} failed: {}".format(url, exc))
            say("attempt {} failed: {}".format(attempt, exc))
            time.sleep(RETRY_DELAY_S)


def fetch_verified(url: str, destination: Path, want: str, say: Say, transport: Transport = download,
                   digest: Digest = file_sha256) -> Path:
    if destination.is_file() and digest(destination) == want:
        return destination
    transport(url, destination, say)
    got = digest(destination)
    if got != want:
        destination.unlink()
        raise DownloadError("{} digest mismatch (got {}, want {})".format(destination.name, got, want))
    return destination
