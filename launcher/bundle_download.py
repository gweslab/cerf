"""Streaming download, verification, and safe ZIP extraction for bundle /
package archives."""
from __future__ import annotations

import os
import shutil
import threading
import urllib.request
import zipfile
from pathlib import Path
from typing import Callable, Optional

from bundles import (
    BundleError,
    DOWNLOAD_CHUNK,
    DOWNLOAD_TIMEOUT,
    USER_AGENT,
    _sha256_file,
)

ProgressFn = Callable[[str, int, Optional[int]], None]


class CancelledError(BundleError):
    pass


def stream_download(url: str, destination: Path, label: str,
                    expected_size: Optional[int], progress: ProgressFn,
                    cancel_event: Optional[threading.Event]) -> None:
    request = urllib.request.Request(url, headers={"User-Agent": USER_AGENT})
    with urllib.request.urlopen(request, timeout=DOWNLOAD_TIMEOUT) as response:
        content_length = response.headers.get("Content-Length")
        total = int(content_length) if content_length and content_length.isdigit() else expected_size
        done = 0
        progress(label, 0, total)
        try:
            with destination.open("wb") as f:
                while True:
                    if cancel_event is not None and cancel_event.is_set():
                        raise CancelledError(f"{label}: cancelled")
                    chunk = response.read(DOWNLOAD_CHUNK)
                    if not chunk:
                        break
                    f.write(chunk)
                    done += len(chunk)
                    progress(label, done, total)
        except BaseException:
            try:
                destination.unlink()
            except OSError:
                pass
            raise


def verify_download(path: Path, label: str,
                    expected_size: Optional[int],
                    expected_sha256: Optional[str]) -> None:
    if expected_size is not None and path.stat().st_size != expected_size:
        raise BundleError(
            f"{label}: size mismatch (got {path.stat().st_size}, expected {expected_size})"
        )
    if expected_sha256:
        digest = _sha256_file(path)
        if digest.lower() != expected_sha256.lower():
            raise BundleError(
                f"{label}: sha256 mismatch (got {digest}, expected {expected_sha256})"
            )


def safe_extract(zip_path: Path, destination: Path) -> None:
    destination_absolute = Path(os.path.abspath(str(destination)))
    with zipfile.ZipFile(zip_path) as archive:
        for member in archive.infolist():
            member_absolute = Path(os.path.abspath(
                str(destination / member.filename)))
            try:
                member_absolute.relative_to(destination_absolute)
            except ValueError as exc:
                raise BundleError(
                    f"unsafe path in archive: {member.filename}"
                ) from exc
        archive.extractall(destination)


def prepared_bundle_root(extract_dir: Path) -> Path:
    entries = [e for e in extract_dir.iterdir() if e.name not in {".", ".."}]
    if len(entries) == 1 and entries[0].is_dir():
        return entries[0]
    return extract_dir


def remove_artifact(path: Path) -> None:
    if path.is_dir():
        shutil.rmtree(path)
    elif path.exists():
        path.unlink()


def download_extract(url: str, label: str, tmp: Path,
                     expected_size: Optional[int],
                     expected_sha256: Optional[str],
                     progress: ProgressFn,
                     cancel_event: Optional[threading.Event]) -> Path:
    archive = tmp / "archive.zip"
    extract = tmp / "extract"
    extract.mkdir()
    stream_download(url, archive, f"Downloading {label}",
                    expected_size, progress, cancel_event)
    verify_download(archive, label, expected_size, expected_sha256)
    progress(f"Extracting {label}", 0, None)
    safe_extract(archive, extract)
    return prepared_bundle_root(extract)
