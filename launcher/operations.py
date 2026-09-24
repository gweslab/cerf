from __future__ import annotations

import random
import shutil
import string
import sys
import tempfile
import threading
from concurrent.futures import ThreadPoolExecutor, Future
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from bundle_download import (
    ProgressFn,
    download_extract,
    remove_artifact,
)
from bundles import (
    BundleError,
    PARALLEL_WORKERS,
    RemoteBundle,
    is_safe_bundle_name,
    load_analytics,
    load_merged_manifest,
)
from bundle_repositories import read_repositories
from cerf_user_json import (
    CERF_USER_JSON_FILENAME,
    LauncherLink,
    read_device_meta,
    read_launcher_link,
    read_rom_primary,
    write_launcher_link,
)
from update_source import fetch_update
from user_device_create import UserDeviceSpec, create_user_device
from device_state import (
    DeviceBundle,
    DeviceMeta,
    LocalBundleRecord,
    LocalPackageRecord,
    PackageStatus,
    load_local_manifest,
    package_artifact_present,
    cerf_json_differs,
    parse_cerf_json_object,
    save_local_manifest,
    write_cerf_json,
)


class BundleManager:
    def __init__(self, devices_dir: Path):
        self.devices_dir: Path = devices_dir
        self.local_manifest_path: Path = devices_dir / "manifest.json"
        self._pool = ThreadPoolExecutor(max_workers=PARALLEL_WORKERS)
        self._manifest_lock = threading.Lock()
        self.remote_bundles: List[RemoteBundle] = []
        self._remote_index: Dict[Tuple[str, str], RemoteBundle] = {}
        self.repo_errors: List[Tuple[str, str]] = []
        self.repo_abuse_emails: Dict[str, str] = {}
        self.download_places: Optional[Dict[Tuple[str, str], int]] = None
        # Local install manifest, keyed by device DIRECTORY name.
        self.installed: Dict[str, LocalBundleRecord] = {}

    def shutdown(self) -> None:
        if sys.version_info >= (3, 9):
            self._pool.shutdown(wait=False, cancel_futures=True)
        else:
            self._pool.shutdown(wait=False)

    def submit_refresh(self) -> Future:
        return self._pool.submit(self._do_refresh)

    def submit_release_check(self) -> Future:
        return self._pool.submit(fetch_update)

    def submit_create_user_device(self, spec: UserDeviceSpec,
                                  progress: ProgressFn,
                                  cancel_event: Optional[threading.Event] = None
                                  ) -> Future:
        return self._pool.submit(create_user_device, self.devices_dir, spec,
                                 progress, cancel_event)

    def load_local(self) -> None:
        try:
            installed = load_local_manifest(self.local_manifest_path)
        except BundleError:
            installed = {}
        with self._manifest_lock:
            self.installed = installed

    def _do_refresh(self) -> None:
        self.load_local()
        repositories = read_repositories()
        (self.remote_bundles, self.repo_errors,
         self.repo_abuse_emails) = load_merged_manifest(repositories)
        self._remote_index = {(rb.repo_url, rb.name): rb
                              for rb in self.remote_bundles}
        self.download_places = load_analytics(repositories)
        self._backfill_installed_sha256()

    def repo_abuse_contacts(self) -> List[Tuple[str, Optional[str]]]:
        return [(r.url, self.repo_abuse_emails.get(r.url))
                for r in read_repositories()]

    def _local_device_dirs(self) -> List[Path]:
        if not self.devices_dir.is_dir():
            return []
        return [e for e in self.devices_dir.iterdir()
                if e.is_dir() and not e.name.startswith(".")
                and is_safe_bundle_name(e.name)]

    def _device_rom_size(self, device_dir: Path) -> Optional[int]:
        primary = read_rom_primary(device_dir)
        if not primary:
            return None
        path = Path(primary)
        if not path.is_absolute():
            path = device_dir / primary
        try:
            return path.stat().st_size if path.is_file() else None
        except OSError:
            return None

    def _remote_for_dir(self, device_dir: Path) -> Optional[RemoteBundle]:
        link = read_launcher_link(device_dir)
        if link is None:
            return None
        return self._remote_index.get(
            (link.repository_url, link.name_on_repository))

    def _backfill_installed_sha256(self) -> None:
        changed = False
        with self._manifest_lock:
            for device_dir in self._local_device_dirs():
                record = self.installed.get(device_dir.name)
                if record is None or record.sha256 is not None:
                    continue
                rb = self._remote_for_dir(device_dir)
                if rb is None or rb.archive_sha256 is None:
                    continue
                record.sha256 = rb.archive_sha256
                changed = True
            if changed:
                save_local_manifest(self.local_manifest_path, self.installed)

    def _package_statuses(self, rb: RemoteBundle, dir_name: str,
                          device_dir: Optional[Path]) -> List[PackageStatus]:
        record = self.installed.get(dir_name)
        statuses: List[PackageStatus] = []
        for pkg in rb.packages:
            present = device_dir is not None and package_artifact_present(device_dir, pkg)
            local = record.find_package(pkg.category, pkg.key) if record else None
            statuses.append(PackageStatus(
                remote=pkg,
                installed=present,
                installed_sha256=local.sha256 if (local and present) else None,
            ))
        return statuses

    def _remote_meta_of(self, rb: RemoteBundle):
        if rb.cerf_json is None:
            return DeviceMeta(), None, None
        return parse_cerf_json_object(rb.cerf_json)

    def _fill_meta_gaps(self, existing: DeviceBundle, remote_meta: DeviceMeta,
                        remote_w: Optional[int],
                        remote_h: Optional[int]) -> None:
        for f in ("device_name", "board_id",
                  "os_name", "os_ver_major", "os_ver_minor", "os_ver_build",
                  "os_language", "device_year", "os_year", "os_notes",
                  "forbid_guest_additions"):
            if not getattr(existing.meta, f):
                setattr(existing.meta, f, getattr(remote_meta, f))
        if existing.meta.source is None:
            existing.meta.source = remote_meta.source
        if existing.default_screen_width is None and remote_w is not None:
            existing.default_screen_width = remote_w
        if existing.default_screen_height is None and remote_h is not None:
            existing.default_screen_height = remote_h

    def list_devices(self) -> List[DeviceBundle]:
        result: Dict[str, DeviceBundle] = {}
        claimed: set = set()

        for entry in self._local_device_dirs():
            meta, w, h = read_device_meta(entry)
            record = self.installed.get(entry.name)
            d = DeviceBundle(
                name=entry.name,
                remote=None,
                local_dir_exists=True,
                installed_sha256=record.sha256 if record else None,
                meta=meta,
                default_screen_width=w,
                default_screen_height=h,
                rom_size=self._device_rom_size(entry),
            )
            rb = self._remote_for_dir(entry)
            if rb is not None:
                claimed.add((rb.repo_url, rb.name))
                d.remote = rb
                d.packages = self._package_statuses(rb, entry.name, entry)
                self._fill_meta_gaps(d, *self._remote_meta_of(rb))
                if (not d.has_update and rb.cerf_json is not None
                        and cerf_json_differs(entry / "cerf.json", rb.cerf_json)):
                    d.cerf_json_pending = True
            result[d.key] = d

        for rb in self.remote_bundles:
            if (rb.repo_url, rb.name) in claimed:
                continue
            remote_meta, remote_w, remote_h = self._remote_meta_of(rb)
            d = DeviceBundle(
                name=rb.name,
                remote=rb,
                local_dir_exists=False,
                installed_sha256=None,
                meta=remote_meta,
                default_screen_width=remote_w,
                default_screen_height=remote_h,
                packages=self._package_statuses(rb, rb.name, None),
                key=f"{rb.repo_url}::{rb.name}",
            )
            result[d.key] = d

        return sorted(result.values(), key=lambda b: b.name.lower())

    def _allocate_dir_name(self, base: str) -> str:
        """Free directory name for a fresh install: the bundle's own name, or
        - when devices/<name> is already taken - the name plus a random
        8-char suffix."""
        if not (self.devices_dir / base).exists():
            return base
        alphabet = string.ascii_letters + string.digits
        while True:
            cand = f"{base}_{''.join(random.choices(alphabet, k=8))}"
            if not (self.devices_dir / cand).exists():
                return cand

    def submit_install(self, device: DeviceBundle, progress: ProgressFn,
                       cancel_event: Optional[threading.Event] = None) -> Future:
        rb = device.remote
        if rb is None:
            raise BundleError(f"{device.name}: no remote bundle to install")
        dir_name = device.name if device.local_dir_exists else None
        return self._pool.submit(self._do_install, rb.repo_url, rb.name,
                                 dir_name, progress, cancel_event)

    def submit_refresh_cerf_json(self, dir_name: str) -> Future:
        """Write the remote manifest's cerf_json to an installed device without
        a ROM download."""
        return self._pool.submit(self._do_refresh_cerf_json, dir_name)

    def _do_refresh_cerf_json(self, dir_name: str) -> str:
        device_dir = self._bundle_dir(dir_name)
        rb = self._remote_for_dir(device_dir)
        if rb is None or rb.cerf_json is None:
            raise BundleError(f"{dir_name}: no remote cerf.json to apply")
        write_cerf_json(device_dir / "cerf.json", rb.cerf_json)
        return dir_name

    def _do_install(self, repo_url: str, remote_name: str,
                    dir_name: Optional[str], progress: ProgressFn,
                    cancel_event: Optional[threading.Event]) -> str:
        bundle = self._remote_index.get((repo_url, remote_name))
        if bundle is None:
            raise BundleError(f"unknown remote bundle: {remote_name}")
        if dir_name is None:
            dir_name = self._allocate_dir_name(bundle.name)
        target = self._bundle_dir(dir_name)
        with tempfile.TemporaryDirectory(prefix=".sync_", dir=str(self.devices_dir)) as tmp_name:
            tmp = Path(tmp_name)
            prepared = download_extract(
                bundle.archive_url, dir_name, tmp,
                bundle.archive_size, bundle.archive_sha256,
                progress, cancel_event)
            # Installed additional packages (a CF image may be the user's
            # mutated persistent disk) and cerf-user.json (user's persisted
            # options, display name, and the repository link) survive a ROM
            # update: stash them aside, wipe, restore after the new ROM is in
            # place.
            preserved = self._stash_installed_packages(dir_name, target,
                                                       tmp / "preserved")
            user_json_stash: Optional[Path] = None
            if (target / CERF_USER_JSON_FILENAME).is_file():
                user_json_stash = tmp / CERF_USER_JSON_FILENAME
                shutil.move(str(target / CERF_USER_JSON_FILENAME),
                            str(user_json_stash))
            if target.exists():
                shutil.rmtree(target)
            shutil.move(str(prepared), str(target))
            for record, stash_path in preserved:
                dest = target / record.key
                remove_artifact(dest)
                shutil.move(str(stash_path), str(dest))
            if user_json_stash is not None:
                shutil.move(str(user_json_stash),
                            str(target / CERF_USER_JSON_FILENAME))

        # Manifest v2: cerf.json is not packed in the ROM zip; the launcher
        # writes it from the manifest's cerf_json after unpacking.
        if bundle.cerf_json is not None:
            write_cerf_json(target / "cerf.json", bundle.cerf_json)
        write_launcher_link(target, LauncherLink(bundle.repo_url, bundle.name))

        with self._manifest_lock:
            self.installed[dir_name] = LocalBundleRecord(
                updated_at=bundle.updated_at,
                sha256=bundle.archive_sha256,
                packages=[record for record, _ in preserved],
            )
            save_local_manifest(self.local_manifest_path, self.installed)
        return dir_name

    def _stash_installed_packages(
            self, name: str, target: Path,
            stash_dir: Path) -> List[Tuple[LocalPackageRecord, Path]]:
        record = self.installed.get(name)
        if record is None or not record.packages or not target.is_dir():
            return []
        preserved: List[Tuple[LocalPackageRecord, Path]] = []
        for pkg_record in record.packages:
            src = target / pkg_record.key
            if not src.exists():
                continue
            stash_dir.mkdir(parents=True, exist_ok=True)
            stash_path = stash_dir / f"{pkg_record.category}__{pkg_record.key}"
            shutil.move(str(src), str(stash_path))
            preserved.append((pkg_record, stash_path))
        return preserved

    def prepare_manual_install(self, device: DeviceBundle) -> str:
        """GUI manual-download path: pre-create the device directory, write its
        cerf.json from the remote manifest, link it to the repository, and
        record the bundle in the local manifest at the remote version. The user
        then unpacks the ZIP they downloaded in a browser into this directory;
        update tracking already matches the recorded version, so the bundle
        reads as up to date once the ROM files are in place. Returns the
        directory name."""
        bundle = device.remote
        if bundle is None:
            raise BundleError(f"{device.name}: no remote bundle to install")
        dir_name = (device.name if device.local_dir_exists
                    else self._allocate_dir_name(bundle.name))
        target = self._bundle_dir(dir_name)
        target.mkdir(parents=True, exist_ok=True)
        if bundle.cerf_json is not None:
            write_cerf_json(target / "cerf.json", bundle.cerf_json)
        write_launcher_link(target, LauncherLink(bundle.repo_url, bundle.name))
        with self._manifest_lock:
            record = self.installed.get(dir_name) or LocalBundleRecord()
            record.updated_at = bundle.updated_at
            record.sha256 = bundle.archive_sha256
            self.installed[dir_name] = record
            save_local_manifest(self.local_manifest_path, self.installed)
        return dir_name

    def _linked_remote(self, name: str) -> RemoteBundle:
        """The remote bundle a device DIRECTORY is linked to via its
        cerf-user.json launcher block."""
        rb = self._remote_for_dir(self._bundle_dir(name))
        if rb is None:
            raise BundleError(
                f"{name}: not linked to a bundle repository entry")
        return rb

    def prepare_manual_install_package(self, name: str, category: str,
                                       key: str) -> None:
        """GUI manual-download path for an additional package: record it in the
        local manifest at the remote sha256 so update tracking matches once the
        user unpacks the browser-downloaded artifact into the device directory.
        Presence is re-derived from disk at list time, so the package reads as
        installed only after its artifact actually lands."""
        bundle = self._linked_remote(name)
        pkg = bundle.find_package(category, key)
        if pkg is None:
            raise BundleError(f"{name}: unknown package {category}/{key}")
        target = self._bundle_dir(name)
        if not target.is_dir():
            raise BundleError(f"{name}: device not installed; install bundle first")
        with self._manifest_lock:
            record = self.installed.setdefault(name, LocalBundleRecord())
            record.drop_package(category, key)
            record.packages.append(LocalPackageRecord(
                category=category, key=pkg.key,
                is_directory=pkg.is_directory,
                sha256=pkg.archive_sha256 or ""))
            save_local_manifest(self.local_manifest_path, self.installed)

    def submit_install_package(self, name: str, category: str, key: str,
                               progress: ProgressFn,
                               cancel_event: Optional[threading.Event] = None) -> Future:
        return self._pool.submit(self._do_install_package, name, category, key,
                                 progress, cancel_event)

    def _do_install_package(self, name: str, category: str, key: str,
                            progress: ProgressFn,
                            cancel_event: Optional[threading.Event]) -> None:
        bundle = self._linked_remote(name)
        pkg = bundle.find_package(category, key)
        if pkg is None:
            raise BundleError(f"{name}: unknown package {category}/{key}")
        target = self._bundle_dir(name)
        if not target.is_dir():
            raise BundleError(f"{name}: device not installed; install bundle first")
        label = f"{name} {pkg.name}"
        with tempfile.TemporaryDirectory(prefix=".pkg_", dir=str(self.devices_dir)) as tmp_name:
            tmp = Path(tmp_name)
            prepared = download_extract(
                pkg.archive_url, label, tmp,
                pkg.archive_size, pkg.archive_sha256,
                progress, cancel_event)
            dest = target / pkg.key
            if pkg.is_directory:
                # Directory packages (e.g. PDBs) ship a flat archive whose
                # root contents become devices/<name>/<directory>/.
                remove_artifact(dest)
                shutil.move(str(prepared), str(dest))
            else:
                src = prepared / pkg.key
                if not src.is_file():
                    raise BundleError(
                        f"{label}: archive does not contain {pkg.key}")
                remove_artifact(dest)
                shutil.move(str(src), str(dest))

        with self._manifest_lock:
            record = self.installed.setdefault(name, LocalBundleRecord())
            record.drop_package(category, key)
            record.packages.append(LocalPackageRecord(
                category=category, key=pkg.key,
                is_directory=pkg.is_directory,
                sha256=pkg.archive_sha256 or ""))
            save_local_manifest(self.local_manifest_path, self.installed)

    def submit_delete_package(self, name: str, category: str, key: str) -> Future:
        return self._pool.submit(self._do_delete_package, name, category, key)

    def _do_delete_package(self, name: str, category: str, key: str) -> None:
        if not is_safe_bundle_name(key):
            raise BundleError(f"unsafe package artifact name: {key!r}")
        target = self._bundle_dir(name)
        remove_artifact(target / key)
        with self._manifest_lock:
            record = self.installed.get(name)
            if record is not None:
                record.drop_package(category, key)
                save_local_manifest(self.local_manifest_path, self.installed)

    def submit_delete(self, name: str) -> Future:
        return self._pool.submit(self._do_delete, name)

    def _do_delete(self, name: str) -> None:
        target = self._bundle_dir(name)
        if target.exists():
            shutil.rmtree(target)
        with self._manifest_lock:
            self.installed.pop(name, None)
            save_local_manifest(self.local_manifest_path, self.installed)

    def _bundle_dir(self, name: str) -> Path:
        if not is_safe_bundle_name(name):
            raise BundleError(f"unsafe bundle name: {name!r}")
        path = (self.devices_dir / name).resolve()
        devices = self.devices_dir.resolve()
        try:
            path.relative_to(devices)
        except ValueError as exc:
            raise BundleError(f"refusing to operate outside {devices}") from exc
        return path
