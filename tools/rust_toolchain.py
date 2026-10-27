from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Callable, Dict, List, Sequence

from json_files import read_json_or_none, write_json
from tool_log import tagged
from tool_process import prepend_path, run_or_raise
from verified_download import fetch_verified

RUSTUP_VERSION = "1.29.2"
STABLE = "1.99.1"
NIGHTLY = "nightly-2026-10-20"
RUST_DIR = Path("third_party") / "rust"
STAMP_NAME = "cerf_rust.json"

INSTALLERS = {
    "win32": ("x86_64-pc-windows-msvc", "rustup-init.exe",
              "00f139da614dced87d3c3d4121c43eebdac3c1bf8a5ee86b9d80dfd71c8d70fd"),
    "linux": ("x86_64-unknown-linux-gnu", "rustup-init",
              "5be191e8c70a5007074254cb74d78dbfdd25cd5a61c27de7b8e5410122ec24f4"),
    "darwin": ("aarch64-apple-darwin", "rustup-init",
               "f7c7e11eb2e07f006e532a8aaac77b32f4527d305ac386c0c633ca6133d35ca9"),
}


class RustError(Exception):
    pass


say = tagged("RUST")


class RustToolchain:
    def __init__(self, root: Path, heartbeat: Callable[[], None]) -> None:
        self.home = root / RUST_DIR
        self.rustup_home = self.home / "rustup"
        self.cargo_home = self.home / "cargo"
        self.heartbeat = heartbeat

    def environment(self, base: Dict[str, str]) -> Dict[str, str]:
        env = prepend_path(base, self.cargo_home / "bin")
        env["RUSTUP_HOME"] = str(self.rustup_home)
        env["CARGO_HOME"] = str(self.cargo_home)
        env.pop("RUSTUP_TOOLCHAIN", None)
        return env

    def cargo(self) -> Path:
        return self.cargo_home / "bin" / ("cargo.exe" if os.name == "nt" else "cargo")

    def _rustup(self) -> Path:
        return self.cargo_home / "bin" / ("rustup.exe" if os.name == "nt" else "rustup")

    def _run(self, argv: Sequence[object]) -> None:
        run_or_raise(argv, RustError, env=self.environment(dict(os.environ)))
        self.heartbeat()

    def _install_rustup(self) -> None:
        if self._rustup().is_file():
            return
        triple, name, sha256 = INSTALLERS[sys.platform]
        local = self.home / "downloads" / RUSTUP_VERSION / triple / name
        fetch_verified("https://static.rust-lang.org/rustup/archive/{}/{}/{}".format(RUSTUP_VERSION, triple, name),
                       local, sha256, say)
        if os.name != "nt":
            local.chmod(0o755)
        say("Installing rustup {} into {}".format(RUSTUP_VERSION, self.home))
        self._run([local, "-y", "--no-modify-path", "--profile", "minimal", "--default-toolchain", "none"])

    def ensure(self, toolchain: str, targets: List[str], components: List[str]) -> None:
        stamp = self.home / STAMP_NAME
        recorded: Dict[str, object] = read_json_or_none(stamp) or {}
        wanted = {"targets": sorted(targets), "components": sorted(components)}
        if recorded.get(toolchain) == wanted and self._rustup().is_file():
            return
        self._install_rustup()
        argv: List[object] = [self._rustup(), "toolchain", "install", toolchain, "--profile", "minimal",
                              "--no-self-update"]
        for component in components:
            argv += ["--component", component]
        for target in targets:
            argv += ["--target", target]
        say("Installing Rust {}".format(toolchain))
        self._run(argv)
        recorded[toolchain] = wanted
        write_json(stamp, recorded)
