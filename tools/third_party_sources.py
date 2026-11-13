#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import host_branch
import http_request
import qt_online_repository
import vcpkg_install
from product_facts import NOTICES_NAME

QT_VERSION = qt_online_repository.QT_VERSION
QT_SOURCE_URL = "https://download.qt.io/official_releases/qt/{0}/{1}/submodules/{2}-everywhere-src-{1}.tar.xz"
QT_SOURCES = {
    "qtbase": "a951bd163c7b80fc6b8c88d7668fb56abf91c152373e13c10666763238131307",
    "qtsvg": "e4ab39534ec97987b1b9b60ef7f4d3253d5912a69f8c713a01753174a4029331",
    "qtdeclarative": "311f3a2603e1973bb59baef9dfa740a376de713157d4782ee043681e889c9260",
    "qtwayland": "ae14d9bcf1bb3c300a3ab2e6a53f50284e5c6c966a4ac4cc5aedcb1bc74e4d02",
}
LINUX_QT_MODULES = ("qtbase", "qtsvg", "qtdeclarative", "qtwayland")
ANDROID_QT_MODULES = ("qtbase", "qtsvg", "qtdeclarative")
QT_MODULES = {
    host_branch.LINUX_AMD64: LINUX_QT_MODULES,
    host_branch.LINUX_ARM64: LINUX_QT_MODULES,
    host_branch.ANDROID_ARM64: ANDROID_QT_MODULES,
    host_branch.ANDROID_AMD64: ANDROID_QT_MODULES,
}
GLIBC_VCPKG_PORTS = ("glib",)
BIONIC_VCPKG_PORTS = ("glib", "gettext-libintl")
VCPKG_PORTS = {
    host_branch.WIN32_X86: ("glib", "libiconv", "gettext-libintl"),
    host_branch.LINUX_AMD64: GLIBC_VCPKG_PORTS,
    host_branch.LINUX_ARM64: GLIBC_VCPKG_PORTS,
    host_branch.ANDROID_ARM64: BIONIC_VCPKG_PORTS,
    host_branch.ANDROID_AMD64: BIONIC_VCPKG_PORTS,
}
VCPKG_PORT_ID = "SPDXRef-port"
VCPKG_REGISTRY_RAW = "https://raw.githubusercontent.com/microsoft/vcpkg/{}/ports/{}/{}"
LIBCERFCORE = "libCerfCore"
OVERLAY_PORTS = "vcpkg-ports"
GITHUB = "https://github.com/"
GITHUB_RAW = "https://raw.githubusercontent.com/"
LGPL_TAG = "LGPL"
NOTICES_SOURCES_HEADING = "SOURCES\n-------\n\n"
SOURCE_RPM_SUFFIX = ".src.rpm"
HOMEBREW_FORMULAE = ("qtbase", "qtsvg", "qtdeclarative", "glib", "gettext", "graphite2")
HOMEBREW_CORE_RAW = "https://raw.githubusercontent.com/Homebrew/homebrew-core/{}/{}"
HOMEBREW_BOTTLES = "https://ghcr.io/v2/homebrew/core/{}/{}"
HOMEBREW_BOTTLE_HEADERS = {"Authorization": "Bearer QQ==", "Accept": "application/vnd.oci.image.index.v1+json"}
HOMEBREW_BUILD_COMMIT = "org.opencontainers.image.revision"
HOMEBREW_BUILD_FORMULA = "org.opencontainers.image.source"
HOMEBREW_BOTTLE_BLOCK = re.compile(r"  bottle do.+?end\n\n?", re.S)
USER_AGENT = "CERF third-party sources"
HOMEBREW_ENV = {"HOMEBREW_DEVELOPER": "1", "HOMEBREW_NO_AUTO_UPDATE": "1"}
HOMEBREW_RECIPE = (
    'require "json"\n'
    "f = Formulary.factory(Pathname(ARGV.fetch(0)))\n"
    'puts JSON.generate({"stable" => [f.stable.url, f.stable.checksum&.hexdigest],\n'
    '  "patches" => f.patchlist.select(&:external?).map { |p| [p.url, p.resource.checksum&.hexdigest] },\n'
    '  "files" => f.patchlist.grep(LocalPatch).map { |p| p.file.to_s }})\n')

class SourceError(Exception):
    pass


@dataclass(frozen=True)
class Download:
    url: str
    want: str = ""


@dataclass
class Component:
    name: str
    version: str
    downloads: List[Download] = field(default_factory=list)


def _output(argv: List[str], env: Optional[Dict[str, str]] = None) -> str:
    return subprocess.run(argv, check=True, capture_output=True, text=True,
                          env=dict(os.environ, **(env or {}))).stdout.strip()


def _get(url: str, headers: Optional[Dict[str, str]] = None) -> bytes:
    return http_request.request(url, headers or {}, SourceError, USER_AGENT)


def _submodule_raw_base(root: Path, name: str) -> str:
    url = _output(["git", "-C", str(root), "config", "-f", ".gitmodules", "--get", "submodule.{}.url".format(name)])
    return url.removesuffix(".git").replace(GITHUB, GITHUB_RAW, 1)


def _committed_sha256(repo: Path, commit: str, path: str) -> str:
    blob = subprocess.run(["git", "-C", str(repo), "show", "{}:{}".format(commit, path)], capture_output=True)
    if blob.returncode != 0:
        raise SourceError("{} is not in {} commit {}".format(path, repo.name, commit))
    return hashlib.sha256(blob.stdout).hexdigest()


def qt_components(branch: str) -> List[Component]:
    series = ".".join(QT_VERSION.split(".")[:2])
    return [Component(module, QT_VERSION, [Download(QT_SOURCE_URL.format(series, QT_VERSION, module), QT_SOURCES[module])])
            for module in QT_MODULES.get(branch, ())]


def qt_win7_components() -> List[Component]:
    import qt_windows
    components = [Component(module, qt_windows.QT_VERSION,
                            [Download(qt_windows.QT_SOURCE_URL.format(qt_windows.QT_VERSION, module), sha256)])
                  for module, sha256 in qt_windows.QT_MODULES]
    components.append(Component("qt6windows7", qt_windows.PATCH_COMMIT, [Download(qt_windows.PATCH_URL)]))
    components += [Component(module, commit, [Download(qt_windows.UPSTREAM_FIX_URL.format(module, commit))])
                   for module, commit, _path, _digest in qt_windows.UPSTREAM_FIXES]
    return components


def _registry_baseline(root: Path) -> str:
    configuration = json.loads((root / "vcpkg-configuration.json").read_text(encoding="utf-8"))
    return configuration["default-registry"]["baseline"]


def _sums(record: dict) -> Dict[str, str]:
    return {c["algorithm"]: c["checksumValue"] for c in record.get("checksums", [])}


def vcpkg_components(root: Path, branch: str) -> List[Component]:
    share = vcpkg_install.installed_prefix(root, vcpkg_install.TRIPLETS[branch]) / "share"
    baseline = _registry_baseline(root)
    core = root / LIBCERFCORE
    core_commit = _output(["git", "-C", str(core), "rev-parse", "HEAD"])
    core_raw = "{}/{}/".format(_submodule_raw_base(root, LIBCERFCORE), core_commit)
    components = []
    for port in VCPKG_PORTS[branch]:
        spdx = json.loads((share / port / "vcpkg.spdx.json").read_text(encoding="utf-8"))
        version = next(p["versionInfo"] for p in spdx["packages"] if p["SPDXID"] == VCPKG_PORT_ID)
        component = Component("vcpkg-" + port, version)
        for package in spdx["packages"]:
            url = package.get("downloadLocation", "")
            if url.startswith("http") and "SHA512" in _sums(package):
                component.downloads.append(Download(url, _sums(package)["SHA512"]))
        if not component.downloads:
            raise SourceError("vcpkg port {} builds no source archive for {}".format(port, branch))
        records = {record["SPDXID"]: record for record in spdx.get("files", [])}
        overlay = (core / OVERLAY_PORTS / port).is_dir()
        for relation in spdx["relationships"]:
            if relation["spdxElementId"] != VCPKG_PORT_ID or relation["relationshipType"] != "CONTAINS":
                continue
            record = records[relation["relatedSpdxElement"]]
            relative = record["fileName"][2:]
            if overlay:
                path = "{}/{}/{}".format(OVERLAY_PORTS, port, relative)
                if _committed_sha256(core, core_commit, path) != _sums(record)["SHA256"]:
                    raise SourceError("{}/{} at commit {} differs from the port that vcpkg installed".format(
                        LIBCERFCORE, path, core_commit))
                component.downloads.append(Download(core_raw + path, _sums(record)["SHA256"]))
            else:
                component.downloads.append(Download(VCPKG_REGISTRY_RAW.format(baseline, port, relative),
                                                    _sums(record)["SHA256"]))
        components.append(component)
    return components


def _shipped_rpm_packages(lib: Path) -> List[Tuple[str, str, str, str]]:
    packages = []
    for path in sorted(p for p in lib.iterdir() if p.is_file() and not p.is_symlink()):
        soname = _output(["patchelf", "--print-soname", str(path)])
        found = subprocess.run(["rpm", "-q", "--whatprovides", "{}()(64bit)".format(soname), "--qf",
                                "%{NAME}\t%{VERSION}-%{RELEASE}\t%{LICENSE}\t%{SOURCERPM}\n"],
                               capture_output=True, text=True)
        if found.returncode == 0:
            package, installed, license_tag, source_rpm = found.stdout.splitlines()[0].split("\t")
            packages.append((package, installed, license_tag, source_rpm))
    return packages


def almalinux_components(release: Path) -> List[Component]:
    lib = release / "lib"
    if not lib.is_dir():
        raise SourceError("{} does not exist; the list is made from the libraries of a built release".format(lib))
    components: Dict[str, Component] = {}
    for package, installed, license_tag, source_rpm in _shipped_rpm_packages(lib):
        if LGPL_TAG not in license_tag or source_rpm in components:
            continue
        name, version, rpm_release = source_rpm[:-len(SOURCE_RPM_SUFFIX)].rsplit("-", 2)
        url = _output(["dnf", "download", "-q", "--source", "--url", "{}-{}".format(package, installed)]).splitlines()[-1]
        components[source_rpm] = Component(name, "{}-{}".format(version, rpm_release), [Download(url)])
    return list(components.values())


def _formula_build(formula: str, keg: Path, recipe: bytes) -> Tuple[str, str, bytes]:
    tags = json.loads(_get(HOMEBREW_BOTTLES.format(formula, "tags/list"), HOMEBREW_BOTTLE_HEADERS))["tags"]
    for tag in [t for t in tags if t == keg.name or t.startswith(keg.name + "-")]:
        index = json.loads(_get(HOMEBREW_BOTTLES.format(formula, "manifests/" + tag), HOMEBREW_BOTTLE_HEADERS))
        commit = index["annotations"][HOMEBREW_BUILD_COMMIT]
        path = index["annotations"][HOMEBREW_BUILD_FORMULA].split("/blob/{}/".format(commit), 1)[1]
        formula_file = _get(HOMEBREW_CORE_RAW.format(commit, path))
        if HOMEBREW_BOTTLE_BLOCK.sub("", formula_file.decode("utf-8")).encode("utf-8") == recipe:
            return commit, path, formula_file
    raise SourceError("no Homebrew bottle of {} {} was built from the formula in {}".format(formula, keg.name, keg))


def homebrew_components() -> List[Component]:
    components = []
    for formula in HOMEBREW_FORMULAE:
        keg = Path(_output(["brew", "--prefix", formula], HOMEBREW_ENV)).resolve()
        recipe = keg / ".brew" / "{}.rb".format(formula)
        commit, path, formula_file = _formula_build(formula, keg, recipe.read_bytes())
        plan = json.loads(_output(["brew", "ruby", "-e", HOMEBREW_RECIPE, str(recipe)], HOMEBREW_ENV).splitlines()[-1])
        component = Component("homebrew-" + formula, keg.name,
                              [Download(HOMEBREW_CORE_RAW.format(commit, path), hashlib.sha256(formula_file).hexdigest()),
                               Download(plan["stable"][0], plan["stable"][1])])
        component.downloads += [Download(url, sha256) for url, sha256 in plan["patches"]]
        component.downloads += [Download(HOMEBREW_CORE_RAW.format(commit, relative)) for relative in plan["files"]]
        components.append(component)
    return components


def branch_components(root: Path, branch: host_branch.HostBranch, release: Path) -> List[Component]:
    if branch.name == host_branch.MACOS_ARM64:
        return homebrew_components()
    components = qt_win7_components() if branch.name == host_branch.WIN32_X86 else qt_components(branch.name)
    components += vcpkg_components(root, branch.name)
    if branch.name in (host_branch.LINUX_AMD64, host_branch.LINUX_ARM64):
        components += almalinux_components(release)
    return components


def listing(components: List[Component]) -> str:
    lines = []
    for component in components:
        lines.append("{} {}".format(component.name, component.version))
        for item in component.downloads:
            lines.append("    {} {}".format(item.url, item.want).rstrip())
    return "\n".join(lines) + "\n"


def stamp_notices(notices: Path, text: str) -> None:
    content = notices.read_text(encoding="utf-8")
    start = content.find(NOTICES_SOURCES_HEADING)
    if start >= 0:
        content = content[:start]
    notices.write_text(content.rstrip("\n") + "\n\n\n" + NOTICES_SOURCES_HEADING + text, encoding="utf-8")


def main(argv: List[str]) -> int:
    if len(argv) not in (2, 3) or argv[0] != "list":
        print("usage: third_party_sources.py list <host branch> [<release dir>]", file=sys.stderr)
        return 2
    root = Path(__file__).resolve().parent.parent
    branch = host_branch.by_name(argv[1])
    release = Path(argv[2]) if len(argv) == 3 else host_branch.output_dir(root, "Release", branch)
    text = listing(branch_components(root, branch, release))
    if len(argv) == 3:
        stamp_notices(release / NOTICES_NAME, text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (SourceError, host_branch.UnsupportedHost, subprocess.CalledProcessError, OSError) as exc:
        print("ERROR: {}".format(exc), file=sys.stderr)
        raise SystemExit(1)
