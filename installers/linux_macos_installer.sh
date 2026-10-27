#!/bin/sh
set -eu

PRODUCT='CE Runtime Foundation'
RELEASE_API='https://api.github.com/repos/gweslab/cerf/releases/latest'
CI_BASE='https://cerf-bundles.dz3n.net/cerf_ci'
APT_PACKAGES='libasound2t64 libc6 libgcc-s1 libqt6core6t64 libqt6dbus6 libqt6gui6 libqt6network6
libqt6qml6 libqt6quick6 libqt6widgets6 libslirp0 libstdc++6 libwayland-client0 libxcb1 libxcb-randr0
libzip5 qml6-module-qtqml qml6-module-qtqml-models qml6-module-qtqml-workerscript qml6-module-qtquick
qml6-module-qtquick-controls qml6-module-qtquick-dialogs qml6-module-qtquick-effects qml6-module-qtquick-layouts
qml6-module-qtquick-templates qml6-module-qtquick-window qt6-svg-plugins unzip python3'
PACMAN_PACKAGES='qt6-base qt6-declarative qt6-svg libslirp libzip alsa-lib libxcb wayland unzip python'
DNF_PACKAGES='qt6-qtbase qt6-qtbase-gui qt6-qtdeclarative qt6-qtsvg libslirp libzip alsa-lib libxcb
libwayland-client unzip python3'
ZYPPER_PACKAGES='libQt6Core6 libQt6Gui6 libQt6Widgets6 libQt6Network6 libQt6DBus6 libQt6Qml6 libQt6Quick6
qt6-declarative-imports libQt6Svg6 libslirp0 libzip5 libasound2 libxcb1 libxcb-randr0 libwayland-client0
unzip python3'

fail() {
    printf '%s\n' "$*" >&2
    exit 1
}

ask() {
    printf '%s ' "$1" > /dev/tty
    IFS= read -r REPLY < /dev/tty || fail 'No answer: this installer reads its answers from the terminal.'
    REPLY=$(printf '%s' "$REPLY" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
}

yes_no() {
    if [ "$2" = yes ]; then hint='[Y/n]'; else hint='[y/N]'; fi
    while :; do
        ask "$1 $hint"
        case "$(printf '%s' "$REPLY" | tr '[:upper:]' '[:lower:]')" in
            '') [ "$2" = yes ]; return ;;
            y | yes) return 0 ;;
            n | no) return 1 ;;
        esac
    done
}

detect_host() {
    case "$(uname -s) $(uname -m)" in
        'Linux x86_64')
            BRANCH=linux-amd64
            FRONTEND='cerf' ;;
        'Darwin arm64')
            BRANCH=macos-arm64
            FRONTEND='CE Runtime Foundation.app/Contents/MacOS/CE Runtime Foundation' ;;
        *)
            fail "$PRODUCT has no build for $(uname -s) on $(uname -m)." ;;
    esac
}

package_installed() {
    case "$1" in
        apt) [ "$(dpkg-query -W -f='${Status}' "$2" 2> /dev/null)" = 'install ok installed' ] ;;
        pacman) pacman -Q "$2" > /dev/null 2>&1 ;;
        dnf | zypper) rpm -q --whatprovides "$2" > /dev/null 2>&1 ;;
    esac
}

install_linux_packages() {
    if command -v apt-get > /dev/null 2>&1; then
        manager=apt; packages=$APT_PACKAGES
    elif command -v pacman > /dev/null 2>&1; then
        manager=pacman; packages=$PACMAN_PACKAGES
    elif command -v dnf > /dev/null 2>&1; then
        manager=dnf; packages=$DNF_PACKAGES
    elif command -v zypper > /dev/null 2>&1; then
        manager=zypper; packages=$ZYPPER_PACKAGES
    else
        for tool in unzip python3; do
            command -v "$tool" > /dev/null 2>&1 || fail "This installer needs $tool. Install it, then run the installer again."
        done
        printf '%s\n' "This installer installs packages with apt-get, pacman, dnf or zypper, and this system has none of them."
        return 0
    fi
    missing=''
    for package in $packages; do
        package_installed "$manager" "$package" || missing="$missing $package"
    done
    [ -n "$missing" ] || return 0
    case "$manager" in
        apt) set -- 'sudo apt-get update' \
            "sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends$missing" ;;
        pacman) set -- "sudo pacman -S --needed --noconfirm$missing" ;;
        dnf) set -- "sudo dnf install -y$missing" ;;
        zypper) set -- "sudo zypper --non-interactive install$missing" ;;
    esac
    printf '%s\n' "These commands install the packages that $PRODUCT needs:"
    printf '  %s\n' "$@"
    yes_no 'Run these commands?' yes || fail "The packages were not installed. $PRODUCT was not installed."
    for command in "$@"; do
        $command < /dev/null
    done
}

query_linux() {
    python3 -I - "$1" "$2" "$3" << 'EOF'
import json
import sys

mode, path, branch = sys.argv[1:4]
with open(path, encoding="utf-8") as stream:
    data = json.load(stream)
name, size, sha256, url, version = "", 0, "", "", ""
if mode == "release":
    version = str(data.get("tag_name") or "")
    suffix = "-Release-" + branch + ".zip"
    for asset in data.get("assets") or []:
        if str(asset.get("name") or "").endswith(suffix):
            name = asset["name"]
            size = asset.get("size") or 0
            digest = str(asset.get("digest") or "")
            sha256 = digest[7:] if digest.startswith("sha256:") else ""
            url = str(asset.get("browser_download_url") or "")
            break
else:
    entry = (data.get("host_branches") or {}).get(branch) or {}
    name = str(entry.get("object_name") or "")
    if "/" in name or "\\" in name or name.startswith("."):
        name = ""
    size = entry.get("object_size") or 0
    sha256 = str(entry.get("object_sha256") or "")
    version = ".".join(str(entry.get(key)) for key in ("ver_major", "ver_minor", "ver_patch", "ver_build"))
print("\n".join([name, str(size), sha256, url, version]))
EOF
}

query_macos() {
    osascript -l JavaScript - "$1" "$2" "$3" << 'EOF'
ObjC.import('Foundation');
function run(argv) {
    var mode = argv[0], branch = argv[2];
    var text = $.NSString.stringWithContentsOfFileEncodingError(argv[1], $.NSUTF8StringEncoding, null).js;
    var data = JSON.parse(text);
    var name = '', size = 0, sha256 = '', url = '', version = '';
    if (mode === 'release') {
        version = String(data.tag_name || '');
        var suffix = '-Release-' + branch + '.zip';
        var assets = data.assets || [];
        for (var i = 0; i < assets.length; i++) {
            var assetName = String(assets[i].name || '');
            if (assetName.slice(-suffix.length) === suffix) {
                name = assetName;
                size = assets[i].size || 0;
                var digest = String(assets[i].digest || '');
                sha256 = digest.indexOf('sha256:') === 0 ? digest.slice(7) : '';
                url = String(assets[i].browser_download_url || '');
                break;
            }
        }
    } else {
        var entry = (data.host_branches || {})[branch] || {};
        name = String(entry.object_name || '');
        if (name.indexOf('/') >= 0 || name.indexOf('\\') >= 0 || name.charAt(0) === '.') name = '';
        size = entry.object_size || 0;
        sha256 = String(entry.object_sha256 || '');
        version = [entry.ver_major, entry.ver_minor, entry.ver_patch, entry.ver_build].join('.');
    }
    return [name, String(size), sha256, url, version].join('\n');
}
EOF
}

query_build() {
    if [ "$BRANCH" = macos-arm64 ]; then query_macos "$@"; else query_linux "$@"; fi
}

sha256_of() {
    if command -v sha256sum > /dev/null 2>&1; then
        sha256sum "$1" | cut -d ' ' -f 1
    else
        shasum -a 256 "$1" | cut -d ' ' -f 1
    fi
}

main() {
    [ -r /dev/tty ] || fail 'This installer needs a terminal for its questions.'
    detect_host

    default_dir="$HOME/$PRODUCT"
    while :; do
        ask "Install folder (press Enter for $default_dir)"
        install_dir=$REPLY
        case "$install_dir" in
            '~') install_dir=$HOME ;;
            '~/'*) install_dir="$HOME/${install_dir#\~/}" ;;
        esac
        if [ -z "$install_dir" ] || [ "$install_dir" = "$default_dir" ]; then
            install_dir=$default_dir
            break
        fi
        printf '%s\n' 'Prefer a directory under your home folder. A system-wide path asks for root rights and can break later upgrades.'
        if yes_no 'Are you sure you want to change the directory?' no; then break; fi
    done
    launch_after=yes
    yes_no 'Launch after installation?' yes || launch_after=no
    unstable=no
    yes_no 'Install unstable version?' no && unstable=yes
    if [ "$unstable" = yes ]; then
        printf '%s\n' 'You picked an unstable build to install. This build might break on new updates or clobber your installation directory. If you want to continue receiving unstable channel updates, pick that channel in Settings later.'
        yes_no 'Would you like to continue?' no || return 0
    fi

    if [ "$BRANCH" = linux-amd64 ]; then install_linux_packages; fi
    command -v unzip > /dev/null 2>&1 || fail 'This installer needs unzip.'

    meta=$(mktemp "${TMPDIR:-/tmp}/cerf-installer.XXXXXX")
    trap 'rm -f "$meta" "$meta.out"' EXIT
    if [ "$unstable" = yes ]; then
        kind='unstable build'
        curl -fsSL -o "$meta" "$CI_BASE/latest.json"
        query_build unstable "$meta" "$BRANCH" > "$meta.out"
    else
        kind='release'
        curl -fsSL -o "$meta" "$RELEASE_API"
        query_build release "$meta" "$BRANCH" > "$meta.out"
    fi
    {
        IFS= read -r name
        IFS= read -r size
        IFS= read -r sha256
        IFS= read -r url
        IFS= read -r version
    } < "$meta.out"
    if [ -z "$name" ]; then
        if [ "$unstable" = yes ]; then fail "latest.json names no $BRANCH build."; fi
        fail "The release $version has no *-Release-$BRANCH.zip asset."
    fi
    if [ "$unstable" = yes ]; then url="$CI_BASE/$name"; fi
    printf '%s\n' "Latest $kind: $PRODUCT $version"

    mkdir -p "$install_dir"
    install_dir=$(cd "$install_dir" && pwd)
    upgrade_dir="$install_dir/upgrade"
    zip="$install_dir/upgrade.zip"
    printf '%s\n' "Preparing $upgrade_dir"
    rm -rf "$upgrade_dir"
    rm -f "$zip"

    tenths=$(( (size * 10 + 524288) / 1048576 ))
    printf '%s\n' "Downloading $name ($(( tenths / 10 )).$(( tenths % 10 )) MB)"
    curl -fL --progress-bar -o "$zip" "$url"
    actual=$(wc -c < "$zip" | tr -d ' ')
    if [ "$size" -gt 0 ] && [ "$actual" -ne "$size" ]; then
        rm -f "$zip"
        fail "The download is $actual bytes; the server announced $size bytes. $PRODUCT was not installed."
    fi
    if [ -n "$sha256" ]; then
        if [ "$(sha256_of "$zip")" != "$(printf '%s' "$sha256" | tr '[:upper:]' '[:lower:]')" ]; then
            rm -f "$zip"
            fail "The SHA-256 of the download does not match the published value. $PRODUCT was not installed."
        fi
    fi

    printf '%s\n' 'Unpacking the archive'
    unzip -q "$zip" -d "$upgrade_dir"
    rm -f "$zip"

    stage="$upgrade_dir/$FRONTEND"
    [ -x "$stage" ] || fail "$name contains no $FRONTEND. $PRODUCT was not installed."
    if [ "$BRANCH" = linux-amd64 ]; then
        unresolved=$(ldd "$stage" 2>&1 | grep 'not found' || true)
        [ -z "$unresolved" ] || fail "$PRODUCT needs libraries that this system does not have:
$unresolved
$PRODUCT was not installed."
    fi
    printf '%s\n' "Staged the new build in $upgrade_dir"

    set -- --install
    if [ "$launch_after" = no ]; then set -- "$@" --do-not-launch-after-install; fi
    (cd "$upgrade_dir" && "$stage" "$@" < /dev/null) || fail "The install stage exited with code $?."
}

main "$@"
