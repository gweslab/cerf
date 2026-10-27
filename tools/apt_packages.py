import sys

from tool_process import exit_code

BUILD_TOOLS = ("cmake", "ninja-build", "g++", "pkg-config", "ccache", "wine")
BUILD_PACKAGES = ("git",) + BUILD_TOOLS + (
    "qt6-base-dev", "qt6-svg-dev", "qt6-declarative-dev", "qt6-declarative-dev-tools",
    "qml6-module-qtquick", "qml6-module-qtquick-controls", "qml6-module-qtquick-templates",
    "qml6-module-qtquick-layouts", "qml6-module-qtquick-window", "qml6-module-qtqml-workerscript",
    "qml6-module-qtquick-dialogs", "qml6-module-qtquick-effects", "qml6-module-qtqml", "qml6-module-qtqml-models",
    "libslirp-dev", "libzip-dev", "nlohmann-json3-dev", "libasound2-dev", "libxcb1-dev", "libxcb-randr0-dev",
    "libwayland-dev")
ANDROID_BUILD_PACKAGES = BUILD_TOOLS + ("curl", "make", "perl", "bison", "flex", "zip", "unzip", "tar",
                                        "python3-venv", "openjdk-21-jdk-headless")
PACKAGE_SETS = {"linux": BUILD_PACKAGES, "android": ANDROID_BUILD_PACKAGES}


def install_command():
    return "sudo apt install " + " ".join(BUILD_PACKAGES)


if __name__ == "__main__":
    sys.exit(exit_code(["apt-get", "install", "-y", "--no-install-recommends", *PACKAGE_SETS[sys.argv[1]]]))
