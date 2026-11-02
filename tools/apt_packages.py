import sys

from tool_process import exit_code

COMPILE_TOOLS = ("cmake", "ninja-build", "g++", "pkg-config", "ccache")
CE_APPS_PACKAGES = ("wine",)
BUILD_PACKAGES = ("git",) + COMPILE_TOOLS + CE_APPS_PACKAGES + (
    "clang", "patchelf", "curl", "zip", "unzip", "tar", "make", "perl", "bison", "flex", "libgl-dev", "libasound2-dev", "libxcb1-dev",
    "libxcb-randr0-dev", "libwayland-dev")
HOST_QT_TOOL_LIBRARIES = ("libgl1", "libegl1", "libglib2.0-0t64", "libxkbcommon0", "libdbus-1-3", "libfreetype6",
                          "libfontconfig1", "libx11-6")
ANDROID_BUILD_PACKAGES = COMPILE_TOOLS + HOST_QT_TOOL_LIBRARIES + (
    "curl", "make", "perl", "bison", "flex", "zip", "unzip", "tar", "python3-venv", "openjdk-21-jdk-headless")
PACKAGE_SETS = {"linux": BUILD_PACKAGES, "ce-apps": CE_APPS_PACKAGES, "android": ANDROID_BUILD_PACKAGES}


def install_command():
    return "sudo apt install " + " ".join(BUILD_PACKAGES)


if __name__ == "__main__":
    sys.exit(exit_code(["apt-get", "install", "-y", "--no-install-recommends", *PACKAGE_SETS[sys.argv[1]]]))
