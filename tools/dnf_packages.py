import sys

from tool_process import exit_code

BUILD_PACKAGES = ("git", "python3", "cmake", "ninja-build", "gcc-toolset-15-gcc-c++", "ccache", "patchelf",
                  "pkgconf-pkg-config", "alsa-lib-devel", "libxcb-devel", "wayland-devel", "mesa-libGL-devel",
                  "zip", "unzip", "tar", "xz", "perl", "make", "bison", "flex", "libbrotli", "fontconfig", "freetype",
                  "harfbuzz", "libxkbcommon", "libxkbcommon-x11", "xcb-util-cursor", "xcb-util-wm", "xcb-util-image",
                  "xcb-util-keysyms", "xcb-util-renderutil")


if __name__ == "__main__":
    if sys.argv[1:] == ["--list"]:
        print(" ".join(BUILD_PACKAGES))
        sys.exit(0)
    sys.exit(exit_code(["dnf", "install", "-y", *BUILD_PACKAGES]))
