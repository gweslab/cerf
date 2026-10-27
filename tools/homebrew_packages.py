import sys

from tool_process import exit_code

BUILD_FORMULAE = ("cmake", "ninja", "pkgconf", "ccache", "qtbase", "qtsvg", "qtdeclarative", "libslirp",
                  "libzip", "nlohmann-json")


def install_command():
    return "brew install " + " ".join(BUILD_FORMULAE)


if __name__ == "__main__":
    sys.exit(exit_code(["brew", "install", *BUILD_FORMULAE]))
