BUILD_FORMULAE = ("cmake", "ninja", "pkgconf", "qtbase", "qtsvg", "libslirp", "nlohmann-json")
PYTHON_FORMULA = "python@3.14"
PYTHON_NAME = "python3.14"
TK_FORMULA = "python-tk@3.14"
ALL_FORMULAE = BUILD_FORMULAE + (PYTHON_FORMULA, TK_FORMULA)


def install_command():
    return "brew install " + " ".join(ALL_FORMULAE)
