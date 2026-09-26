import re

from branding import AUTHOR, PRODUCT_NAME, copyright_line


def _defines(header_path):
    try:
        with open(header_path, "r", encoding="utf-8", errors="ignore") as f:
            text = f.read()
    except OSError:
        return {}
    out = {}
    for name in ("MAJOR", "MINOR", "PATCH", "BUILD_WORD"):
        match = re.search(r"#define\s+CERF_VERSION_" + name + r"\s+(\d+)", text)
        out[name] = int(match.group(1)) if match else 0
    return out


def version_tuple(header_path):
    d = _defines(header_path)
    if not d:
        return (0, 0, 0, 0)
    return (d["MAJOR"], d["MINOR"], d["PATCH"], d["BUILD_WORD"])


def version_string(header_path):
    return ".".join(str(n) for n in version_tuple(header_path))


def rc_script(header_path, original_filename, internal_name, description,
              icon_paths):
    numbers = ",".join(str(n) for n in version_tuple(header_path))
    text = version_string(header_path)
    icons = "".join('{} ICON "{}"\n'.format(index + 1, path.replace("\\", "/"))
                    for index, path in enumerate(icon_paths))
    strings = "".join('            VALUE "{}", "{}"\n'.format(key, value)
                      for key, value in (
                          ("CompanyName", AUTHOR),
                          ("FileDescription", description),
                          ("FileVersion", text),
                          ("InternalName", internal_name),
                          ("LegalCopyright", copyright_line()),
                          ("OriginalFilename", original_filename),
                          ("ProductName", PRODUCT_NAME),
                          ("ProductVersion", text)))
    return ("#include <winver.h>\n" + icons +
            "1 VERSIONINFO\n"
            " FILEVERSION {0}\n"
            " PRODUCTVERSION {0}\n"
            " FILEOS VOS_NT_WINDOWS32\n"
            " FILETYPE VFT_APP\n"
            "BEGIN\n"
            '    BLOCK "StringFileInfo"\n'
            "    BEGIN\n"
            '        BLOCK "040904E4"\n'
            "        BEGIN\n"
            "{1}"
            "        END\n"
            "    END\n"
            '    BLOCK "VarFileInfo"\n'
            "    BEGIN\n"
            '        VALUE "Translation", 0x0409, 0x04E4\n'
            "    END\n"
            "END\n").format(numbers, strings)


def build(header_path, original_filename, internal_name, description):
    from PyInstaller.utils.win32 import versioninfo as vi

    numbers = version_tuple(header_path)
    text = version_string(header_path)
    strings = [
        vi.StringStruct("CompanyName", AUTHOR),
        vi.StringStruct("FileDescription", description),
        vi.StringStruct("FileVersion", text),
        vi.StringStruct("InternalName", internal_name),
        vi.StringStruct("LegalCopyright", copyright_line()),
        vi.StringStruct("OriginalFilename", original_filename),
        vi.StringStruct("ProductName", PRODUCT_NAME),
        vi.StringStruct("ProductVersion", text),
    ]
    return vi.VSVersionInfo(
        ffi=vi.FixedFileInfo(filevers=numbers, prodvers=numbers),
        kids=[vi.StringFileInfo([vi.StringTable("040904E4", strings)]),
              vi.VarFileInfo([vi.VarStruct("Translation", [0x0409, 0x04E4])])])
