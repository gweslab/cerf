#include "host_file_bytes.h"

#include "string_utils.h"

#include <fstream>

std::vector<uint8_t> ReadHostFileBytes(const std::string& path) {
    std::ifstream f(Utf8ToWide(path.c_str()), std::ios::binary | std::ios::ate);
    if (!f.is_open()) return {};
    const auto sz = f.tellg();
    std::vector<uint8_t> bytes(static_cast<size_t>(sz));
    f.seekg(0);
    f.read(reinterpret_cast<char*>(bytes.data()), sz);
    return bytes;
}

bool HostFileNonEmpty(const std::string& path) {
    WIN32_FILE_ATTRIBUTE_DATA fad{};
    if (!GetFileAttributesExW(Utf8ToWide(path.c_str()).c_str(), GetFileExInfoStandard, &fad))
        return false;
    if (fad.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) return false;
    return fad.nFileSizeHigh != 0 || fad.nFileSizeLow != 0;
}
