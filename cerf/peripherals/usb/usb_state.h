#pragma once

#include "../../state/state_stream.h"
#include <string>
#include <vector>

namespace UsbState {
inline void Require(StateReader& r, bool ok, const char* reason) {
    if (!ok) r.Reject("USB: %s", reason);
}
inline void WriteString(StateWriter& w, const char* length_name, const char* name,
                        const std::string& value) {
    w.Write<uint32_t>(length_name, static_cast<uint32_t>(value.size()));
    w.WriteBytes(name, value.data(), value.size());
}
inline std::string ReadString(StateReader& r, const char* length_name, const char* name) {
    uint32_t n = 0; r.Read(length_name, n);
    Require(r, n <= 32768, "invalid string length");
    std::string value(n, '\0'); r.ReadBytes(name, value.data(), n);
    Require(r, value.find('\0') == std::string::npos, "invalid string");
    return value;
}
inline void WriteBuffer(StateWriter& w, const char* size_name, const char* name,
                        const std::vector<uint8_t>& value) {
    w.Write<uint32_t>(size_name, static_cast<uint32_t>(value.size()));
    w.WriteBytes(name, value.data(), value.size());
}
inline void ReadBuffer(StateReader& r, const char* size_name, const char* name,
                       std::vector<uint8_t>& value, uint32_t limit) {
    uint32_t n = 0; r.Read(size_name, n);
    Require(r, n <= limit, "invalid transfer buffer length");
    value.resize(n); r.ReadBytes(name, value.data(), n);
}
}
