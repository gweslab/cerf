#pragma once

#include "../../core/log.h"
#include "../../state/state_stream.h"
#include <string>
#include <vector>

namespace UsbState {
inline void Require(bool ok, const char* reason) {
    if (ok) return;
    LOG(Caution, "USB state restore failed: %s\n", reason);
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}
inline void WriteString(StateWriter& w, const std::string& value) {
    w.Write<uint32_t>(static_cast<uint32_t>(value.size()));
    w.WriteBytes(value.data(), value.size());
}
inline std::string ReadString(StateReader& r) {
    uint32_t n = 0; r.Read(n);
    Require(r.Ok() && n <= 32768 && r.Position() <= r.FileSize() &&
            n <= r.FileSize() - r.Position(), "invalid string length");
    std::string value(n, '\0'); r.ReadBytes(value.data(), n);
    Require(r.Ok() && value.find('\0') == std::string::npos, "invalid string");
    return value;
}
inline void WriteBuffer(StateWriter& w, const std::vector<uint8_t>& value) {
    w.Write<uint32_t>(static_cast<uint32_t>(value.size()));
    w.WriteBytes(value.data(), value.size());
}
inline void ReadBuffer(StateReader& r, std::vector<uint8_t>& value, uint32_t limit) {
    uint32_t n = 0; r.Read(n);
    Require(r.Ok() && n <= limit && r.Position() <= r.FileSize() &&
            n <= r.FileSize() - r.Position(), "invalid transfer buffer length");
    value.resize(n); r.ReadBytes(value.data(), n);
    Require(r.Ok(), "truncated transfer buffer");
}
}
