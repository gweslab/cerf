#include "wait_for_pid.h"

#include <cerfcore/core/cli_option.h>

namespace {

template <typename Char>
bool Parse(const Char* arg, std::optional<uint32_t>& pid) {
    const Char* digits = nullptr;
    if (!cerfcore::ReadCliOption(arg, kWaitForPidArg, digits)) return false;
    pid.reset();
    if (*digits == Char('\0')) return true;
    uint64_t value = 0;
    for (const Char* c = digits; *c != Char('\0'); ++c) {
        if (*c < Char('0') || *c > Char('9')) return true;
        value = value * 10 + uint64_t(*c - Char('0'));
        if (value > UINT32_MAX) return true;
    }
    pid = uint32_t(value);
    return true;
}

}

std::string WaitForPidArgument(uint32_t pid) { return kWaitForPidArg + std::to_string(pid); }

bool ParseWaitForPidArg(const char* arg, std::optional<uint32_t>& pid) { return Parse(arg, pid); }

bool ParseWaitForPidArg(const wchar_t* arg, std::optional<uint32_t>& pid) { return Parse(arg, pid); }
