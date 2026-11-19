#pragma once

#include "automation_server.h"

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace cerffrontend {

class AutomationParams {
public:
    explicit AutomationParams(const AutomationJson& params) : params_(params) {}

    int64_t                    Integer(const char* name) const;
    std::optional<int64_t>     OptionalInteger(const char* name) const;
    bool                       Boolean(const char* name) const;
    std::optional<bool>        OptionalBoolean(const char* name) const;
    std::string                String(const char* name) const;
    std::optional<std::string> OptionalString(const char* name) const;
    std::vector<std::string>   Strings(const char* name) const;
    const AutomationJson*      Find(const char* name) const;

private:
    const AutomationJson& params_;
};

}
