#include "automation_option.h"

#include <cerfcore/core/cli_option.h>

#include <cstring>

namespace cerffrontend {

namespace {

bool NameCharacter(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '.' || c == '_' ||
           c == '-';
}

}

AutomationArgument ReadAutomationArgument(const char* argument, std::string& name) {
    if (std::strcmp(argument, kArgAutomation) == 0) {
        name.clear();
        return AutomationArgument::kUnnamed;
    }
    const char* value = nullptr;
    if (!cerfcore::ReadCliOption(argument, kArgAutomationName, value)) return AutomationArgument::kOther;
    name = value;
    if (name.empty() || name.size() > kMaxAutomationNameLength) return AutomationArgument::kInvalid;
    for (char c : name)
        if (!NameCharacter(c)) return AutomationArgument::kInvalid;
    return AutomationArgument::kNamed;
}

bool AutomationRequested(int argc, char** argv) {
    std::string name;
    for (int i = 1; i < argc; ++i)
        if (ReadAutomationArgument(argv[i], name) != AutomationArgument::kOther) return true;
    return false;
}

}
