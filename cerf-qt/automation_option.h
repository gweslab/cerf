#pragma once

#include <cstddef>
#include <string>

namespace cerffrontend {

inline constexpr char   kArgAutomation[]          = "--automation";
inline constexpr char   kArgAutomationName[]      = "--automation=";
inline constexpr size_t kMaxAutomationNameLength = 64;

enum class AutomationArgument { kOther, kUnnamed, kNamed, kInvalid };

AutomationArgument ReadAutomationArgument(const char* argument, std::string& name);
bool               AutomationRequested(int argc, char** argv);

}
