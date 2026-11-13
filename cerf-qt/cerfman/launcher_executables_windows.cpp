#include "launcher_executables.h"

#include "../executable_names_text.h"

std::vector<const char*> LauncherExecutables() {
    return {CERF_LAUNCHER_NAME ".exe", CERF_LAUNCHER_NAME "/" CERF_LAUNCHER_NAME ".exe"};
}
