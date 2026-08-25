#pragma once

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

void CerfStartShellWatch(void);
void CerfShellWatchRegister(void (*cb)(void));

#ifdef __cplusplus
}
#endif
