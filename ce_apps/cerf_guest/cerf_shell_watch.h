#pragma once

#include <windows.h>

#ifdef __cplusplus
extern "C" {
#endif

void CerfShellWatchTick(void);
void CerfShellWatchRegister(void (*cb)(void));
BOOL CerfShellWatchIsUp(void);

#ifdef __cplusplus
}
#endif
