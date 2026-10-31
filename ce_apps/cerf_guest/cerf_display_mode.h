#pragma once

#include <windows.h>

volatile ULONG* CerfDisplayModeChannel(void);
ULONG           CerfDisplayModeRotationCaps(void);
ULONG           CerfDisplayModeAngle(void);
LONG            CerfDisplayModeRotate(ULONG dmdo);
void            CerfDisplayModeRequestNative(ULONG w, ULONG h);
BOOL            CerfDisplayModeNativePending(void);
void            CerfDisplayModeCancelRequest(void);
void            CerfDisplayModeBeginPumpTurn(ULONG from, BOOL keep_published);
BOOL            CerfDisplayModeEndPumpTurn(void);
