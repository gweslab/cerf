#pragma once

#include <windows.h>

extern ULONG g_FbWidth;
extern ULONG g_FbHeight;
extern ULONG g_FbBpp;
extern ULONG g_FbStride;
extern ULONG g_FbDpi;
extern ULONG g_FbRefreshRate;
extern LONG  g_FbSystemFontHeight;
extern ULONG g_FbSystemFontPresent;
extern ULONG g_FbMemTotal;
extern ULONG g_FbPrimaryReserve;
extern ULONG g_EngineVersion;
extern ULONG g_OsMajor;

void  CerfReadFbRegs(void);
void* CerfMapFbMemory(void);

extern "C" const wchar_t* CerfInjectedModuleName(void);
extern "C" ULONG CerfGpeBlt(ULONG desc_va);
extern "C" ULONG CerfGpeGrad(ULONG desc_va);
extern "C" ULONG CerfGpeLine(ULONG desc_va);
extern "C" ULONG CerfGpeFbMemBasePa(void);
extern "C" void  CerfPublishPalette(const ULONG* rgb, unsigned first, unsigned count);
extern "C" void* CerfMapFbGlobal(void);
