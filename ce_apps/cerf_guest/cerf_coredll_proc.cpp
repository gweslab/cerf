#include "cerf_coredll_proc.h"

extern "C" FARPROC CerfCoredllProc(const wchar_t* name) {
    HMODULE core = LoadLibraryW(L"coredll.dll");
    FARPROC proc = GetProcAddressW(core, name);
    FreeLibrary(core);
    return proc;
}
