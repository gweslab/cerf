#include <windows.h>

static const wchar_t kTarget[] = L"launcher\\launcher.exe";
static const wchar_t kTitle[] = L"CE Runtime Foundation";

static const wchar_t *SkipProgramName(const wchar_t *cmd)
{
    if (*cmd == L'"') {
        ++cmd;
        while (*cmd && *cmd != L'"')
            ++cmd;
        if (*cmd)
            ++cmd;
        return cmd;
    }
    while (*cmd && *cmd != L' ' && *cmd != L'\t')
        ++cmd;
    return cmd;
}

static void Fail(const wchar_t *text)
{
    MessageBoxW(NULL, text, kTitle, MB_OK | MB_ICONERROR);
    ExitProcess(1);
}

void __stdcall StubEntry(void)
{
    wchar_t exe[MAX_PATH];
    DWORD len = GetModuleFileNameW(NULL, exe, MAX_PATH);
    DWORD cut = 0;
    DWORD i;
    const wchar_t *tail;
    int tail_len;
    int size;
    wchar_t *cmd;
    STARTUPINFOW si;
    PROCESS_INFORMATION pi;

    if (len == 0 || len >= MAX_PATH)
        Fail(L"The launcher could not find its own location.");
    for (i = 0; i < len; ++i) {
        if (exe[i] == L'\\' || exe[i] == L'/')
            cut = i + 1;
    }
    if (cut + lstrlenW(kTarget) >= MAX_PATH)
        Fail(L"The installation path is too long.");
    lstrcpynW(exe + cut, kTarget, MAX_PATH - cut);

    tail = SkipProgramName(GetCommandLineW());
    tail_len = lstrlenW(tail);
    size = lstrlenW(exe) + tail_len + 3;
    cmd = (wchar_t *)HeapAlloc(GetProcessHeap(), 0, size * sizeof(wchar_t));
    if (cmd == NULL)
        Fail(L"Out of memory.");
    cmd[0] = L'"';
    lstrcpynW(cmd + 1, exe, size - 1);
    lstrcpynW(cmd + 1 + lstrlenW(exe), L"\"", 2);
    lstrcpynW(cmd + 2 + lstrlenW(exe), tail, tail_len + 1);

    SecureZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    SecureZeroMemory(&pi, sizeof(pi));
    if (!CreateProcessW(exe, cmd, NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi))
        Fail(L"launcher\\launcher.exe could not be started. Re-download CERF "
             L"from https://cerf.cx/download");

    AllowSetForegroundWindow(pi.dwProcessId);
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    ExitProcess(0);
}
