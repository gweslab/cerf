#include "log.h"
#include <windows.h>
#include <dbghelp.h>
#include <tlhelp32.h>
#include <atomic>
#include <cstdio>
#include <cstdint>

/* ==== DbgHelp serialization ============================================== */

/* dbghelp is single-threaded per MSDN; every Sym* call in CERF takes
   this mutex. Initialised lazily via SymInitialize on first use; never
   cleaned up (process exit releases). Per-call Init/Cleanup cycles are
   themselves not safe to interleave with other Sym* users. */
static std::mutex g_dbghelp_mutex;
static bool       g_dbghelp_inited = false;  /* guarded by g_dbghelp_mutex */

static void EnsureDbgHelpInited_Locked() {
    if (g_dbghelp_inited) return;
    SymInitialize(GetCurrentProcess(), NULL, TRUE);
    g_dbghelp_inited = true;
}

/* ==== Emergency logging — ucrt-free crash path =========================== */

static std::atomic<bool> g_emergency_started{false};
static HANDLE            g_emergency_file   = INVALID_HANDLE_VALUE;

static void EmergencyWriteRaw(const char* buf, unsigned len) {
    if (!buf || len == 0) return;
    DWORD w = 0;
    if (g_emergency_file != INVALID_HANDLE_VALUE)
        WriteFile(g_emergency_file, buf, len, &w, NULL);
    HANDLE herr = GetStdHandle(STD_ERROR_HANDLE);
    if (herr && herr != INVALID_HANDLE_VALUE)
        WriteFile(herr, buf, len, &w, NULL);
}

/* Suspends every thread in the current process except the caller.
   The process is going to exit anyway, so no matching Resume. Any
   lock held by a now-frozen thread stays held — Emergency* code must
   never wait on such a lock (uses try_lock / ucrt-free primitives). */
static void FreezeAllOtherThreads() {
    DWORD my_tid = GetCurrentThreadId();
    DWORD my_pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != my_pid) continue;
            if (te.th32ThreadID == my_tid)       continue;
            HANDLE th = OpenThread(THREAD_SUSPEND_RESUME, FALSE, te.th32ThreadID);
            if (th) {
                SuspendThread(th);
                CloseHandle(th);
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
}

void Log::EmergencyDumpAllThreadStacks() {
    static std::atomic<bool> dumped{false};
    bool expected = false;
    if (!dumped.compare_exchange_strong(expected, true)) return;
    DWORD my_tid = GetCurrentThreadId();
    DWORD my_pid = GetCurrentProcessId();
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return;
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    Log::Emergency("\n=== All other threads' state at crash (frozen) ===\n");
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID != my_pid) continue;
            if (te.th32ThreadID == my_tid)       continue;
            HANDLE th = OpenThread(THREAD_GET_CONTEXT | THREAD_QUERY_INFORMATION,
                                   FALSE, te.th32ThreadID);
            if (!th) continue;
            CONTEXT ctx{};
            ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
            if (GetThreadContext(th, &ctx)) {
                Log::Emergency("--- tid=%lu  EIP=0x%p  ESP=0x%p  EBP=0x%p\n",
                               (unsigned long)te.th32ThreadID,
                               (void*)ctx.Eip, (void*)ctx.Esp, (void*)ctx.Ebp);
                /* Top 16 stack dwords — return-address scan. Any dword
                   whose value falls into cerf.exe's .text or a DLL is
                   likely a caller frame. Guard with IsBadReadPtr so a
                   corrupt ESP doesn't nest-fault us. */
                if (ctx.Esp && !IsBadReadPtr((const void*)ctx.Esp, 16 * 4)) {
                    unsigned __int32* sp = (unsigned __int32*)ctx.Esp;
                    for (int i = 0; i < 16; i++) {
                        Log::Emergency("     [sp+%02X] 0x%08X\n",
                                       i * 4, sp[i]);
                    }
                }
            }
            CloseHandle(th);
        } while (Thread32Next(snap, &te));
    }
    Log::Emergency("=== end frozen thread dump ===\n\n");
    CloseHandle(snap);
}

void Log::EmergencyStart() {
    bool expected = false;
    if (!g_emergency_started.compare_exchange_strong(expected, true))
        return;  /* already in emergency — concurrent handler on another thread */
    FreezeAllOtherThreads();
    g_emergency_file = CreateFileA("cerf.crash.log", GENERIC_WRITE,
                                   FILE_SHARE_READ | FILE_SHARE_WRITE, NULL,
                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    SYSTEMTIME st;
    GetLocalTime(&st);
    char hdr[256];
    int n = wsprintfA(hdr,
        "=== CERF CRASH %04u-%02u-%02u %02u:%02u:%02u.%03u (tid=%lu pid=%lu) ===\n",
        st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond,
        st.wMilliseconds,
        (unsigned long)GetCurrentThreadId(),
        (unsigned long)GetCurrentProcessId());
    if (n > 0) EmergencyWriteRaw(hdr, (unsigned)n);
    /* Record cerf.exe's runtime base so "sym-locked" stack frames can be
       resolved offline: RVA = runtime_addr - cerf_base, look up in dumpbin
       or the build's cerf.exe.map. ASLR re-bases per run so this is the
       only way to recover symbols when dbghelp is unavailable. */
    HMODULE self = GetModuleHandleA(NULL);
    n = wsprintfA(hdr, "=== cerf.exe runtime base=0x%p (RVA = addr - base) ===\n",
                  (void*)self);
    if (n > 0) EmergencyWriteRaw(hdr, (unsigned)n);
}

void Log::Emergency(const char* fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    int n = wvsprintfA(buf, fmt, ap);
    va_end(ap);
    if (n <= 0) return;
    if (n > (int)sizeof(buf)) n = sizeof(buf);
    EmergencyWriteRaw(buf, (unsigned)n);
}

void Log::EmergencyPrintNativeStack(const char* tag) {
    void* frames[32];
    USHORT n = CaptureStackBackTrace(0, 32, frames, NULL);
    /* try_lock — if another (now-frozen) thread held dbghelp, we can't
       safely use it; print raw addresses instead. */
    std::unique_lock<std::mutex> lk(g_dbghelp_mutex, std::try_to_lock);
    bool have_sym = lk.owns_lock();
    if (have_sym) EnsureDbgHelpInited_Locked();
    char line[512];
    char sym_buf[sizeof(SYMBOL_INFO) + 256];
    SYMBOL_INFO* sym = (SYMBOL_INFO*)sym_buf;
    sym->SizeOfStruct = sizeof(SYMBOL_INFO);
    sym->MaxNameLen = 255;
    for (USHORT i = 0; i < n; i++) {
        int ln = 0;
        if (have_sym) {
            DWORD64 disp = 0;
            if (SymFromAddr(GetCurrentProcess(), (DWORD64)frames[i], &disp, sym)) {
                ln = wsprintfA(line, "%s   [%u] %s+0x%X\n",
                               tag, i, sym->Name, (uint32_t)disp);
            } else {
                ln = wsprintfA(line, "%s   [%u] 0x%p\n", tag, i, frames[i]);
            }
        } else {
            ln = wsprintfA(line, "%s   [%u] 0x%p (sym-locked)\n",
                           tag, i, frames[i]);
        }
        if (ln > 0) EmergencyWriteRaw(line, (unsigned)ln);
    }
}

/* ==== Terminal exits ===================================================== */

void CerfFatalExit(int code) {
    if (code == CERF_FATAL_USER_ERROR) {
        /* Not a crash — skip the thread-freeze + crash.log + native-stack
           dump so a missing ROM / unsupported board doesn't read as a bug. */
        Log::Close();
        ExitProcess((UINT)code);
    }

    /* Freeze every other thread, open cerf.crash.log, stop using Log:: */
    Log::EmergencyStart();
    Log::EmergencyDumpAllThreadStacks();
    Log::Emergency("[FATAL] CerfFatalExit(%d) tid=%lu stack trace:\n",
                   code, (unsigned long)GetCurrentThreadId());
    Log::EmergencyPrintNativeStack("[FATAL]");
    Log::Close();  /* flush-only, doesn't close g_logfile */

#if !CERF_DEV_MODE
    if (code == CERF_FATAL_RUNTIME_ERROR) {
        MessageBoxA(nullptr,
                    "Something inside CERF blew up and it has to close.\n\n"
                    "Two log files were written next to cerf.exe:\n"
                    "  - cerf.log         (full run log)\n"
                    "  - cerf.crash.log   (thread snapshot at the crash)\n\n"
                    "If you can share those, the developers can take a look "
                    "and figure out what broke.",
                    "CERF: unexpected error",
                    MB_OK | MB_ICONERROR | MB_TASKMODAL | MB_TOPMOST);
    }
#endif

    ExitProcess((UINT)code);
}

