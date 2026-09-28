#include "log.h"
#include "crash_report.h"
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

/* ==== Emergency logging - ucrt-free crash path =========================== */

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
   lock held by a now-frozen thread stays held - Emergency* code must
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
                /* Top 16 stack dwords - return-address scan. Any dword
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

bool Log::IsEmergencyActive() {
    return g_emergency_started.load(std::memory_order_acquire);
}

void Log::EmergencyStart() {
    bool expected = false;
    if (!g_emergency_started.compare_exchange_strong(expected, true))
        return;  /* already in emergency - concurrent handler on another thread */
    FreezeAllOtherThreads();
    wchar_t crash_path[MAX_PATH];
    const DWORD mod_len = GetModuleFileNameW(NULL, crash_path, MAX_PATH);
    int cut = 0;
    if (mod_len > 0 && mod_len < MAX_PATH) {
        for (int i = 0; i < (int)mod_len; ++i) {
            if (crash_path[i] == L'\\' || crash_path[i] == L'/') cut = i + 1;
        }
    }
    lstrcpynW(crash_path + cut, L"cerf.crash.log", MAX_PATH - cut);
    g_emergency_file = CreateFileW(crash_path, GENERIC_WRITE,
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

void Log::EmergencyWriteBytes(const char* buf, size_t len) {
    EmergencyWriteRaw(buf, (unsigned)len);
}

void Log::EmergencyPrintNativeStack(const char* tag) {
    void* frames[32];
    USHORT n = CaptureStackBackTrace(0, 32, frames, NULL);
    /* try_lock - if another (now-frozen) thread held dbghelp, we can't
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

/* ==== Top-level unhandled-exception filter =============================== */

bool Log::SymbolizeAddress(const void* addr, char* out, size_t out_size) {
    if (!out || out_size == 0) return false;
    out[0] = '\0';

    std::unique_lock<std::mutex> lk(g_dbghelp_mutex, std::try_to_lock);
    if (!lk.owns_lock()) return false;
    EnsureDbgHelpInited_Locked();

    char         sym_buf[sizeof(SYMBOL_INFO) + 256];
    SYMBOL_INFO* sym  = (SYMBOL_INFO*)sym_buf;
    sym->SizeOfStruct = sizeof(SYMBOL_INFO);
    sym->MaxNameLen   = 255;
    DWORD64 disp      = 0;
    if (!SymFromAddr(GetCurrentProcess(), (DWORD64)addr, &disp, sym)) {
        return false;
    }

    char line[512];
    if (wsprintfA(line, "%s+0x%X", sym->Name, (uint32_t)disp) <= 0) return false;
    size_t n = 0;
    while (line[n] != '\0' && n + 1 < out_size) { out[n] = line[n]; ++n; }
    out[n] = '\0';
    return true;
}

/* Symbolize one address under the dbghelp mutex (try_lock - a frozen thread
   may hold it). Mirrors EmergencyPrintNativeStack's locking. */
static void EmergencySymbolizeAddr(const char* tag, void* addr) {
    char sym[512];
    if (Log::SymbolizeAddress(addr, sym, sizeof(sym))) {
        Log::Emergency("%s fault at %s (0x%p)\n", tag, sym, addr);
        return;
    }
    Log::Emergency("%s fault at 0x%p (sym-locked)\n", tag, addr);
}

/* Walk the FAULTING thread's stack from its trap context. The UEF runs on
   the faulting thread, but KiUserExceptionDispatcher breaks the EBP chain, so
   CaptureStackBackTrace from here only sees the handler frames - StackWalk64
   seeded from ContextRecord recovers the frames that actually faulted. */
static void EmergencyWalkFaultingStack(const char* tag, CONTEXT* ctx_in) {
    if (!ctx_in) return;
    std::unique_lock<std::mutex> lk(g_dbghelp_mutex, std::try_to_lock);
    if (!lk.owns_lock()) {  /* a frozen thread holds dbghelp; can't walk safely */
        Log::Emergency("%s faulting-stack walk skipped (dbghelp locked)\n", tag);
        return;
    }
    EnsureDbgHelpInited_Locked();

    CONTEXT ctx = *ctx_in;  /* StackWalk64 mutates the context it walks */
    STACKFRAME64 sf{};
    sf.AddrPC.Offset    = ctx.Eip; sf.AddrPC.Mode    = AddrModeFlat;
    sf.AddrFrame.Offset = ctx.Ebp; sf.AddrFrame.Mode = AddrModeFlat;
    sf.AddrStack.Offset = ctx.Esp; sf.AddrStack.Mode = AddrModeFlat;

    HANDLE proc = GetCurrentProcess();
    HANDLE thr  = GetCurrentThread();
    char line[512];
    char sym_buf[sizeof(SYMBOL_INFO) + 256];
    SYMBOL_INFO* sym = (SYMBOL_INFO*)sym_buf;
    for (int i = 0; i < 40; ++i) {
        if (!StackWalk64(IMAGE_FILE_MACHINE_I386, proc, thr, &sf, &ctx, NULL,
                         SymFunctionTableAccess64, SymGetModuleBase64, NULL))
            break;
        if (sf.AddrPC.Offset == 0) break;
        sym->SizeOfStruct = sizeof(SYMBOL_INFO);
        sym->MaxNameLen   = 255;
        DWORD64 disp = 0;
        if (SymFromAddr(proc, sf.AddrPC.Offset, &disp, sym))
            wsprintfA(line, "%s   [%d] %s+0x%X\n", tag, i, sym->Name, (uint32_t)disp);
        else
            wsprintfA(line, "%s   [%d] 0x%p\n", tag, i,
                      (void*)(uintptr_t)sf.AddrPC.Offset);
        Log::Emergency("%s", line);
    }
}

static LONG WINAPI CerfTopLevelExceptionFilter(EXCEPTION_POINTERS* ep) {
    LOG(Cerf, "this run ends here; the crash tail is in cerf.crash.log\n");
    Log::Close();
    Log::EmergencyStart();
    char recent_cautions[4096];
    Log::CopyRecentCautionsPostFreeze(recent_cautions,
                                      sizeof(recent_cautions));
    if (recent_cautions[0]) {
        Log::Emergency("[UNHANDLED] recent cautions:\n");
        EmergencyWriteRaw(recent_cautions,
                          (unsigned)lstrlenA(recent_cautions));
    }
    if (ep && ep->ExceptionRecord) {
        EXCEPTION_RECORD* er = ep->ExceptionRecord;
        Log::Emergency("[UNHANDLED] code=0x%08X flags=0x%X at 0x%p\n",
                       (unsigned)er->ExceptionCode, (unsigned)er->ExceptionFlags,
                       er->ExceptionAddress);
        if (er->ExceptionCode == EXCEPTION_ACCESS_VIOLATION &&
            er->NumberParameters >= 2) {
            Log::Emergency("[UNHANDLED] access violation: %s 0x%p\n",
                           er->ExceptionInformation[0] ? "write to" : "read from",
                           (void*)er->ExceptionInformation[1]);
        }
        EmergencySymbolizeAddr("[UNHANDLED]", er->ExceptionAddress);
    }
    if (ep && ep->ContextRecord) {
        CONTEXT* c = ep->ContextRecord;
        Log::Emergency("[UNHANDLED] EIP=0x%p ESP=0x%p EBP=0x%p tid=%lu\n",
                       (void*)c->Eip, (void*)c->Esp, (void*)c->Ebp,
                       (unsigned long)GetCurrentThreadId());
    }
    Log::EmergencyDumpAllThreadStacks();
    EmergencyWalkFaultingStack("[UNHANDLED]", ep ? ep->ContextRecord : nullptr);
    Log::Close();
    ExitProcess((UINT)CERF_FATAL_RUNTIME_ERROR);  /* [[noreturn]] */
}

void Log::InstallCrashHandler() {
    SetUnhandledExceptionFilter(CerfTopLevelExceptionFilter);
}

/* ==== Terminal exits ===================================================== */

void CerfFatalExit(int code) {
    char recent_cautions[4096];
    recent_cautions[0] = '\0';

    if (code == CERF_FATAL_NORMAL_EXIT || code == CERF_FATAL_TIMEOUT)
        LOG(Cerf, "CERF is exiting (code = %d)\n", code);
    else
        LOG(Caution, "CERF is halting (fatal code = %d)\n", code);

    if (code == CERF_FATAL_USER_ERROR || code == CERF_FATAL_NORMAL_EXIT ||
        code == CERF_FATAL_TIMEOUT) {
        /* Not a crash - skip the thread-freeze + crash.log + native-stack
           dump so a missing ROM / unsupported board doesn't read as a bug. */
        Log::Close();
        ExitProcess((UINT)code);
    }

    LOG(Cerf, "this run ends here; the crash tail is in cerf.crash.log\n");
    Log::Close();

    Log::EmergencyStart();
    Log::CopyRecentCautionsPostFreeze(recent_cautions,
                                      sizeof(recent_cautions));
    if (recent_cautions[0]) {
        Log::Emergency("[FATAL] recent cautions:\n");
        EmergencyWriteRaw(recent_cautions,
                          (unsigned)lstrlenA(recent_cautions));
    }
    Log::EmergencyDumpAllThreadStacks();
    Log::Emergency("[FATAL] CerfFatalExit(%d) tid=%lu stack trace:\n",
                   code, (unsigned long)GetCurrentThreadId());
    Log::EmergencyPrintNativeStack("[FATAL]");
    Log::Close();

#if !CERF_DEV_MODE
    if (code == CERF_FATAL_RUNTIME_ERROR) CrashReport::Present();
#endif

    ExitProcess((UINT)code);
}

