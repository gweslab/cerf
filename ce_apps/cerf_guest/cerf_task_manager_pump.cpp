#include <windows.h>
#include <tlhelp32.h>

#include "cerf_regs_map.h"
#include "cerf_gwes_ready.h"
#include "cerf_toolhelp.h"
#include "cerf_task_manager_pump.h"

#include "cerf/peripherals/cerf_virt/cerf_virt_addr_map.h"

#define CERF_TM_CMD_GEN       0x00u
#define CERF_TM_CMD_CODE      0x04u
#define CERF_TM_CMD_PID       0x08u
#define CERF_TM_CMD_RUNLEN    0x0Cu
#define CERF_TM_CMD_RUNTEXT   0x100u

#define CERF_TM_RESP_CMDGEN   0x40u
#define CERF_TM_RESP_STATUS   0x44u
#define CERF_TM_RESP_ERR      0x48u
#define CERF_TM_RESP_COUNT    0x50u
#define CERF_TM_RESP_TOTAL    0x54u
#define CERF_TM_REC_INDEX     0x60u
#define CERF_TM_REC_KICK      0x64u
#define CERF_TM_RESP_KICK     0x80u
#define CERF_TM_REC_DATA      0x200u

#define CERF_TM_OP_LIST         1u
#define CERF_TM_OP_KILL         2u
#define CERF_TM_OP_SWITCHTO     3u
#define CERF_TM_OP_RUN          4u
#define CERF_TM_OP_LISTWINDOWS  5u
#define CERF_TM_OP_SWITCHTOWIN  6u

#define CERF_TM_RUN_MAX         256u
#define CERF_TM_MAX_RECORDS     256u
#define CERF_TM_NAME_WCHARS     64u
#define CERF_TM_WIN_TITLE_WCHARS 64u
#define CERF_TM_WINFLAG_VISIBLE 0x1u

typedef struct CerfTmProcRecord {
    DWORD pid;
    DWORD parent_pid;
    DWORD thread_count;
    LONG  base_priority;
    DWORD mem_base;
    WCHAR name[CERF_TM_NAME_WCHARS];
} CerfTmProcRecord;
typedef char cerf_tm_record_size_check[(sizeof(CerfTmProcRecord) == 148) ? 1 : -1];

typedef struct CerfTmWindowRecord {
    DWORD hwnd;
    DWORD pid;
    DWORD thread_id;
    DWORD flags;
    WCHAR title[CERF_TM_WIN_TITLE_WCHARS];
} CerfTmWindowRecord;
typedef char cerf_tm_winrec_size_check[(sizeof(CerfTmWindowRecord) == 144) ? 1 : -1];

static volatile ULONG* s_tm_regs = NULL;

static void CerfTmRespond(DWORD gen, DWORD status, DWORD err,
                          DWORD count, DWORD total) {
    s_tm_regs[CERF_TM_RESP_CMDGEN / 4] = gen;
    s_tm_regs[CERF_TM_RESP_STATUS / 4] = status;
    s_tm_regs[CERF_TM_RESP_ERR / 4]    = err;
    s_tm_regs[CERF_TM_RESP_COUNT / 4]  = count;
    s_tm_regs[CERF_TM_RESP_TOTAL / 4]  = total;
    s_tm_regs[CERF_TM_RESP_KICK / 4]   = 1;
}

static void CerfTmSendRecord(const ULONG* words, DWORD count, DWORD index) {
    DWORD i;
    for (i = 0; i < count; ++i)
        s_tm_regs[(CERF_TM_REC_DATA + i * 4) / 4] = words[i];
    s_tm_regs[CERF_TM_REC_INDEX / 4] = index;
    s_tm_regs[CERF_TM_REC_KICK / 4]  = 1;
}

static void CerfTmDoList(DWORD gen) {
    PROCESSENTRY32 pe;
    CerfTmProcRecord rec;
    HANDLE snap;
    DWORD count = 0, total = 0;
    BOOL ok;

    if (!CerfToolhelpReady()) {
        CerfTmRespond(gen, 0, ERROR_NOT_SUPPORTED, 0, 0);
        return;
    }
    snap = CerfToolhelpSnapshotProcesses();
    if (snap == INVALID_HANDLE_VALUE) {
        CerfTmRespond(gen, 0, GetLastError(), 0, 0);
        return;
    }

    pe.dwSize = sizeof(pe);
    ok = CerfToolhelpProcessFirst(snap, &pe);
    while (ok) {
        total++;
        if (count < CERF_TM_MAX_RECORDS) {
            DWORD i;
            rec.pid           = pe.th32ProcessID;
            rec.parent_pid    = pe.th32ParentProcessID;
            rec.thread_count  = pe.cntThreads;
            rec.base_priority = pe.pcPriClassBase;
            rec.mem_base      = pe.th32MemoryBase;
            for (i = 0; i < CERF_TM_NAME_WCHARS - 1 && pe.szExeFile[i]; ++i)
                rec.name[i] = pe.szExeFile[i];
            for (; i < CERF_TM_NAME_WCHARS; ++i)
                rec.name[i] = 0;
            CerfTmSendRecord((const ULONG*)&rec, sizeof(rec) / 4, count);
            count++;
        }
        pe.dwSize = sizeof(pe);
        ok = CerfToolhelpProcessNext(snap, &pe);
    }
    CerfToolhelpCloseSnapshot(snap);
    CerfTmRespond(gen, 1, 0, count, total);
}

static void CerfTmDoKill(DWORD gen, DWORD pid) {
    HANDLE h = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    BOOL ok;
    DWORD err;
    if (!h) {
        CerfTmRespond(gen, 0, GetLastError(), 0, 0);
        return;
    }
    ok  = TerminateProcess(h, 0);
    err = ok ? 0 : GetLastError();
    CloseHandle(h);
    CerfTmRespond(gen, ok ? 1u : 0u, err, 0, 0);
}

static void CerfTmDoSwitchTo(DWORD gen, DWORD pid) {
    HWND visible = NULL, any = NULL, target;
    DWORD seen = 0;
    HWND w = GetForegroundWindow();
    CERF_LOG_X("cerf_guest: tmpump switch target pid", pid);
    CERF_LOG_X("cerf_guest: tmpump switch fg hwnd", (DWORD)w);
    if (w) w = GetWindow(w, GW_HWNDFIRST);
    for (; w; w = GetWindow(w, GW_HWNDNEXT)) {
        DWORD wpid = 0;
        GetWindowThreadProcessId(w, &wpid);
        seen++;
        if (wpid != pid) continue;
        if (!any) any = w;
        if (IsWindowVisible(w)) {
            visible = w;
            break;
        }
    }
    CERF_LOG_X("cerf_guest: tmpump switch walk seen", seen);
    target = visible ? visible : any;
    if (!target) {
        CerfTmRespond(gen, 0, ERROR_NOT_FOUND, 0, 0);
        return;
    }
    SetForegroundWindow(target);
    CerfTmRespond(gen, 1, 0, 0, 0);
}

#define CERF_TM_EVENT_RESET  2u
#define CERF_TM_EVENT_SET    3u
#define CERF_TM_TITLE_TIMEOUT_MS 250u

static HANDLE        s_wt_req  = NULL;
static HANDLE        s_wt_done = NULL;
static volatile HWND s_wt_hwnd = NULL;
static WCHAR         s_wt_text[CERF_TM_WIN_TITLE_WCHARS];
static volatile LONG s_wt_busy = 0;

static DWORD WINAPI CerfTmTitleWorker(LPVOID) {
    for (;;) {
        HWND  h;
        WCHAR local[CERF_TM_WIN_TITLE_WCHARS];
        DWORD i;
        WaitForSingleObject(s_wt_req, INFINITE);
        h = s_wt_hwnd;
        for (i = 0; i < CERF_TM_WIN_TITLE_WCHARS; ++i) local[i] = 0;
        GetWindowTextW(h, local, CERF_TM_WIN_TITLE_WCHARS);
        for (i = 0; i < CERF_TM_WIN_TITLE_WCHARS; ++i) s_wt_text[i] = local[i];
        EventModify(s_wt_done, CERF_TM_EVENT_SET);
    }
}

static void CerfTmStartTitleWorker(void) {
    HANDLE t;
    s_wt_req  = CreateEventW(NULL, FALSE, FALSE, NULL);
    s_wt_done = CreateEventW(NULL, TRUE,  FALSE, NULL);
    if (!s_wt_req || !s_wt_done) { s_wt_req = NULL; s_wt_done = NULL; return; }
    t = CreateThread(NULL, 0, CerfTmTitleWorker, NULL, 0, NULL);
    if (t) CloseHandle(t);
}

static void CerfTmFetchTitle(HWND h, WCHAR* out, DWORD cch) {
    DWORD i;
    if (cch) out[0] = 0;
    if (!s_wt_req || !s_wt_done) return;
    if (s_wt_busy) {
        if (WaitForSingleObject(s_wt_done, 0) != WAIT_OBJECT_0) return;
        s_wt_busy = 0;
    }
    s_wt_hwnd = h;
    s_wt_busy = 1;
    EventModify(s_wt_done, CERF_TM_EVENT_RESET);
    EventModify(s_wt_req,  CERF_TM_EVENT_SET);
    if (WaitForSingleObject(s_wt_done, CERF_TM_TITLE_TIMEOUT_MS) == WAIT_OBJECT_0) {
        for (i = 0; i + 1 < cch && i < CERF_TM_WIN_TITLE_WCHARS; ++i) out[i] = s_wt_text[i];
        out[i] = 0;
        s_wt_busy = 0;
    }
}

static void CerfTmDoListWindows(DWORD gen) {
    CerfTmWindowRecord rec;
    HWND  w = GetForegroundWindow();
    DWORD count = 0, total = 0;
    if (w) w = GetWindow(w, GW_HWNDFIRST);
    for (; w; w = GetWindow(w, GW_HWNDNEXT)) {
        DWORD pid = 0, tid, i;
        total++;
        if (count >= CERF_TM_MAX_RECORDS) continue;
        tid           = GetWindowThreadProcessId(w, &pid);
        rec.hwnd      = (DWORD)w;
        rec.pid       = pid;
        rec.thread_id = tid;
        rec.flags     = IsWindowVisible(w) ? CERF_TM_WINFLAG_VISIBLE : 0;
        for (i = 0; i < CERF_TM_WIN_TITLE_WCHARS; ++i) rec.title[i] = 0;
        CerfTmFetchTitle(w, rec.title, CERF_TM_WIN_TITLE_WCHARS);
        CerfTmSendRecord((const ULONG*)&rec, sizeof(rec) / 4, count);
        count++;
    }
    CerfTmRespond(gen, 1, 0, count, total);
}

static void CerfTmDoSwitchToWin(DWORD gen, DWORD hwnd) {
    HWND w = (HWND)hwnd;
    if (!w || !IsWindow(w)) {
        CerfTmRespond(gen, 0, ERROR_NOT_FOUND, 0, 0);
        return;
    }
    SetForegroundWindow(w);
    CerfTmRespond(gen, 1, 0, 0, 0);
}

static BOOL CerfTmSpawn(const WCHAR* image, const WCHAR* args, DWORD* err) {
    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));
    if (!CreateProcessW(image, args, NULL, NULL, FALSE, 0, NULL, NULL, NULL,
                        &pi)) {
        *err = GetLastError();
        return FALSE;
    }
    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    return TRUE;
}

static void CerfTmDoRun(DWORD gen) {
    WCHAR cmd[CERF_TM_RUN_MAX + 1];
    WCHAR* image;
    WCHAR* args = NULL;
    WCHAR* p;
    BOOL ok;
    DWORD err = 0;
    DWORD len = s_tm_regs[CERF_TM_CMD_RUNLEN / 4];
    DWORD i;

    if (len == 0 || len > CERF_TM_RUN_MAX) {
        CerfTmRespond(gen, 0, ERROR_INVALID_PARAMETER, 0, 0);
        return;
    }
    for (i = 0; i < (len + 1) / 2; ++i) {
        ULONG v = s_tm_regs[(CERF_TM_CMD_RUNTEXT + i * 4) / 4];
        cmd[i * 2] = (WCHAR)(v & 0xFFFFu);
        if (i * 2 + 1 < len) cmd[i * 2 + 1] = (WCHAR)(v >> 16);
    }
    cmd[len] = 0;

    image = cmd;
    if (cmd[0] == L'"') {
        image = cmd + 1;
        for (p = image; *p && *p != L'"'; ++p) {}
        if (*p) {
            *p++ = 0;
            while (*p == L' ') ++p;
            if (*p) args = p;
        }
        ok = CerfTmSpawn(image, args, &err);
    } else {
        ok = CerfTmSpawn(image, NULL, &err);
        if (!ok) {
            for (p = image; *p; ++p) {
                if (*p == L' ') {
                    *p   = 0;
                    args = p + 1;
                    break;
                }
            }
            if (args) ok = CerfTmSpawn(image, args, &err);
        }
    }
    CERF_LOG_X("cerf_guest: tmpump run result", ok ? 1u : err);
    CerfTmRespond(gen, ok ? 1u : 0u, err, 0, 0);
}

static BOOL CerfTmRequireGwes(DWORD gen) {
    if (CerfGwesApiSetReady()) return TRUE;
    CERF_LOG("cerf_guest: tmpump window op rejected - gwes api set not registered yet");
    CerfTmRespond(gen, 0, ERROR_NOT_READY, 0, 0);
    return FALSE;
}

static BOOL  s_tm_dead     = FALSE;
static BOOL  s_tm_ready    = FALSE;
static ULONG s_tm_last_gen = 0;

static volatile LONG s_tm_busy     = 0;
static ULONG         s_tm_job_gen  = 0;
static ULONG         s_tm_job_code = 0;
static ULONG         s_tm_job_pid  = 0;

static void CerfTmExecute(ULONG gen, ULONG code, ULONG pid) {
    switch (code) {
        case CERF_TM_OP_LIST:        CerfTmDoList(gen);            break;
        case CERF_TM_OP_KILL:        CerfTmDoKill(gen, pid);       break;
        case CERF_TM_OP_SWITCHTO:
            if (CerfTmRequireGwes(gen)) CerfTmDoSwitchTo(gen, pid);
            break;
        case CERF_TM_OP_RUN:         CerfTmDoRun(gen);             break;
        case CERF_TM_OP_LISTWINDOWS:
            if (CerfTmRequireGwes(gen)) CerfTmDoListWindows(gen);
            break;
        case CERF_TM_OP_SWITCHTOWIN:
            if (CerfTmRequireGwes(gen)) CerfTmDoSwitchToWin(gen, pid);
            break;
        default:
            CERF_LOG_X("cerf_guest: tmpump unknown cmd", code);
            CerfTmRespond(gen, 0, ERROR_INVALID_PARAMETER, 0, 0);
            break;
    }
}

static DWORD WINAPI CerfTmCommandWorker(LPVOID) {
    CerfTmExecute(s_tm_job_gen, s_tm_job_code, s_tm_job_pid);
    s_tm_busy = 0;
    return 0;
}

extern "C" void CerfTaskManagerTick(void) {
    ULONG  gen;
    HANDLE t;

    if (s_tm_dead) return;

    if (!s_tm_ready) {
        s_tm_regs = (volatile ULONG*)CerfMapRegsPage(g_CerfVirtBase + CerfVirt::kTaskManagerOffset,
                                                     CerfVirt::kTaskManagerSize);
        if (!s_tm_regs) {
            CERF_LOG("cerf_guest: tmpump map FAILED");
            s_tm_dead = TRUE;
            return;
        }
        CerfTmStartTitleWorker();
        s_tm_last_gen = s_tm_regs[CERF_TM_CMD_GEN / 4];
        s_tm_ready = TRUE;
        return;
    }

    if (s_tm_busy) return;

    gen = s_tm_regs[CERF_TM_CMD_GEN / 4];
    if (gen == s_tm_last_gen) return;

    s_tm_job_gen  = gen;
    s_tm_job_code = s_tm_regs[CERF_TM_CMD_CODE / 4];
    s_tm_job_pid  = s_tm_regs[CERF_TM_CMD_PID / 4];
    s_tm_last_gen = gen;

    s_tm_busy = 1;
    t = CreateThread(NULL, 0, CerfTmCommandWorker, NULL, 0, NULL);
    if (t) {
        CloseHandle(t);
        return;
    }

    s_tm_busy = 0;
    CERF_LOG_X("cerf_guest: tmpump command thread FAILED", s_tm_job_code);
    CerfTmRespond(gen, 0, GetLastError(), 0, 0);
}
