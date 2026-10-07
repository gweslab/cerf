#pragma once

#include <windows.h>

/* Physical-memory map (PAGE_PHYSICAL). Absent from CE 1.0 coredll.lib (added
   in CE 1.01), so it is resolved by name at runtime; dump.cpp reads via MIPS
   kseg1 when the resolve returns NULL. PAGE_PHYSICAL/PAGE_NOCACHE: <windows.h>. */
typedef BOOL (*VirtualCopyFn)(LPVOID lpvDest, LPVOID lpvSrc,
                              DWORD cbSize, DWORD fdwProtect);

#define WIN_BYTES    0x00100000u           /* 1 MB map window / address step  */
#define PAGE_BYTES   0x00001000u           /* 4 KB SEH read granularity        */
#define CHUNK_BYTES  0x00010000u

/* Worker -> UI messages. */
#define WM_APP_LOG      (WM_APP + 1)   /* lParam = LocalAlloc'd WCHAR*, UI frees */
#define WM_APP_SEGMENT  (WM_APP + 2)   /* worker asks UI to prompt for next seg  */
#define WM_APP_DONE     (WM_APP + 3)   /* worker finished                        */
#define WM_APP_STORAGE  (WM_APP + 4)   /* worker: write failed, ask Retry/Cancel */

/* Wizard steps. */
enum { STEP_PRESET = 0, STEP_CONFIG = 1, STEP_DUMP = 2, STEP_COUNT = 3 };

/* cbWndExtra slot on the main window class holding AppState*. Shared with the
   step_preset custom control, which reads it via GetParent. */
#define WNDX_STATE 0

/* Bottom nav-panel geometry, shared by the shell and the progress painter. */
#define PANEL_H     32
#define NAV_W       92
#define NAV_H       24
#define BTN_MARGIN   6

/* Control IDs. The nav button is persistent across steps (relabelled). */
#define ID_NAV        200   /* Next / Start Dump / Stop-then-Exit (bottom-right) */
#define ID_CANCEL     201   /* Cancel, steps 1-2 only (bottom-left)             */
#define ID_PRESETLIST 210   /* step 1 full-height listbox                       */
#define ID_FILELBL    220
#define ID_FILE       221
#define ID_BROWSE     222
#define ID_BASELBL    223
#define ID_BASE       224
#define ID_ENDLBL     225
#define ID_END        226
#define ID_SIZELBL    227
#define ID_SIZE       228
#define ID_SEG        229
#define ID_SEGHELP    230
#define ID_SEGLBL     231
#define ID_LOG        240   /* step 3 read-only multiline log                   */

typedef struct {
    HWND  hwnd;
    HWND  panel;      /* opaque bottom strip covering scrolled-off content   */
    int   step;

    /* Selected preset (step 1) and its seeded/committed config (step 2). All
       addresses are 1 MB-aligned; length is a whole number of megabytes. */
    int   preset_index;
    WCHAR outpath[MAX_PATH];
    DWORD base;
    DWORD length;
    int   segmented;
    DWORD seg_bytes;

    /* Vertical scroll of the active step's content area. */
    int   scroll_y;
    int   content_h;
    int   view_h;

    /* Dump worker state. */
    HANDLE         thread;
    volatile DWORD cur_pa;
    volatile DWORD bytes_done;
    volatile DWORD fault_pages;
    volatile int   cancel;
    volatile int   running;
    volatile int   finished;
    volatile int   ok;
    WCHAR          err[160];

    /* Segmented handshake. seg_start_pa/seg_end_pa frame the just-written
       segment for the pause prompt; seg_event lets the UI wake the worker. */
    volatile DWORD seg_index;      /* segment just written, 1-based        */
    volatile DWORD seg_total;      /* total segments                       */
    volatile DWORD segs_written;   /* fully-written segment files          */
    volatile DWORD seg_start_pa;
    volatile DWORD seg_end_pa;
    volatile int   seg_continue;   /* UI Yes(1)/No(0) to the pause prompt  */
    volatile DWORD fail_pa;        /* window PA of a storage-full write    */
    volatile int   storage_retry;  /* UI Retry(1)/Cancel(0) answer         */
    HANDLE         seg_event;      /* UI wakes the worker (pause + retry)  */
} AppState;

/* Worker (dump.cpp). */
DWORD WINAPI DumpThread(LPVOID param);

/* Shell helpers (main.cpp) usable from step files. */
void    AppLog(AppState* st, LPCWSTR text);
RECT    ContentRect(HWND hwnd);
FARPROC CoreProc(LPCWSTR name);

/* Per-step interface. Layout returns the step's content height (drives the
   scrollbar); OnNext returns TRUE to let the wizard advance (FALSE = stay);
   Command returns TRUE if it consumed the WM_COMMAND. */
void StepPresetCreate(AppState* st, HINSTANCE hi);
void StepPresetShow(AppState* st, BOOL show);
int  StepPresetLayout(AppState* st, RECT area);
BOOL StepPresetOnNext(AppState* st);

void StepConfigCreate(AppState* st, HINSTANCE hi);
void StepConfigShow(AppState* st, BOOL show);
void StepConfigEnter(AppState* st);                  /* seed fields from preset */
int  StepConfigLayout(AppState* st, RECT area);
BOOL StepConfigCommand(AppState* st, WPARAM wp, LPARAM lp);
BOOL StepConfigOnNext(AppState* st);

void StepDumpCreate(AppState* st, HINSTANCE hi);
void StepDumpShow(AppState* st, BOOL show);
void StepDumpEnter(AppState* st);                    /* start the worker */
int  StepDumpLayout(AppState* st, RECT area);
BOOL StepDumpCommand(AppState* st, WPARAM wp, LPARAM lp);
void StepDumpOnMessage(AppState* st, UINT msg, WPARAM wp, LPARAM lp);
void StepDumpPaintProgress(AppState* st, HDC dc, RECT panel);

/* Shared preset table (main.cpp) queried by step 1/2. `detail` is the second
   line shown in the step-1 picker (known devices / description); it may be
   empty. */
typedef struct { LPCWSTR name; LPCWSTR detail; DWORD base; DWORD size_mb; int custom; } Preset;
extern const Preset kPresets[];
extern const int    kNumPresets;
