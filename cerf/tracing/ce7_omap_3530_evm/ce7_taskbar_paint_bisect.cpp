#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "../../jit/arm_mmu_state.h"
#include "ce7_bundle.h"
#include "ce7_process_resolver.h"

#include <atomic>
#include <cstdint>

#if CERF_DEV_MODE

namespace {

/* explorer.exe ImageBase 0x10000. CTaskBar::Create body — first/last
   CreateWindowExW calls + the visibility-trigger triple at the end. */
constexpr uint32_t kPcCreateBlCreateWindowEx     = 0x00025EA0u;
constexpr uint32_t kPcCreatePostCreateWindowEx   = 0x00025EA4u;
constexpr uint32_t kPcCreateBlInvalidateRect     = 0x000262ACu;
constexpr uint32_t kPcCreateBlShowWindow         = 0x000262B8u;
constexpr uint32_t kPcCreateBlUpdateWindow       = 0x000262C0u;
constexpr uint32_t kPcCreatePostUpdateWindow     = 0x000262C4u;

/* explorer.exe CTaskBar WndProcs. Real handler 0x275A4; static-thunk
   0x291F8 calls it via the class-extra slot. Hooking both captures
   any dispatch path. */
constexpr uint32_t kPcTaskBarWndProcReal         = 0x000275A4u;
constexpr uint32_t kPcTaskBarWndProcThunk        = 0x000291F8u;

/* gwes kernel-side dispatchers (FCSE-immune). Filtered by taskbar
   hwnd so we admit only the taskbar's invocations and ignore every
   other window going through the same handler. */
constexpr uint32_t kPcGwesInvalidateRect_I       = 0xEFD9ADA0u;
constexpr uint32_t kPcGwesShowWindow_I           = 0xEFD9F4C4u;
constexpr uint32_t kPcGwesBeginPaint_I           = 0xEFD9A9A4u;
constexpr uint32_t kPcGwesEndPaint_I             = 0xEFD9AD34u;
constexpr uint32_t kPcGwesRepaintProc            = 0xEFD75B80u;
constexpr uint32_t kPcGwesCallWindowProcW_I      = 0xEFD79178u;
constexpr uint32_t kPcGwesAddPaintRequest        = 0xEFD6DCE8u;
constexpr uint32_t kPcGwesInvalidateRectPreTest  = 0xEFD9AECCu;
constexpr uint32_t kPcGwesInvalidateRectPaint    = 0xEFD9AED4u;
constexpr uint32_t kPcGwesInvalidateRectSkip     = 0xEFD9AF3Cu;
constexpr uint32_t kPcGwesModifyUpdateRegionBL   = 0xEFD9AF20u;
constexpr uint32_t kPcGwesModifyUpdateRegionEntry = 0xEFD99E30u;
constexpr uint32_t kPcGwesSetObscurity            = 0xEFE20690u;
constexpr uint32_t kPcGwesCWindowInitialize       = 0xEFD79808u;
constexpr uint32_t kPcGwesOnWindowCreatedBit29Str = 0xEFD89240u;
constexpr uint32_t kPcGwesSetAllNeedsBackbuffer   = 0xEFDD3648u;
constexpr uint32_t kPcGwesMWBOnChildChange        = 0xEFDD3928u;
constexpr uint32_t kPcGwesMwbEntry                = 0xEFDD39ECu;
constexpr uint32_t kPcGwesMwbProceed              = 0xEFDD3A38u;
constexpr uint32_t kPcGwesMwbEarlyOut             = 0xEFDD3B1Cu;
constexpr uint32_t kPcSetWindowPosICallsMwb       = 0xEFD9EA14u;
constexpr uint32_t kPcMwbTopLoopV8Check           = 0xEFDD3828u;
constexpr uint32_t kPcMwbTopLoopVisCheck          = 0xEFDD3834u;
constexpr uint32_t kPcMwbTopLoopIntersect         = 0xEFDD384Cu;
constexpr uint32_t kPcMwbTopLoopCombine           = 0xEFDD3868u;
constexpr uint32_t kPcMwbTopLoopPostRemove        = 0xEFDD38A8u;
constexpr uint32_t kPcGwesSetWindowLongWWorker    = 0xEFDCB3C4u;
constexpr uint32_t kPcGwesDestroyWindowI          = 0xEFD79F1Cu;
constexpr uint32_t kPcGwesDestroyWindowE          = 0xEFD7A2F8u;
constexpr uint32_t kPcGweUserDestroyDialogCb      = 0x00012770u;
constexpr uint32_t kPcGweUserDdcDestroySplashBl   = 0x000127B4u;
constexpr uint32_t kPcGweUserDdcPostQuitBranch    = 0x000127C8u;
constexpr uint32_t kPcGweUserCleanupBackground    = 0x00016690u;
constexpr uint32_t kPcGweUserDestroyWindowThunk   = 0x0001689Cu;
constexpr uint32_t kPcGweUserStartupDlgProcEntry  = 0x00015294u;
constexpr uint32_t kPcGweUserDlgProcCallsDdc      = 0x00015D40u;
constexpr uint32_t kPcGweUserResetCheck           = 0x00015884u;
constexpr uint32_t kPcGweUserPreLassWait          = 0x000158A8u;
constexpr uint32_t kPcGweUserPostLassWait         = 0x000158B0u;
constexpr uint32_t kPcLassdSeqThreadEntry         = 0x40961B98u;
constexpr uint32_t kPcLassdLoopTop                = 0x40961BB0u;
constexpr uint32_t kPcLassdPostSleep              = 0x40961BB8u;
constexpr uint32_t kPcLassdPostCreateLas0         = 0x40961BD8u;
constexpr uint32_t kPcLassdFailureReturn          = 0x40961BECu;
constexpr uint32_t kPcLassdEventModifyBl          = 0x40961C5Cu;

/* Captured at runtime from the post-CreateWindowExW R0 inside
   CTaskBar::Create. Used by gwes-side filters as the hwnd to admit. */
std::atomic<uint32_t> g_taskbar_hwnd{0u};
std::atomic<uint32_t> g_taskbar_pcwnd{0u};
std::atomic<uint32_t> g_working_pcwnd{0u};
std::atomic<uint32_t> g_splash_pcwnd{0u};

bool IsTaskbarHwnd(const TraceContext& c) {
    const uint32_t tb = g_taskbar_hwnd.load(std::memory_order_relaxed);
    return tb != 0u && c.regs[0] == tb;
}

class TraceCe7TaskbarPaintBisect : public Service {
public:
    using Service::Service;
    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kCe7BundleCrc32, [&] {
            auto expl_only =
                ce7_resolver::PidPredicateForName("explorer.exe");

            tm.OnPcFiltered(kPcCreateBlCreateWindowEx, expl_only,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[tb] CTaskBar::Create BL CreateWindowExW_0 "
                        "(HHTaskBar) dwExStyle=0x%08X lpClassName=0x%08X "
                        "dwStyle(stk)=0x%08X LR=0x%08X\n",
                        c.regs[0], c.regs[1],
                        c.ReadVa32(c.regs[13]).value_or(0xDEADBEEFu),
                        c.regs[14]);
                });

            tm.OnPcFiltered(kPcCreatePostCreateWindowEx, expl_only,
                [](const TraceContext& c) {
                    /* Capture before logging so downstream filters see
                       the hwnd even if logging is rate-limited later. */
                    const uint32_t hwnd = c.regs[0];
                    if (hwnd != 0u)
                        g_taskbar_hwnd.store(hwnd,
                                             std::memory_order_relaxed);
                    LOG(Trace,
                        "[tb] CTaskBar::Create post-CreateWindowExW_0 "
                        "(HHTaskBar) hwnd=0x%08X (captured as taskbar)\n",
                        hwnd);
                });

            tm.OnPcFiltered(kPcCreateBlInvalidateRect, expl_only,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[tb] CTaskBar::Create BL InvalidateRect_0 "
                        "hwnd=0x%08X lpRect=0x%08X bErase=%u LR=0x%08X\n",
                        c.regs[0], c.regs[1], c.regs[2], c.regs[14]);
                });

            tm.OnPcFiltered(kPcCreateBlShowWindow, expl_only,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[tb] CTaskBar::Create BL ShowWindow_0 "
                        "hwnd=0x%08X nCmdShow=%u LR=0x%08X\n",
                        c.regs[0], c.regs[1], c.regs[14]);
                });

            tm.OnPcFiltered(kPcCreateBlUpdateWindow, expl_only,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[tb] CTaskBar::Create BL UpdateWindow_0 "
                        "hwnd=0x%08X LR=0x%08X\n",
                        c.regs[0], c.regs[14]);
                });

            tm.OnPcFiltered(kPcCreatePostUpdateWindow, expl_only,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[tb] CTaskBar::Create post-UpdateWindow_0 "
                        "ret=0x%08X LR=0x%08X\n",
                        c.regs[0], c.regs[14]);
                });

            /* WndProc entries — fire on every msg dispatched to the
               class. Log only when hwnd matches the captured taskbar
               (skip noise from other HHTaskBar instances if any). */
            auto wndproc_hook = [](const char* tag) {
                return [tag](const TraceContext& c) {
                    const uint32_t tb =
                        g_taskbar_hwnd.load(std::memory_order_relaxed);
                    if (tb == 0u || c.regs[0] != tb) return;
                    LOG(Trace,
                        "[tb] %s hwnd=0x%08X msg=0x%04X "
                        "wParam=0x%08X lParam=0x%08X LR=0x%08X\n",
                        tag, c.regs[0], c.regs[1], c.regs[2],
                        c.regs[3], c.regs[14]);
                };
            };
            tm.OnPcFiltered(kPcTaskBarWndProcThunk, expl_only,
                wndproc_hook("s_TaskBarWndProc(thunk)"));
            tm.OnPcFiltered(kPcTaskBarWndProcReal, expl_only,
                wndproc_hook("TaskBarWndProc(real)"));

            /* gwes-side: filtered by taskbar hwnd in R0. The predicate
               admits the hook iff the live hwnd matches what we
               captured from CTaskBar::Create above. */
            tm.OnPcFiltered(kPcGwesShowWindow_I, IsTaskbarHwnd,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[tb] gwes!ShowWindow_I (taskbar) hwnd=0x%08X "
                        "nCmdShow=%d LR=0x%08X\n",
                        c.regs[0], static_cast<int32_t>(c.regs[1]),
                        c.regs[14]);
                });
            tm.OnPcFiltered(kPcGwesInvalidateRect_I, IsTaskbarHwnd,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[tb] gwes!InvalidateRect_I (taskbar) "
                        "hwnd=0x%08X lpRect=0x%08X bErase=%u LR=0x%08X\n",
                        c.regs[0], c.regs[1], c.regs[2], c.regs[14]);
                });
            tm.OnPcFiltered(kPcGwesBeginPaint_I, IsTaskbarHwnd,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[tb] gwes!BeginPaint_I (taskbar) hwnd=0x%08X "
                        "lpPaint=0x%08X LR=0x%08X\n",
                        c.regs[0], c.regs[1], c.regs[14]);
                });
            tm.OnPcFiltered(kPcGwesEndPaint_I, IsTaskbarHwnd,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[tb] gwes!EndPaint_I (taskbar) hwnd=0x%08X "
                        "lpPaint=0x%08X LR=0x%08X\n",
                        c.regs[0], c.regs[1], c.regs[14]);
                });
            tm.OnPcFiltered(kPcGwesRepaintProc, IsTaskbarHwnd,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[tb] gwes!RepaintProc (taskbar) hwnd=0x%08X "
                        "lParam=0x%08X LR=0x%08X\n",
                        c.regs[0], c.regs[1], c.regs[14]);
                });
            tm.OnPcFiltered(kPcGwesAddPaintRequest,
                [](const TraceContext& c) {
                    /* AddPaintRequest's hwnd is R1 not R0 (R0 is the
                       MsgQueue this). */
                    const uint32_t tb =
                        g_taskbar_hwnd.load(std::memory_order_relaxed);
                    return tb != 0u && c.regs[1] == tb;
                },
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[tb] gwes!AddPaintRequest (taskbar) "
                        "MQ=0x%08X hwnd=0x%08X LR=0x%08X\n",
                        c.regs[0], c.regs[1], c.regs[14]);
                });

            tm.OnPcFiltered(kPcGwesCallWindowProcW_I,
                [](const TraceContext& c) {
                    const uint32_t tb =
                        g_taskbar_hwnd.load(std::memory_order_relaxed);
                    return tb != 0u && c.regs[1] == tb;
                },
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[tb] gwes!CallWindowProcW_I (taskbar) "
                        "hwnd=0x%08X msg=0x%04X wParam=0x%08X "
                        "lParam(stk)=0x%08X LR=0x%08X\n",
                        c.regs[1], c.regs[2], c.regs[3],
                        c.ReadVa32(c.regs[13]).value_or(0xDEADBEEFu),
                        c.regs[14]);
                });

            tm.OnPc(kPcGwesInvalidateRectPreTest,
                [](const TraceContext& c) {
                    const uint32_t pcwnd = c.regs[0];
                    const uint32_t hwnd =
                        c.ReadVa32(pcwnd + 0x78u).value_or(0u);
                    const uint32_t tb =
                        g_taskbar_hwnd.load(std::memory_order_relaxed);
                    const bool is_tb = (tb != 0u && hwnd == tb);
                    if (is_tb)
                        g_taskbar_pcwnd.store(
                            pcwnd, std::memory_order_relaxed);
                    static uint32_t n_all = 0;
                    ++n_all;
                    if (!is_tb && n_all > 30 && (n_all % 200u) != 0u)
                        return;
                    const uint32_t m_e4 = c.regs[3];
                    LOG(Trace,
                        "[tb] InvR pre-TST pcwnd=0x%08X hwnd=0x%08X "
                        "m[0xE4]=0x%08X bit1=%u (%s)\n",
                        pcwnd, hwnd, m_e4, (m_e4 >> 1) & 1u,
                        is_tb ? "TASKBAR" : "other");
                });

            tm.OnPc(kPcGwesInvalidateRectPaint,
                [](const TraceContext& c) {
                    const uint32_t pcwnd = c.regs[0];
                    const uint32_t hwnd =
                        c.ReadVa32(pcwnd + 0x78u).value_or(0u);
                    const uint32_t tb =
                        g_taskbar_hwnd.load(std::memory_order_relaxed);
                    static uint32_t n_all = 0;
                    ++n_all;
                    const bool is_tb = (tb != 0u && hwnd == tb);
                    if (!is_tb && n_all > 30 && (n_all % 200u) != 0u)
                        return;
                    LOG(Trace,
                        "[tb] InvR PAINT-branch pcwnd=0x%08X hwnd=0x%08X "
                        "(%s)\n", pcwnd, hwnd,
                        is_tb ? "TASKBAR" : "other");
                });

            tm.OnPc(kPcGwesInvalidateRectSkip,
                [](const TraceContext& c) {
                    const uint32_t pcwnd = c.regs[0];
                    const uint32_t hwnd =
                        c.ReadVa32(pcwnd + 0x78u).value_or(0u);
                    const uint32_t tb =
                        g_taskbar_hwnd.load(std::memory_order_relaxed);
                    static uint32_t n_all = 0;
                    ++n_all;
                    const bool is_tb = (tb != 0u && hwnd == tb);
                    if (!is_tb && n_all > 30 && (n_all % 200u) != 0u)
                        return;
                    const uint32_t m_e4 =
                        c.ReadVa32(pcwnd + 0xE4u).value_or(0u);
                    LOG(Trace,
                        "[tb] InvR SKIP-branch pcwnd=0x%08X hwnd=0x%08X "
                        "m[0xE4]=0x%08X (%s)\n",
                        pcwnd, hwnd, m_e4,
                        is_tb ? "TASKBAR" : "other");
                });

            tm.OnPc(kPcGwesModifyUpdateRegionBL,
                [](const TraceContext& c) {
                    const uint32_t pcwnd = c.regs[0];
                    const uint32_t hwnd =
                        c.ReadVa32(pcwnd + 0x78u).value_or(0u);
                    const uint32_t tb =
                        g_taskbar_hwnd.load(std::memory_order_relaxed);
                    static uint32_t n_all = 0;
                    ++n_all;
                    const bool is_tb = (tb != 0u && hwnd == tb);
                    if (!is_tb && n_all > 30 && (n_all % 200u) != 0u)
                        return;
                    LOG(Trace,
                        "[tb] InvR ModifyUpdateRegion BL "
                        "pcwnd=0x%08X hwnd=0x%08X CombineMode=%u (%s)\n",
                        pcwnd, hwnd, c.regs[1],
                        is_tb ? "TASKBAR" : "other");
                });

            tm.OnPc(kPcGwesCWindowInitialize,
                [](const TraceContext& c) {
                    const uint32_t pcwnd = c.regs[0];
                    const uint32_t pcwnd_parent = c.regs[1];
                    const uint32_t hwnd =
                        c.ReadVa32(pcwnd + 0x78u).value_or(0u);
                    const uint32_t m_e4 =
                        c.ReadVa32(pcwnd + 0xE4u).value_or(0xDEADBEEFu);
                    const uint32_t tb =
                        g_taskbar_hwnd.load(std::memory_order_relaxed);
                    const bool is_tb =
                        hwnd == 0xFE190002u || (tb != 0u && hwnd == tb);
                    LOG(Trace,
                        "[tb] CWindow::Initialize-entry pcwnd=0x%08X "
                        "pcwnd_parent(R1)=0x%08X hwnd=0x%08X "
                        "m[0xE4]=0x%08X (taskbar=%d)\n",
                        pcwnd, pcwnd_parent, hwnd, m_e4, is_tb ? 1 : 0);
                    if (is_tb)
                        g_taskbar_pcwnd.store(
                            pcwnd, std::memory_order_relaxed);
                    if (hwnd == 0xFE0B0002u)
                        g_splash_pcwnd.store(
                            pcwnd, std::memory_order_relaxed);
                });

            tm.OnPc(kPcGwesSetAllNeedsBackbuffer,
                [](const TraceContext& c) {
                    const uint32_t pcwnd = c.regs[2];
                    const uint32_t hwnd =
                        c.ReadVa32(pcwnd + 0x78u).value_or(0u);
                    const uint32_t m_e4 =
                        c.ReadVa32(pcwnd + 0xE4u).value_or(0xDEADBEEFu);
                    const uint32_t style =
                        c.ReadVa32(pcwnd + 0x98u).value_or(0xDEADBEEFu);
                    LOG(Trace,
                        "[tb] SetAllNeedsBackbuffer pcwnd=0x%08X "
                        "hwnd=0x%08X m[0xE4]=0x%08X m[0x98]/grfStyle=0x%08X "
                        "WS_VISIBLE=%u LR=0x%08X\n",
                        pcwnd, hwnd, m_e4, style,
                        (style >> 28) & 1u, c.regs[14]);
                });

            tm.OnPc(kPcGwesMWBOnChildChange,
                [](const TraceContext& c) {
                    const uint32_t pcwnd = c.regs[2];
                    const uint32_t ir    = c.regs[3];
                    const uint32_t hwnd =
                        c.ReadVa32(pcwnd + 0x78u).value_or(0u);
                    const uint32_t m_e4 =
                        c.ReadVa32(pcwnd + 0xE4u).value_or(0xDEADBEEFu);
                    const uint32_t style =
                        c.ReadVa32(pcwnd + 0x98u).value_or(0xDEADBEEFu);
                    const uint32_t parent =
                        c.ReadVa32(pcwnd + 8u).value_or(0u);
                    const uint32_t parent_e4 = parent
                        ? c.ReadVa32(parent + 0xE4u).value_or(0xDEADBEEFu)
                        : 0xDEADBEEFu;
                    LOG(Trace,
                        "[tb] MWBOnChildChange pcwnd=0x%08X hwnd=0x%08X "
                        "ir=0x%08X m[0xE4]=0x%08X grfStyle=0x%08X "
                        "parent=0x%08X parent.m[0xE4]=0x%08X LR=0x%08X\n",
                        pcwnd, hwnd, ir, m_e4, style, parent,
                        parent_e4, c.regs[14]);
                });

            tm.OnPcFiltered(kPcGwesMwbEntry,
                [](const TraceContext&) { return true; },
                [](const TraceContext& c) {
                    const uint32_t pcwnd = c.regs[2];
                    const uint32_t ir    = c.regs[3];
                    const uint32_t hwnd =
                        c.ReadVa32(pcwnd + 0x78u).value_or(0u);
                    const uint32_t tb =
                        g_taskbar_hwnd.load(std::memory_order_relaxed);
                    static uint32_t n_all = 0;
                    ++n_all;
                    const bool is_tb = (tb != 0u && hwnd == tb);
                    if (!is_tb && n_all > 30 && (n_all % 200u) != 0u)
                        return;
                    LOG(Trace,
                        "[tb] MWB-entry pcwnd=0x%08X hwnd=0x%08X "
                        "ir=0x%08X LR=0x%08X (%s)\n",
                        pcwnd, hwnd, ir, c.regs[14],
                        is_tb ? "TASKBAR" : "other");
                });

            tm.OnPc(kPcGwesMwbProceed,
                [](const TraceContext& c) {
                    const uint32_t pcwnd = c.regs[4];
                    const uint32_t ir    = c.regs[5];
                    const uint32_t hwnd =
                        c.ReadVa32(pcwnd + 0x78u).value_or(0u);
                    const uint32_t grfStyle =
                        c.ReadVa32(pcwnd + 0x98u).value_or(0xDEADBEEFu);
                    const uint32_t m_e4 =
                        c.ReadVa32(pcwnd + 0xE4u).value_or(0xDEADBEEFu);
                    const uint32_t tb =
                        g_taskbar_hwnd.load(std::memory_order_relaxed);
                    static uint32_t n_all = 0;
                    ++n_all;
                    const bool is_tb = (tb != 0u && hwnd == tb);
                    if (!is_tb && n_all > 30 && (n_all % 200u) != 0u)
                        return;
                    LOG(Trace,
                        "[tb] MWB-PROCEED pcwnd=0x%08X hwnd=0x%08X "
                        "ir=0x%08X grfStyle=0x%08X WS_VIS=%u m[0xE4]=0x%08X (%s)\n",
                        pcwnd, hwnd, ir, grfStyle,
                        (grfStyle >> 28) & 1u, m_e4,
                        is_tb ? "TASKBAR" : "other");
                });

            tm.OnPc(kPcGwesMwbEarlyOut,
                [](const TraceContext& c) {
                    const uint32_t pcwnd = c.regs[4];
                    const uint32_t ir    = c.regs[5];
                    const uint32_t hwnd =
                        c.ReadVa32(pcwnd + 0x78u).value_or(0u);
                    const uint32_t tb =
                        g_taskbar_hwnd.load(std::memory_order_relaxed);
                    static uint32_t n_all = 0;
                    ++n_all;
                    const bool is_tb = (tb != 0u && hwnd == tb);
                    if (!is_tb && n_all > 30 && (n_all % 200u) != 0u)
                        return;
                    const char* gate = "unknown";
                    if (ir == 0u) gate = "ir=IR_NONE";
                    else if (ir == 0x80u) gate = "ir=IR_FRAMEONLY";
                    else gate = "pcwnd==root";
                    LOG(Trace,
                        "[tb] MWB-EARLY-OUT pcwnd=0x%08X hwnd=0x%08X "
                        "ir=0x%08X gate=%s (%s)\n",
                        pcwnd, hwnd, ir, gate,
                        is_tb ? "TASKBAR" : "other");
                });

            tm.OnPc(kPcSetWindowPosICallsMwb,
                [](const TraceContext& c) {
                    const uint32_t pcwnd = c.regs[1];
                    const uint32_t ir    = c.regs[2];
                    const uint32_t hwnd =
                        c.ReadVa32(pcwnd + 0x78u).value_or(0u);
                    const uint32_t tb =
                        g_taskbar_hwnd.load(std::memory_order_relaxed);
                    static uint32_t n_all = 0;
                    ++n_all;
                    const bool is_tb = (tb != 0u && hwnd == tb);
                    if (!is_tb && n_all > 30 && (n_all % 200u) != 0u)
                        return;
                    LOG(Trace,
                        "[tb] SWP-I->MWB pcwnd=0x%08X hwnd=0x%08X "
                        "ir=0x%08X LR=0x%08X (%s)\n",
                        pcwnd, hwnd, ir, c.regs[14],
                        is_tb ? "TASKBAR" : "other");
                });

            auto mwb_loop_tb_only =
                [](const TraceContext& c) {
                    const uint32_t pcwnd = c.regs[4];
                    const uint32_t tb_pcwnd =
                        g_taskbar_pcwnd.load(std::memory_order_relaxed);
                    return tb_pcwnd != 0u && pcwnd == tb_pcwnd;
                };

            tm.OnPcFiltered(kPcMwbTopLoopV8Check, mwb_loop_tb_only,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[tb] MWB-top-loop v8-check pcwnd=0x%08X R10(v8)=0x%08X\n",
                        c.regs[4], c.regs[10]);
                });

            tm.OnPcFiltered(kPcMwbTopLoopVisCheck, mwb_loop_tb_only,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[tb] MWB-top-loop vis-check pcwnd=0x%08X "
                        "R3(m_grfStyle)=0x%08X WS_VISIBLE=%u\n",
                        c.regs[4], c.regs[3],
                        (c.regs[3] >> 28) & 1u);
                });

            tm.OnPcFiltered(kPcMwbTopLoopIntersect, mwb_loop_tb_only,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[tb] MWB-top-loop intersect-result pcwnd=0x%08X "
                        "R0=%u (1=intersect, 0=no)\n",
                        c.regs[4], c.regs[0]);
                });

            tm.OnPcFiltered(kPcMwbTopLoopCombine, mwb_loop_tb_only,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[tb] MWB-top-loop combine-result pcwnd=0x%08X "
                        "R0=%u (1=NULLREGION→skip)\n",
                        c.regs[4], c.regs[0]);
                });

            tm.OnPcFiltered(kPcMwbTopLoopV8Check,
                [](const TraceContext&) { return true; },
                [](const TraceContext& c) {
                    const uint32_t pcwnd = c.regs[4];
                    const uint32_t v8    = c.regs[10];
                    const uint32_t hwnd =
                        c.ReadVa32(pcwnd + 0x78u).value_or(0u);
                    LOG(Trace,
                        "[tb] MWB-top-loop ITER pcwnd=0x%08X hwnd=0x%08X "
                        "v8-at-entry=0x%08X\n",
                        pcwnd, hwnd, v8);
                });

            tm.OnPcFiltered(kPcMwbTopLoopVisCheck,
                [](const TraceContext&) { return true; },
                [](const TraceContext& c) {
                    const uint32_t pcwnd = c.regs[4];
                    const uint32_t grfStyle = c.regs[3];
                    const uint32_t hwnd =
                        c.ReadVa32(pcwnd + 0x78u).value_or(0u);
                    LOG(Trace,
                        "[tb] MWB-top-loop VIS pcwnd=0x%08X hwnd=0x%08X "
                        "grfStyle=0x%08X WS_VISIBLE=%u\n",
                        pcwnd, hwnd, grfStyle, (grfStyle >> 28) & 1u);
                });

            tm.OnPcFiltered(kPcMwbTopLoopIntersect,
                [](const TraceContext&) { return true; },
                [](const TraceContext& c) {
                    const uint32_t pcwnd = c.regs[4];
                    const uint32_t intersect = c.regs[0];
                    const uint32_t hwnd =
                        c.ReadVa32(pcwnd + 0x78u).value_or(0u);
                    const uint32_t rc_left =
                        c.ReadVa32(pcwnd + 0x38u).value_or(0u);
                    const uint32_t rc_top =
                        c.ReadVa32(pcwnd + 0x3Cu).value_or(0u);
                    const uint32_t rc_right =
                        c.ReadVa32(pcwnd + 0x40u).value_or(0u);
                    const uint32_t rc_bottom =
                        c.ReadVa32(pcwnd + 0x44u).value_or(0u);
                    LOG(Trace,
                        "[tb] MWB-top-loop INTERSECT pcwnd=0x%08X hwnd=0x%08X "
                        "rc=(%d,%d,%d,%d) result=%u\n",
                        pcwnd, hwnd,
                        static_cast<int32_t>(rc_left),
                        static_cast<int32_t>(rc_top),
                        static_cast<int32_t>(rc_right),
                        static_cast<int32_t>(rc_bottom),
                        intersect);
                });

            tm.OnPcFiltered(kPcMwbTopLoopCombine,
                [](const TraceContext&) { return true; },
                [](const TraceContext& c) {
                    const uint32_t pcwnd = c.regs[4];
                    const uint32_t combine = c.regs[0];
                    const uint32_t hwnd =
                        c.ReadVa32(pcwnd + 0x78u).value_or(0u);
                    const uint32_t hrgnVis =
                        c.ReadVa32(pcwnd + 0xC8u).value_or(0u);
                    LOG(Trace,
                        "[tb] MWB-top-loop COMBINE pcwnd=0x%08X hwnd=0x%08X "
                        "hrgnVisible=0x%08X result=%u (1=NULLREGION→skip)\n",
                        pcwnd, hwnd, hrgnVis, combine);
                });

            tm.OnPc(kPcMwbTopLoopPostRemove,
                [](const TraceContext& c) {
                    const uint32_t pcwnd = c.regs[4];
                    const uint32_t v8    = c.regs[10];
                    const uint32_t hwnd =
                        c.ReadVa32(pcwnd + 0x78u).value_or(0u);
                    LOG(Trace,
                        "[tb] MWB-top-loop POST-Remove pcwnd=0x%08X "
                        "hwnd=0x%08X new-v8=0x%08X\n",
                        pcwnd, hwnd, v8);
                });

            tm.OnPc(kPcGwesSetWindowLongWWorker,
                [](const TraceContext& c) {
                    const uint32_t hwnd     = c.regs[0];
                    const int32_t  index    = static_cast<int32_t>(c.regs[1]);
                    const uint32_t newValue = c.regs[2];
                    const char* tag = "extra";
                    switch (index) {
                        case -21: tag = "GWL_USERDATA"; break;
                        case -20: tag = "GWL_EXSTYLE";  break;
                        case -16: tag = "GWL_STYLE";    break;
                        case -12: tag = "GWL_ID";       break;
                        case -4:  tag = "GWL_WNDPROC";  break;
                        default:  break;
                    }
                    LOG(Trace,
                        "[tb] SetWindowLongW_Worker hwnd=0x%08X "
                        "Index=%d(%s) NewValue=0x%08X hCallerProc=0x%08X "
                        "LR=0x%08X\n",
                        hwnd, index, tag, newValue, c.regs[3], c.regs[14]);
                });

            tm.OnPc(kPcGwesDestroyWindowI,
                [](const TraceContext& c) {
                    const uint32_t ttbr0 =
                        c.emu.Get<ArmMmu>().State()->translation_table_base.word
                        & 0xFFFFC000u;
                    LOG(Trace,
                        "[tb] DestroyWindow_I hwnd=0x%08X TTBR0=0x%08X "
                        "LR=0x%08X\n",
                        c.regs[0], ttbr0, c.regs[14]);
                });

            tm.OnPc(kPcGwesDestroyWindowE,
                [](const TraceContext& c) {
                    const uint32_t ttbr0 =
                        c.emu.Get<ArmMmu>().State()->translation_table_base.word
                        & 0xFFFFC000u;
                    LOG(Trace,
                        "[tb] DestroyWindow_E hwnd=0x%08X TTBR0=0x%08X "
                        "LR=0x%08X\n",
                        c.regs[0], ttbr0, c.regs[14]);
                });

            auto gweuser_only =
                ce7_resolver::PidPredicateForName("GweUser.exe");

            tm.OnPcFiltered(kPcGweUserDestroyDialogCb, gweuser_only,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[tb] Startup_DestroyDialogCallback ENTRY LR=0x%08X\n",
                        c.regs[14]);
                });

            tm.OnPcFiltered(kPcGweUserDdcDestroySplashBl, gweuser_only,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[tb] Startup_DestroyDialogCallback pre-DestroyWindow "
                        "hwnd=0x%08X\n",
                        c.regs[0]);
                });

            tm.OnPcFiltered(kPcGweUserDdcPostQuitBranch, gweuser_only,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[tb] Startup_DestroyDialogCallback pre-PostQuit "
                        "(tail-call) R0=%d\n",
                        c.regs[0]);
                });

            tm.OnPcFiltered(kPcGweUserCleanupBackground, gweuser_only,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[tb] Startup_CleanupBackground ENTRY LR=0x%08X\n",
                        c.regs[14]);
                });

            tm.OnPcFiltered(kPcGweUserDestroyWindowThunk, gweuser_only,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[tb] GweUser DestroyWindow_0 thunk hwnd=0x%08X "
                        "user_LR=0x%08X\n",
                        c.regs[0], c.regs[14]);
                });

            tm.OnPcFiltered(kPcGweUserStartupDlgProcEntry, gweuser_only,
                [](const TraceContext& c) {
                    const uint32_t msg = c.regs[1];
                    if (msg != 0x110u && msg != 0x113u && msg != 0x400u &&
                        msg != 0x401u && msg != 0x111u && msg != 0x100u &&
                        msg != 0x10u  && msg != 0x2u)
                        return;
                    LOG(Trace,
                        "[tb] Startup_DlgProc msg=0x%04X wParam=0x%08X "
                        "lParam=0x%08X LR=0x%08X\n",
                        msg, c.regs[2], c.regs[3], c.regs[14]);
                });

            tm.OnPcFiltered(kPcGweUserDlgProcCallsDdc, gweuser_only,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[tb] Startup_DlgProc BL Startup_DestroyDialogCallback "
                        "(cleanup path reached) LR=0x%08X\n",
                        c.regs[14]);
                });

            tm.OnPcFiltered(kPcGweUserResetCheck, gweuser_only,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[tb] Startup_DlgProc post-LDR-v_fReset R3=%u "
                        "(0=skip-LASS-wait, non-0=enter-LASS-wait)\n",
                        c.regs[3]);
                });

            tm.OnPcFiltered(kPcGweUserPreLassWait, gweuser_only,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[tb] Startup_DlgProc pre-WaitForSingleObject"
                        "(LASS_SRV_STARTED) hEvent=0x%08X dwMs=0x%08X\n",
                        c.regs[0], c.regs[1]);
                });

            tm.OnPcFiltered(kPcGweUserPostLassWait, gweuser_only,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[tb] Startup_DlgProc post-Wait(LASS) ret=0x%08X "
                        "(0=signaled, 0x102=timeout)\n",
                        c.regs[0]);
                });

            tm.OnPc(kPcLassdSeqThreadEntry,
                [](const TraceContext& c) {
                    const uint32_t ttbr0 =
                        c.emu.Get<ArmMmu>().State()->translation_table_base.word
                        & 0xFFFFC000u;
                    LOG(Trace,
                        "[tb] lassd!WaitForServiceReadyAndSignalServiceStarted "
                        "ENTRY this=0x%08X TTBR0=0x%08X LR=0x%08X\n",
                        c.regs[0], ttbr0, c.regs[14]);
                });

            tm.OnPc(kPcLassdPostCreateLas0,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[tb] lassd post-CreateFileW(LAS0:) ret=0x%08X "
                        "(-1=fail/retry, otherwise=success-break)\n",
                        c.regs[0]);
                });

            tm.OnPc(kPcLassdFailureReturn,
                [](const TraceContext& c) {
                    (void)c;
                    LOG(Trace,
                        "[tb] lassd FAILURE-RETURN R0=21 "
                        "(LAS0: never opened in 5 retries)\n");
                });

            tm.OnPc(kPcLassdEventModifyBl,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[tb] lassd BL EventModify(LASS_SRV_STARTED, SET) "
                        "hEvent=0x%08X — about to signal\n",
                        c.regs[0]);
                });

            tm.OnPc(kPcLassdLoopTop,
                [](const TraceContext& c) {
                    LOG(Trace,
                        "[tb] lassd loop-top R4(retry_count)=%u\n",
                        c.regs[4]);
                });

            tm.OnPc(kPcLassdPostSleep,
                [](const TraceContext& c) {
                    (void)c;
                    LOG(Trace,
                        "[tb] lassd post-Sleep(1000) — about to CreateFileW(LAS0:)\n");
                });

            tm.OnPc(kPcGwesOnWindowCreatedBit29Str,
                [](const TraceContext& c) {
                    const uint32_t pcwnd = c.regs[5];  /* R5 = pWindow */
                    const uint32_t hwnd =
                        c.ReadVa32(pcwnd + 0x78u).value_or(0u);
                    const uint32_t parent =
                        c.ReadVa32(pcwnd + 8u).value_or(0u);
                    LOG(Trace,
                        "[tb] GweHgOnWindowCreated SET-bit29 pcwnd=0x%08X "
                        "hwnd=0x%08X m_pParent=0x%08X new_m=0x%08X\n",
                        pcwnd, hwnd, parent, c.regs[3]);
                });

            tm.OnPc(kPcGwesSetObscurity,
                [](const TraceContext& c) {
                    const uint32_t pthis = c.regs[0];
                    const uint32_t fObs  = c.regs[1];
                    const uint32_t pcwnd =
                        c.ReadVa32(pthis + 4u).value_or(0u);
                    const uint32_t hwnd =
                        pcwnd ? c.ReadVa32(pcwnd + 0x78u).value_or(0u) : 0u;
                    LOG(Trace,
                        "[tb] SetObscurity this=0x%08X pcwnd=0x%08X "
                        "hwnd=0x%08X fObscured=%u LR=0x%08X\n",
                        pthis, pcwnd, hwnd, fObs, c.regs[14]);
                });

            tm.OnPc(kPcGwesModifyUpdateRegionEntry,
                [](const TraceContext& c) {
                    const uint32_t pcwnd = c.regs[0];
                    const uint32_t hwnd =
                        c.ReadVa32(pcwnd + 0x78u).value_or(0u);
                    const uint32_t m_e4 =
                        c.ReadVa32(pcwnd + 0xE4u).value_or(0xDEADBEEFu);
                    if (hwnd == 0xFE140002u)
                        g_working_pcwnd.store(
                            pcwnd, std::memory_order_relaxed);
                    LOG(Trace,
                        "[tb] MUR-entry pcwnd=0x%08X hwnd=0x%08X "
                        "m[0xE4]=0x%08X bit29=%u CombineMode=%u\n",
                        pcwnd, hwnd, m_e4,
                        (m_e4 >> 29) & 1u, c.regs[1]);
                });

            tm.OnRunLoopIter(
                [last = uint32_t{0xDEADBEEFu}, fired_initial = false]
                (const TraceContext& c) mutable {
                    const uint32_t pcwnd =
                        g_taskbar_pcwnd.load(std::memory_order_relaxed);
                    if (pcwnd == 0u) return;
                    const uint32_t m_e4 =
                        c.ReadVa32(pcwnd + 0xE4u).value_or(0xDEADBEEFu);
                    if (m_e4 == 0xDEADBEEFu) return;
                    if (m_e4 == last) return;
                    LOG(Trace,
                        "[tb] tb-m[0xE4] %s pcwnd=0x%08X 0x%08X -> 0x%08X "
                        "(bit29 %u->%u) pc=0x%08X\n",
                        fired_initial ? "TRANSITION" : "INITIAL",
                        pcwnd, last, m_e4,
                        (last  >> 29) & 1u,
                        (m_e4 >> 29) & 1u, c.pc);
                    last = m_e4;
                    fired_initial = true;
                });

            tm.OnRunLoopIter(
                [last = uint32_t{0xDEADBEEFu}, fired_initial = false]
                (const TraceContext& c) mutable {
                    const uint32_t pcwnd =
                        g_working_pcwnd.load(std::memory_order_relaxed);
                    if (pcwnd == 0u) return;
                    const uint32_t m_e4 =
                        c.ReadVa32(pcwnd + 0xE4u).value_or(0xDEADBEEFu);
                    if (m_e4 == 0xDEADBEEFu) return;
                    if (m_e4 == last) return;
                    LOG(Trace,
                        "[tb] working-m[0xE4] %s pcwnd=0x%08X 0x%08X -> "
                        "0x%08X (bit29 %u->%u) pc=0x%08X\n",
                        fired_initial ? "TRANSITION" : "INITIAL",
                        pcwnd, last, m_e4,
                        (last  >> 29) & 1u,
                        (m_e4 >> 29) & 1u, c.pc);
                    last = m_e4;
                    fired_initial = true;
                });

            tm.OnRunLoopIter(
                [last = uint32_t{0xDEADBEEFu}, fired_initial = false]
                (const TraceContext& c) mutable {
                    const uint32_t pcwnd =
                        g_splash_pcwnd.load(std::memory_order_relaxed);
                    if (pcwnd == 0u) return;
                    const uint32_t m_e4 =
                        c.ReadVa32(pcwnd + 0xE4u).value_or(0xDEADBEEFu);
                    if (m_e4 == 0xDEADBEEFu) return;
                    if (m_e4 == last) return;
                    LOG(Trace,
                        "[tb] splash-m[0xE4] %s pcwnd=0x%08X 0x%08X -> "
                        "0x%08X (bit29 %u->%u) pc=0x%08X\n",
                        fired_initial ? "TRANSITION" : "INITIAL",
                        pcwnd, last, m_e4,
                        (last  >> 29) & 1u,
                        (m_e4 >> 29) & 1u, c.pc);
                    last = m_e4;
                    fired_initial = true;
                });
        });
    }
};

REGISTER_SERVICE(TraceCe7TaskbarPaintBisect);

}  /* namespace */

#endif  /* CERF_DEV_MODE */
