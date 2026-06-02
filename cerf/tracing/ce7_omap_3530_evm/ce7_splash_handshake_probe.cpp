#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "../../jit/arm_mmu_state.h"
#include "ce7_bundle.h"
#include "ce7_process_resolver.h"

#include <cstdint>

#if CERF_DEV_MODE

namespace {

/* StartupScreenThread (splash) PCs — pTh=0xC0473198 historically. */
constexpr uint32_t kPcSplashBlCreateDialog       = 0x125F8u;
constexpr uint32_t kPcSplashPostCreateDialog     = 0x125FCu;
constexpr uint32_t kPcSplashBlEvtShutdownSet     = 0x1260Cu;
constexpr uint32_t kPcSplashPostEvtShutdownSet   = 0x12610u;
constexpr uint32_t kPcSplashBlWaitContinueStart  = 0x12618u;
constexpr uint32_t kPcSplashPostWaitContinueStart = 0x1261Cu;

/* GweUser_StartupScreenSetup_I PCs. */
constexpr uint32_t kPcSetupBlEvtBeginSet       = 0x1272Cu;
constexpr uint32_t kPcSetupPostEvtBeginSet     = 0x12730u;
constexpr uint32_t kPcSetupBlWaitShutdown      = 0x12738u;
constexpr uint32_t kPcSetupPostWaitShutdown    = 0x1273Cu;
constexpr uint32_t kPcSetupReturnEpilogue      = 0x12744u;

/* Startup_CreateDialog internal bisection: which of the 3 BLs hangs. */
constexpr uint32_t kPcCdBlFindResource      = 0x16760u;
constexpr uint32_t kPcCdPostFindResource    = 0x16764u;
constexpr uint32_t kPcCdBlLoadResource      = 0x1676Cu;
constexpr uint32_t kPcCdPostLoadResource    = 0x16770u;
constexpr uint32_t kPcCdBlCreateDialog      = 0x16788u;
constexpr uint32_t kPcCdPostCreateDialog    = 0x1678Cu;

/* Startup_DlgProc WM_INITDIALOG (0x110) handler post-call sites, flat-splash branch. */
constexpr uint32_t kPcDpPostCreateSplash    = 0x1560Cu;
constexpr uint32_t kPcDpPostSetTimer        = 0x15634u;
constexpr uint32_t kPcDpPostSetWindowPos    = 0x1565Cu;
constexpr uint32_t kPcDpPostUpdateWindow    = 0x15664u;
constexpr uint32_t kPcDpPostGetWindowLongW  = 0x15670u;
constexpr uint32_t kPcDpPostSetWindowLongW  = 0x15680u;
constexpr uint32_t kPcDpInitDialogReturn    = 0x153B8u;

/* CreateSplash inner BL sites. */
constexpr uint32_t kPcCsPostRegister        = 0x16620u;
constexpr uint32_t kPcCsPostGSM1            = 0x16638u;
constexpr uint32_t kPcCsPostGSM2            = 0x16644u;
constexpr uint32_t kPcCsPostCreateWindow    = 0x16680u;

/* StartupSplash::WindowProc tail (DefWindowProcW dispatch for unhandled messages). */
constexpr uint32_t kPcWpEntry                  = 0x16458u;
constexpr uint32_t kPcWpBlDefWindowProc        = 0x16574u;
constexpr uint32_t kPcWpPostDefWindowProc      = 0x16578u;
constexpr uint32_t kPcWpReturn                 = 0x16580u;

constexpr uint32_t kVaPCurThd = 0xFFFFC824u;

class TraceCe7SplashHandshakeProbe : public Service {
public:
    using Service::Service;
    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kCe7BundleCrc32, [&] {
            auto gweuser_only =
                ce7_resolver::PidPredicateForName("GweUser.exe");

            /* Splash thread chain. */
            tm.OnPcFiltered(kPcSplashBlCreateDialog, gweuser_only,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[splash-hs] BL Startup_CreateDialog pTh=0x%08X "
                        "LR=0x%08X SP=0x%08X\n",
                        pcurthd, c.regs[14], c.regs[13]);
                });
            tm.OnPcFiltered(kPcSplashPostCreateDialog, gweuser_only,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[splash-hs] post-CreateDialog pTh=0x%08X "
                        "R0(hwndDlg)=0x%08X\n",
                        pcurthd, c.regs[0]);
                });
            tm.OnPcFiltered(kPcSplashBlEvtShutdownSet, gweuser_only,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[splash-hs] BL EventModify(hShutdown,SET) "
                        "pTh=0x%08X R0(hEvent)=0x%08X R1(func)=%u LR=0x%08X\n",
                        pcurthd, c.regs[0], c.regs[1], c.regs[14]);
                });
            tm.OnPcFiltered(kPcSplashPostEvtShutdownSet, gweuser_only,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[splash-hs] post-EventModify(Shutdown,SET) "
                        "pTh=0x%08X R0(ret)=0x%08X\n",
                        pcurthd, c.regs[0]);
                });
            tm.OnPcFiltered(kPcSplashBlWaitContinueStart, gweuser_only,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[splash-hs] BL WaitForSingleObject(ContinueStartup,INF) "
                        "pTh=0x%08X R0(hHandle)=0x%08X LR=0x%08X\n",
                        pcurthd, c.regs[0], c.regs[14]);
                });
            tm.OnPcFiltered(kPcSplashPostWaitContinueStart, gweuser_only,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[splash-hs] post-wait(ContinueStartup) pTh=0x%08X "
                        "R0(ret)=0x%08X\n",
                        pcurthd, c.regs[0]);
                });

            /* GweUser_StartupScreenSetup_I (Worker A) chain. */
            tm.OnPcFiltered(kPcSetupBlEvtBeginSet, gweuser_only,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[setupI-hs] BL EventModify(hBegin,SET) pTh=0x%08X "
                        "R0(hEvent)=0x%08X R1(func)=%u LR=0x%08X\n",
                        pcurthd, c.regs[0], c.regs[1], c.regs[14]);
                });
            tm.OnPcFiltered(kPcSetupPostEvtBeginSet, gweuser_only,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[setupI-hs] post-EventModify(Begin,SET) pTh=0x%08X "
                        "R0(ret)=0x%08X\n",
                        pcurthd, c.regs[0]);
                });
            tm.OnPcFiltered(kPcSetupBlWaitShutdown, gweuser_only,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[setupI-hs] BL WaitForSingleObject(ContinueShutdown,INF) "
                        "pTh=0x%08X R0(hHandle)=0x%08X LR=0x%08X\n",
                        pcurthd, c.regs[0], c.regs[14]);
                });
            tm.OnPcFiltered(kPcSetupPostWaitShutdown, gweuser_only,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[setupI-hs] post-wait(ContinueShutdown) pTh=0x%08X "
                        "R0(ret)=0x%08X\n",
                        pcurthd, c.regs[0]);
                });
            tm.OnPcFiltered(kPcSetupReturnEpilogue, gweuser_only,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[setupI-hs] return-epilogue pTh=0x%08X R0(ret)=0x%08X "
                        "LR=0x%08X\n",
                        pcurthd, c.regs[0], c.regs[14]);
                });

            /* Startup_CreateDialog internal chain. */
            tm.OnPcFiltered(kPcCdBlFindResource, gweuser_only,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[cd-hs] BL FindResourceW pTh=0x%08X "
                        "R0(hMod)=0x%08X R1(lpName)=0x%08X R2(lpType)=0x%08X "
                        "LR=0x%08X\n",
                        pcurthd, c.regs[0], c.regs[1], c.regs[2], c.regs[14]);
                });
            tm.OnPcFiltered(kPcCdPostFindResource, gweuser_only,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[cd-hs] post-FindResourceW pTh=0x%08X R0(hRsrc)=0x%08X\n",
                        pcurthd, c.regs[0]);
                });
            tm.OnPcFiltered(kPcCdBlLoadResource, gweuser_only,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[cd-hs] BL LoadResource pTh=0x%08X "
                        "R0(hMod)=0x%08X R1(hRsrc)=0x%08X LR=0x%08X\n",
                        pcurthd, c.regs[0], c.regs[1], c.regs[14]);
                });
            tm.OnPcFiltered(kPcCdPostLoadResource, gweuser_only,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[cd-hs] post-LoadResource pTh=0x%08X R0(pRes)=0x%08X\n",
                        pcurthd, c.regs[0]);
                });
            tm.OnPcFiltered(kPcCdBlCreateDialog, gweuser_only,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[cd-hs] BL CreateDialogIndirectParamW pTh=0x%08X "
                        "R0(hInst)=0x%08X R1(pTpl)=0x%08X R2(hParent)=0x%08X "
                        "R3(pDlgProc)=0x%08X LR=0x%08X SP=0x%08X\n",
                        pcurthd, c.regs[0], c.regs[1], c.regs[2], c.regs[3],
                        c.regs[14], c.regs[13]);
                });
            tm.OnPcFiltered(kPcCdPostCreateDialog, gweuser_only,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[cd-hs] post-CreateDialogIndirectParamW pTh=0x%08X "
                        "R0(hwnd)=0x%08X\n",
                        pcurthd, c.regs[0]);
                });

            /* Startup_DlgProc WM_INITDIALOG body chain. */
            tm.OnPcFiltered(kPcDpPostCreateSplash, gweuser_only,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[dp-hs] post-CreateSplash pTh=0x%08X "
                        "R0(hwndSplash)=0x%08X\n",
                        pcurthd, c.regs[0]);
                });
            tm.OnPcFiltered(kPcDpPostSetTimer, gweuser_only,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[dp-hs] post-SetTimer pTh=0x%08X R0(ret)=0x%08X\n",
                        pcurthd, c.regs[0]);
                });
            tm.OnPcFiltered(kPcDpPostSetWindowPos, gweuser_only,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[dp-hs] post-SetWindowPos pTh=0x%08X R0(ret)=0x%08X\n",
                        pcurthd, c.regs[0]);
                });
            tm.OnPcFiltered(kPcDpPostUpdateWindow, gweuser_only,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[dp-hs] post-UpdateWindow pTh=0x%08X R0(ret)=0x%08X\n",
                        pcurthd, c.regs[0]);
                });
            tm.OnPcFiltered(kPcDpPostGetWindowLongW, gweuser_only,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[dp-hs] post-GetWindowLongW pTh=0x%08X R0(ret)=0x%08X\n",
                        pcurthd, c.regs[0]);
                });
            tm.OnPcFiltered(kPcDpPostSetWindowLongW, gweuser_only,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[dp-hs] post-SetWindowLongW pTh=0x%08X R0(ret)=0x%08X\n",
                        pcurthd, c.regs[0]);
                });
            tm.OnPcFiltered(kPcDpInitDialogReturn, gweuser_only,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[dp-hs] WM_INITDIALOG epilogue (R4=1) pTh=0x%08X\n",
                        pcurthd);
                });

            /* CreateSplash inner chain. */
            tm.OnPcFiltered(kPcCsPostRegister, gweuser_only,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[cs-hs] post-StartupSplash::Register pTh=0x%08X "
                        "R0(ret)=0x%08X\n",
                        pcurthd, c.regs[0]);
                });
            tm.OnPcFiltered(kPcCsPostGSM1, gweuser_only,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[cs-hs] post-GetSystemMetrics(1) pTh=0x%08X R0=%d\n",
                        pcurthd, static_cast<int32_t>(c.regs[0]));
                });
            tm.OnPcFiltered(kPcCsPostGSM2, gweuser_only,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[cs-hs] post-GetSystemMetrics(2) pTh=0x%08X R0=%d\n",
                        pcurthd, static_cast<int32_t>(c.regs[0]));
                });
            tm.OnPcFiltered(kPcCsPostCreateWindow, gweuser_only,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[cs-hs] post-CreateWindowExW (StartupSplash) "
                        "pTh=0x%08X R0(hwnd)=0x%08X\n",
                        pcurthd, c.regs[0]);
                });

            /* StartupSplash::WindowProc dispatch path. */
            tm.OnPcFiltered(kPcWpEntry, gweuser_only,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[wp-hs] StartupSplash::WindowProc ENTRY pTh=0x%08X "
                        "hwnd=0x%08X uMsg=0x%X wParam=0x%08X lParam=0x%08X "
                        "LR=0x%08X\n",
                        pcurthd, c.regs[0], c.regs[1], c.regs[2], c.regs[3],
                        c.regs[14]);
                });
            tm.OnPcFiltered(kPcWpBlDefWindowProc, gweuser_only,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[wp-hs] BL DefWindowProcW pTh=0x%08X "
                        "hwnd=0x%08X uMsg=0x%X wParam=0x%08X lParam=0x%08X\n",
                        pcurthd, c.regs[0], c.regs[1], c.regs[2], c.regs[3]);
                });
            tm.OnPcFiltered(kPcWpPostDefWindowProc, gweuser_only,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[wp-hs] post-DefWindowProcW pTh=0x%08X R0(ret)=0x%08X\n",
                        pcurthd, c.regs[0]);
                });
            tm.OnPcFiltered(kPcWpReturn, gweuser_only,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    LOG(Trace,
                        "[wp-hs] WindowProc POP/RET pTh=0x%08X R0(ret)=0x%08X\n",
                        pcurthd, c.regs[0]);
                });
        });
    }
};

REGISTER_SERVICE(TraceCe7SplashHandshakeProbe);

}  /* namespace */

#endif  /* CERF_DEV_MODE */
