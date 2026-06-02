#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "../../jit/arm_mmu_state.h"
#include "ce7_bundle.h"
#include "ce7_process_resolver.h"

#include <cstdint>
#include <unordered_map>

#if CERF_DEV_MODE

namespace {

/* explorer.exe WinMain bisection: process-filtered (FCSE-immune)
   hooks across the 5 points between WinMain entry and MessageLoop.
   Each one's fire/no-fire under explorer's TTBR0 narrows where the
   primary thread stops. */
constexpr uint32_t kPcWinMainEntry        = 0x000141F0u;
constexpr uint32_t kPcLoadConfigCall      = 0x000113ECu;  /* BL LoadConfiguration */
constexpr uint32_t kPcLoadConfigRet       = 0x000113F0u;  /* PC right after BL */
constexpr uint32_t kPcCDesktopWndCreate   = 0x000162C8u;
constexpr uint32_t kPcCDesktopWndRetSite  = 0x0001440Cu;  /* PC after CDesktopWnd::Create call */
constexpr uint32_t kPcCreateEventW        = 0x00014428u;
constexpr uint32_t kPcCreateThread        = 0x00014454u;
constexpr uint32_t kPcWaitForSyncCall     = 0x00014468u;
constexpr uint32_t kPcSendMessageW        = 0x0001448Cu;
constexpr uint32_t kPcSignalStartedCall   = 0x0001449Cu;
constexpr uint32_t kPcDoStartupTasksCall  = 0x000144E0u;
constexpr uint32_t kPcSndPlaySoundCall    = 0x00014534u;
constexpr uint32_t kPcMessageLoopEntry    = 0x00014540u;

/* CDesktopWnd::Create internal chain. */
constexpr uint32_t kPcCDWSHGetCall        = 0x000162D8u;  /* BL SHGetDesktopFolder */
constexpr uint32_t kPcCDWSHGetRet         = 0x000162DCu;
constexpr uint32_t kPcCDWCreateViewObj    = 0x00016304u;  /* BLX CreateViewObject */
constexpr uint32_t kPcCDWCreateViewObjRet = 0x00016308u;
constexpr uint32_t kPcCDWGetSysMetricsH   = 0x00016334u;
constexpr uint32_t kPcCDWGetSysMetricsW   = 0x00016340u;
constexpr uint32_t kPcCDWSetRectRet       = 0x00016358u;
constexpr uint32_t kPcCDWCreateViewWnd    = 0x00016380u;  /* BLX CreateViewWindow */
constexpr uint32_t kPcCDWCreateViewWndRet = 0x00016384u;
constexpr uint32_t kPcCDWRegisterDesktop  = 0x0001639Cu;
constexpr uint32_t kPcCDWRegDesktopRet    = 0x000163A0u;
constexpr uint32_t kPcCDWSuccessRet       = 0x000163D8u;
constexpr uint32_t kPcCDWFailureRet       = 0x000163E4u;

/* CDesktopView::CreateViewWindow internal BL sites (ceshell.dll, kernel-VA). */
constexpr uint32_t kPcCvwGetClassInfoCall  = 0x4231BCE0u;  /* BL GetClassInfoW_0 */
constexpr uint32_t kPcCvwRegClassCall      = 0x4231BD40u;  /* BL RegisterClassW_0 */
constexpr uint32_t kPcCvwCreateWindowCall  = 0x4231BDE8u;  /* BL CreateWindowExW_0 */
constexpr uint32_t kPcCvwCreateWindowRet   = 0x4231BDECu;  /* PC after BL */
constexpr uint32_t kPcCvwAddRefBlx         = 0x4231BE04u;  /* BLX R3 (AddRef) */
constexpr uint32_t kPcCvwSetViewModeBlx    = 0x4231BE18u;  /* BLX R3 (SetViewMode) */
constexpr uint32_t kPcCvwSetWndLongCall    = 0x4231BE34u;  /* BL SetWindowLongW_0 */
constexpr uint32_t kPcCvwEnableRedrawCall  = 0x4231BE50u;  /* BL EnableRedraw */
constexpr uint32_t kPcCvwSetRedrawBlx      = 0x4231BE64u;  /* BLX R3 (SetRedraw) */
constexpr uint32_t kPcCvwHandleSettingBlx  = 0x4231BED4u;  /* BLX R3 (HandleSettingChange(this,20,0)) */
constexpr uint32_t kPcCvwHandleSettingRet  = 0x4231BED8u;  /* PC after HandleSettingChange BLX */
constexpr uint32_t kPcCvwShowWindowCall    = 0x4231BEE0u;  /* BL ShowWindow_0(*phwnd, SW_SHOW) */
constexpr uint32_t kPcCvwShowWindowRet     = 0x4231BEE4u;  /* PC after BL ShowWindow_0 */
constexpr uint32_t kPcCvwFuncReturn        = 0x4231BEECu;  /* POP {R4-R11,PC} success epilogue */
constexpr uint32_t kPcGwesShowWindowI      = 0xEFD9F4C4u;  /* CWindow::ShowWindow_I entry */
constexpr uint32_t kPcGwesSetWindowPosI    = 0xEFD9E200u;  /* CWindow::SetWindowPos_I entry */
constexpr uint32_t kPcGwesSendSizeMoveMsgs = 0xEFD9A2B8u;  /* CWindow::SendSizeMoveMsgs entry */
constexpr uint32_t kPcGwesSetWindowPosWorker = 0xEFD9B698u;  /* CWindow::SetWindowPosWorker entry */
constexpr uint32_t kPcGwesOwnerOwnedGroupWindowList = 0xEFD86540u;  /* CWindowManager::OwnerOwnedGroupWindowList */
constexpr uint32_t kPcKernelDoWaitWithWaitStruct = 0x8C050714u;  /* kernel.dll DoWaitWithWaitStruct */
constexpr uint32_t kPcKernelNKExitThread = 0x8C042DCCu;  /* kernel.dll NKExitThread */
constexpr uint32_t kPcCoredllMsgWaitForMultipleObjectsEx = 0x40020F2Cu;
constexpr uint32_t kPcKernelNKSleep = 0x8C05046Cu;
constexpr uint32_t kPcKernelNKSleepTillTick = 0x8C050530u;
constexpr uint32_t kPcKernelMDCallUserHAPI = 0x8C035958u;
constexpr uint32_t kPcKernelLockServerWithId = 0x8C05E258u;
constexpr uint32_t kPcKernelSetupCallToUserServer = 0x8C060494u;

/* WM_SETREDRAW dispatch chain. */
constexpr uint32_t kPcSetRedrawEntry       = 0x42320830u;  /* CShellListView::SetRedraw */
constexpr uint32_t kPcSendMessageWThunk    = 0x4232CD54u;  /* ceshell SendMessageW_0 thunk */
constexpr uint32_t kPcSubclassProcEntry    = 0x4231BB50u;  /* CDesktopView::SubclassProc */
constexpr uint32_t kPcXxxWaitSingleEntry   = 0xEFF69D9Cu;  /* k.coredll!xxx_WaitForSingleObject — verified via IDA */

/* commctrl.dll listview WndProc internals for LVM_ARRANGE(msg=0x1016)
   chain. User-mode shared mapping (0x40xxxxxx) — MUST be filtered. */
constexpr uint32_t kPcListViewOnArrange     = 0x406FCA34u;
constexpr uint32_t kPcListViewCommonArrange = 0x406FC0C4u;
constexpr uint32_t kPcListViewCommonArrangeEx    = 0x406FBDE4u;
constexpr uint32_t kPcListViewCommonArrangeGroup = 0x406FAB40u;
constexpr uint32_t kPcCalcSlotRect          = 0x406F7F48u;
constexpr uint32_t kPcListViewSetIconPos    = 0x406F9FB8u;
constexpr uint32_t kPcListViewGetSlotCountEx = 0x406F9798u;
constexpr uint32_t kPcGetSlotCountExPostGetClient = 0x406F9868u;
constexpr uint32_t kPcMsgQueueSendMessageWithOptions = 0xEFD71B3Cu;

class TraceCe7ExplorerWmBisect : public Service {
public:
    using Service::Service;
    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kCe7BundleCrc32, [&] {
            auto expl_only = ce7_resolver::PidPredicateForName("explorer.exe");

            tm.OnPcFiltered(kPcWinMainEntry, expl_only,
                [](const TraceContext& c) {
                    LOG(Trace, "[wm] explorer WinMain entry "
                        "hInst=0x%08X cmd=0x%08X LR=0x%08X SP=0x%08X\n",
                        c.regs[0], c.regs[2], c.regs[14], c.regs[13]);
                });
            tm.OnPcFiltered(kPcLoadConfigCall, expl_only,
                [](const TraceContext& c) {
                    LOG(Trace, "[wm] explorer LoadConfiguration CALL "
                        "LR=0x%08X SP=0x%08X\n", c.regs[14], c.regs[13]);
                });
            tm.OnPcFiltered(kPcLoadConfigRet, expl_only,
                [](const TraceContext& c) {
                    LOG(Trace, "[wm] explorer LoadConfiguration RET R0=0x%08X "
                        "LR=0x%08X SP=0x%08X\n",
                        c.regs[0], c.regs[14], c.regs[13]);
                });
            tm.OnPcFiltered(kPcCDesktopWndCreate, expl_only,
                [](const TraceContext& c) {
                    LOG(Trace, "[wm] explorer CDesktopWnd::Create CALL "
                        "this=0x%08X LR=0x%08X SP=0x%08X\n",
                        c.regs[0], c.regs[14], c.regs[13]);
                });
            tm.OnPcFiltered(kPcCDesktopWndRetSite, expl_only,
                [](const TraceContext& c) {
                    LOG(Trace, "[wm] explorer CDesktopWnd::Create RET site "
                        "R0=0x%08X LR=0x%08X SP=0x%08X\n",
                        c.regs[0], c.regs[14], c.regs[13]);
                });
            tm.OnPcFiltered(kPcCreateEventW, expl_only,
                [](const TraceContext& c) {
                    LOG(Trace, "[wm] explorer CreateEventW CALL LR=0x%08X SP=0x%08X\n",
                        c.regs[14], c.regs[13]);
                });
            tm.OnPcFiltered(kPcCreateThread, expl_only,
                [](const TraceContext& c) {
                    LOG(Trace, "[wm] explorer CreateThread CALL "
                        "start=0x%08X param=0x%08X LR=0x%08X SP=0x%08X\n",
                        c.regs[2], c.regs[3], c.regs[14], c.regs[13]);
                });
            tm.OnPcFiltered(kPcWaitForSyncCall, expl_only,
                [](const TraceContext& c) {
                    LOG(Trace, "[wm] explorer WaitForSingleObject(TaskbarSync) "
                        "hHandle=0x%08X timeout=0x%08X LR=0x%08X SP=0x%08X\n",
                        c.regs[0], c.regs[1], c.regs[14], c.regs[13]);
                });
            tm.OnPcFiltered(kPcSendMessageW, expl_only,
                [](const TraceContext& c) {
                    LOG(Trace, "[wm] explorer SendMessageW(SETTINGCHANGE) "
                        "hwnd=0x%08X LR=0x%08X SP=0x%08X\n",
                        c.regs[0], c.regs[14], c.regs[13]);
                });

            tm.OnPcFiltered(kPcSignalStartedCall, expl_only,
                [](const TraceContext& c) {
                    LOG(Trace, "[wm] explorer SignalStarted CALL "
                        "R0=0x%08X LR=0x%08X SP=0x%08X\n",
                        c.regs[0], c.regs[14], c.regs[13]);
                });

            tm.OnPcFiltered(kPcDoStartupTasksCall, expl_only,
                [](const TraceContext& c) {
                    LOG(Trace, "[wm] explorer DoStartupTasks CALL "
                        "R0=0x%08X LR=0x%08X SP=0x%08X\n",
                        c.regs[0], c.regs[14], c.regs[13]);
                });

            tm.OnPcFiltered(kPcSndPlaySoundCall, expl_only,
                [](const TraceContext& c) {
                    LOG(Trace, "[wm] explorer sndPlaySoundW CALL "
                        "R0=0x%08X R1=0x%08X LR=0x%08X SP=0x%08X\n",
                        c.regs[0], c.regs[1], c.regs[14], c.regs[13]);
                });

            tm.OnPcFiltered(kPcMessageLoopEntry, expl_only,
                [](const TraceContext& c) {
                    LOG(Trace, "[wm] explorer MessageLoop entry "
                        "LR=0x%08X SP=0x%08X\n",
                        c.regs[14], c.regs[13]);
                });

            tm.OnPcFiltered(kPcCDWSHGetCall, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[cdw] SHGetDesktopFolder CALL  R0=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[14]);
            });
            tm.OnPcFiltered(kPcCDWSHGetRet, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[cdw] SHGetDesktopFolder RET  R0=0x%08X\n", c.regs[0]);
            });
            tm.OnPcFiltered(kPcCDWCreateViewObj, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[cdw] CreateViewObject CALL  R0(pSHF)=0x%08X R4(vtbl[8])=0x%08X R3(&_psv)=0x%08X\n",
                    c.regs[0], c.regs[4], c.regs[3]);
            });
            tm.OnPcFiltered(kPcCDWCreateViewObjRet, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[cdw] CreateViewObject RET  R0=0x%08X\n", c.regs[0]);
            });
            tm.OnPcFiltered(kPcCDWGetSysMetricsH, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[cdw] GetSystemMetrics(VIRT_H) RET  R0=%u\n", c.regs[0]);
            });
            tm.OnPcFiltered(kPcCDWGetSysMetricsW, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[cdw] GetSystemMetrics(VIRT_W) RET  R0=%u\n", c.regs[0]);
            });
            tm.OnPcFiltered(kPcCDWSetRectRet, expl_only, [](const TraceContext&) {
                LOG(Trace, "[cdw] SetRect RET\n");
            });
            tm.OnPcFiltered(kPcCDWCreateViewWnd, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[cdw] CreateViewWindow CALL  this=0x%08X rect=0x%08X "
                    "phWnd=0x%08X R4(target)=0x%08X R12=0x%08X\n",
                    c.regs[0], c.regs[3], c.regs[2], c.regs[4], c.regs[12]);
            });
            tm.OnPcFiltered(kPcCDWCreateViewWndRet, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[cdw] CreateViewWindow RET  R0=0x%08X\n", c.regs[0]);
            });
            tm.OnPcFiltered(kPcCDWRegisterDesktop, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[cdw] RegisterDesktop CALL  hWnd=0x%08X\n", c.regs[0]);
            });
            tm.OnPcFiltered(kPcCDWRegDesktopRet, expl_only, [](const TraceContext&) {
                LOG(Trace, "[cdw] RegisterDesktop RET\n");
            });
            tm.OnPcFiltered(kPcCDWSuccessRet, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[cdw] success POP/RET R0=0x%08X\n", c.regs[0]);
            });
            tm.OnPcFiltered(kPcCDWFailureRet, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[cdw] failure POP/RET R0=0x%08X\n", c.regs[0]);
            });

            tm.OnPcFiltered(kPcCvwGetClassInfoCall, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[cvw] BL GetClassInfoW_0  R0=0x%08X R1=0x%08X\n", c.regs[0], c.regs[1]);
            });
            tm.OnPcFiltered(kPcCvwRegClassCall, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[cvw] BL RegisterClassW_0  R0=0x%08X\n", c.regs[0]);
            });
            tm.OnPcFiltered(kPcCvwCreateWindowCall, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[cvw] BL CreateWindowExW_0  dwExStyle=R0=0x%08X lpClass=R1=0x%08X\n",
                    c.regs[0], c.regs[1]);
            });
            tm.OnPcFiltered(kPcCvwCreateWindowRet, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[cvw] CreateWindowExW_0 RET  R0(hwnd)=0x%08X\n", c.regs[0]);
            });
            tm.OnPcFiltered(kPcCvwAddRefBlx, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[cvw] BLX AddRef  R0=0x%08X R3(target)=0x%08X\n", c.regs[0], c.regs[3]);
            });
            tm.OnPcFiltered(kPcCvwSetViewModeBlx, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[cvw] BLX SetViewMode  R0=0x%08X R3(target)=0x%08X\n", c.regs[0], c.regs[3]);
            });
            tm.OnPcFiltered(kPcCvwSetWndLongCall, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[cvw] BL SetWindowLongW_0  R0=0x%08X R1=0x%08X\n", c.regs[0], c.regs[1]);
            });
            tm.OnPcFiltered(kPcCvwEnableRedrawCall, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[cvw] BL EnableRedraw  R0=0x%08X R1=%u\n", c.regs[0], c.regs[1]);
            });
            tm.OnPcFiltered(kPcCvwSetRedrawBlx, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[cvw] BLX SetRedraw  R0=0x%08X R3(target)=0x%08X\n", c.regs[0], c.regs[3]);
            });
            tm.OnPcFiltered(kPcCvwHandleSettingBlx, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[cvw] BLX HandleSettingChange(this=0x%08X, %u, %u)  R3(target)=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[3]);
            });
            tm.OnPcFiltered(kPcCvwHandleSettingRet, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[cvw] HandleSettingChange RET  R0=0x%08X\n", c.regs[0]);
            });
            tm.OnPcFiltered(kPcCvwShowWindowCall, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[cvw] BL ShowWindow_0(hwnd=0x%08X, nCmdShow=%u)\n",
                    c.regs[0], c.regs[1]);
            });
            tm.OnPcFiltered(kPcCvwShowWindowRet, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[cvw] ShowWindow_0 RET  R0=0x%08X\n", c.regs[0]);
            });
            tm.OnPcFiltered(kPcCvwFuncReturn, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[cvw] CreateViewWindow EPILOGUE  R0(hr)=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[14]);
            });
            tm.OnPcFiltered(kPcGwesShowWindowI, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[gwes] ShowWindow_I ENTRY hwndThis=0x%08X nCmdShow=%d LR=0x%08X SP=0x%08X\n",
                    c.regs[0], static_cast<int32_t>(c.regs[1]), c.regs[14], c.regs[13]);
            });
            tm.OnPcFiltered(kPcGwesSendSizeMoveMsgs, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[gwes] SendSizeMoveMsgs ENTRY this=0x%08X LR=0x%08X SP=0x%08X\n",
                    c.regs[0], c.regs[14], c.regs[13]);
            });
            tm.OnPcFiltered(kPcGwesSetWindowPosI, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[gwes] SetWindowPos_I ENTRY hwnd=0x%08X hwndAfter=0x%08X x=%d y=%d cx=%d cy=%d "
                    "uFlags(stack)=0x%08X LR=0x%08X SP=0x%08X\n",
                    c.regs[0], c.regs[1],
                    static_cast<int32_t>(c.regs[2]), static_cast<int32_t>(c.regs[3]),
                    static_cast<int32_t>(c.ReadVa32(c.regs[13]).value_or(0xDEADBEEFu)),
                    static_cast<int32_t>(c.ReadVa32(c.regs[13] + 4).value_or(0xDEADBEEFu)),
                    c.ReadVa32(c.regs[13] + 8).value_or(0xDEADBEEFu),
                    c.regs[14], c.regs[13]);
            });
            tm.OnPcFiltered(kPcGwesSetWindowPosWorker, expl_only, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count > 50 && (count % 100u) != 0u) return;
                LOG(Trace, "[gwes] SetWindowPosWorker #%u ENTRY this=0x%08X hwndAfter=0x%08X "
                    "pwndAfter=0x%08X x=%d y=%d uFlags(stack)=0x%08X LR=0x%08X\n",
                    count, c.regs[0], c.regs[1], c.regs[2],
                    static_cast<int32_t>(c.regs[3]),
                    static_cast<int32_t>(c.ReadVa32(c.regs[13]).value_or(0xDEADBEEFu)),
                    c.ReadVa32(c.regs[13] + 8).value_or(0xDEADBEEFu),
                    c.regs[14]);
            });
            tm.OnPcFiltered(kPcGwesOwnerOwnedGroupWindowList, expl_only, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count > 30 && (count % 100u) != 0u) return;
                LOG(Trace, "[gwes] OwnerOwnedGroupWindowList #%u ENTRY pWindow=0x%08X LR=0x%08X\n",
                    count, c.regs[0], c.regs[14]);
            });
            tm.OnPcFiltered(kPcKernelDoWaitWithWaitStruct, expl_only, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                const uint32_t pws = c.regs[0];
                uint32_t w[12];
                for (int i = 0; i < 12; ++i)
                    w[i] = c.ReadVa32(pws + i * 4u).value_or(0xDEADBEEFu);
                LOG(Trace, "[kern] DoWaitWithWaitStruct #%u pws=0x%08X LR=0x%08X SP=0x%08X "
                    "ws[0..11]={0x%08X 0x%08X 0x%08X 0x%08X 0x%08X 0x%08X 0x%08X 0x%08X 0x%08X 0x%08X 0x%08X 0x%08X}\n",
                    count, pws, c.regs[14], c.regs[13],
                    w[0], w[1], w[2], w[3], w[4], w[5], w[6], w[7], w[8], w[9], w[10], w[11]);
            });
            tm.OnPcFiltered(kPcKernelNKExitThread, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[kern] NKExitThread ENTRY pTh=0x%08X dwExitCode=0x%08X LR=0x%08X SP=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[14], c.regs[13]);
            });
            tm.OnPcFiltered(kPcCoredllMsgWaitForMultipleObjectsEx, expl_only, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                uint32_t h0 = c.ReadVa32(c.regs[1]).value_or(0xDEADBEEFu);
                LOG(Trace, "[wait] MsgWaitForMultipleObjectsEx #%u cObjs=%u pHandles=0x%08X h0=0x%08X dwMs=%u dwWakeMask=0x%08X LR=0x%08X SP=0x%08X\n",
                    count, c.regs[0], c.regs[1], h0, c.regs[2], c.regs[3], c.regs[14], c.regs[13]);
            });
            tm.OnPcFiltered(kPcKernelNKSleep, expl_only, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count > 30 && (count % 100u) != 0u) return;
                LOG(Trace, "[wait] NKSleep #%u dwMs=%u LR=0x%08X\n",
                    count, c.regs[0], c.regs[14]);
            });
            tm.OnPcFiltered(kPcKernelNKSleepTillTick, expl_only, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count > 30 && (count % 100u) != 0u) return;
                LOG(Trace, "[wait] NKSleepTillTick #%u LR=0x%08X\n",
                    count, c.regs[14]);
            });
            tm.OnPcFiltered(kPcKernelMDCallUserHAPI, expl_only, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                const uint32_t phd = c.regs[0];
                const uint32_t phc = c.regs[1];
                uint32_t h[8], p[8];
                for (int i = 0; i < 8; ++i) {
                    h[i] = c.ReadVa32(phd + i * 4u).value_or(0xDEADBEEFu);
                    p[i] = c.ReadVa32(phc + i * 4u).value_or(0xDEADBEEFu);
                }
                LOG(Trace, "[hapi] MDCallUserHAPI #%u phd=0x%08X phc=0x%08X LR=0x%08X SP=0x%08X "
                    "phd[0..7]={%08X %08X %08X %08X %08X %08X %08X %08X} "
                    "phc[0..7]={%08X %08X %08X %08X %08X %08X %08X %08X}\n",
                    count, phd, phc, c.regs[14], c.regs[13],
                    h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7],
                    p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
            });
            tm.OnPcFiltered(kPcKernelLockServerWithId, expl_only, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                LOG(Trace, "[hapi] LockServerWithId #%u dwProcId=0x%08X LR=0x%08X SP=0x%08X\n",
                    count, c.regs[0], c.regs[14], c.regs[13]);
            });
            tm.OnPc(kPcKernelLockServerWithId, [](const TraceContext& c) {
                if (c.regs[0] != 0x01C80012u) return;
                static uint32_t count = 0;
                ++count;
                auto& mmu = c.emu.Get<ArmMmu>();
                const uint32_t ttbr = mmu.State()->translation_table_base.word
                                    & 0xFFFFC000u;
                const uint32_t pcurthd = c.ReadVa32(0xFFFFC824u).value_or(0xDEADBEEFu);
                LOG(Trace, "[hapi-tgt0x01C80012] #%u TTBR0=0x%08X PCURTHD=0x%08X LR=0x%08X SP=0x%08X\n",
                    count, ttbr, pcurthd, c.regs[14], c.regs[13]);
            });
            tm.OnPcFiltered(0x8C0605F8u, expl_only, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                LOG(Trace, "[hapi-post-LSWI-0x8C0605F8] #%u R0=0x%08X LR=0x%08X SP=0x%08X\n",
                    count, c.regs[0], c.regs[14], c.regs[13]);
            });
            tm.OnPcFiltered(0x8C060070u, expl_only, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count > 30 && (count % 500u) != 0u) return;
                LOG(Trace, "[hapi-post-LSWI-0x8C060070] #%u R0=0x%08X LR=0x%08X SP=0x%08X\n",
                    count, c.regs[0], c.regs[14], c.regs[13]);
            });
            tm.OnPcFiltered(kPcKernelSetupCallToUserServer, expl_only, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                const uint32_t phd = c.regs[0];
                const uint32_t phc = c.regs[1];
                uint32_t h0 = c.ReadVa32(phd +  0u).value_or(0xDEADBEEFu);
                uint32_t h1 = c.ReadVa32(phd +  4u).value_or(0xDEADBEEFu);
                uint32_t h2 = c.ReadVa32(phd +  8u).value_or(0xDEADBEEFu);
                uint32_t h3 = c.ReadVa32(phd + 12u).value_or(0xDEADBEEFu);
                uint32_t p0 = c.ReadVa32(phc +  0u).value_or(0xDEADBEEFu);
                uint32_t p1 = c.ReadVa32(phc +  4u).value_or(0xDEADBEEFu);
                LOG(Trace, "[hapi] SetupCallToUserServer #%u phd=0x%08X phc=0x%08X LR=0x%08X SP=0x%08X "
                    "phd[0..3]={%08X %08X %08X %08X} phc[0..1]={%08X %08X}\n",
                    count, phd, phc, c.regs[14], c.regs[13],
                    h0, h1, h2, h3, p0, p1);
            });

            tm.OnPcFiltered(kPcSetRedrawEntry, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[smr] SetRedraw ENTRY this=0x%08X fRedraw=%d LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[14]);
            });
            tm.OnPcFiltered(kPcSendMessageWThunk, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[smr] SendMessageW thunk CALL hwnd=0x%08X msg=0x%X wParam=0x%08X lParam=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[3], c.regs[14]);
            });
            tm.OnPcFiltered(kPcSubclassProcEntry, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[smr] SubclassProc ENTRY hwnd=0x%08X msg=0x%X wParam=0x%08X lParam=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[3], c.regs[14]);
            });
            tm.OnPcFiltered(kPcXxxWaitSingleEntry, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[smr] xxx_WaitForSingleObject ENTRY hHandle=0x%08X dwMs=0x%08X LR=0x%08X SP=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[14], c.regs[13]);
            });

            tm.OnPcFiltered(kPcListViewOnArrange, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[lva] ListView_OnArrange ENTRY plv=0x%08X style=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[14]);
            });
            tm.OnPcFiltered(kPcListViewCommonArrange, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[lva] ListView_CommonArrange ENTRY plv=0x%08X style=0x%08X dpa=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[14]);
            });
            tm.OnPcFiltered(kPcListViewCommonArrangeEx, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[lva] ListView_CommonArrangeEx ENTRY plv=0x%08X style=0x%08X dpa=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[14]);
            });
            tm.OnPcFiltered(kPcListViewCommonArrangeGroup, expl_only, [](const TraceContext& c) {
                LOG(Trace, "[lva] ListView_CommonArrangeGroup ENTRY plv=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[14]);
            });
            tm.OnPcFiltered(kPcListViewGetSlotCountEx, expl_only, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count > 30 && (count % 1000u) != 0u) return;
                const uint32_t plv      = c.regs[0];
                const uint32_t flags1c  = c.ReadVa32(plv + 0x1Cu).value_or(0xDEADBEEFu);
                const uint32_t cistyle  = c.ReadVa32(plv + 0x08u).value_or(0xDEADBEEFu);
                const uint32_t cx       = c.ReadVa32(plv + 0x70u).value_or(0xDEADBEEFu);
                const uint32_t cy       = c.ReadVa32(plv + 0x74u).value_or(0xDEADBEEFu);
                const uint32_t nWA      = c.ReadVa32(plv + 0x78u).value_or(0xDEADBEEFu);
                const uint32_t bL       = c.ReadVa32(plv + 0x228u).value_or(0xDEADBEEFu);
                const uint32_t bT       = c.ReadVa32(plv + 0x22Cu).value_or(0xDEADBEEFu);
                const uint32_t bR       = c.ReadVa32(plv + 0x230u).value_or(0xDEADBEEFu);
                const uint32_t bB       = c.ReadVa32(plv + 0x234u).value_or(0xDEADBEEFu);
                const uint32_t pL       = c.ReadVa32(plv + 0x254u).value_or(0xDEADBEEFu);
                const uint32_t pT       = c.ReadVa32(plv + 0x258u).value_or(0xDEADBEEFu);
                const uint32_t pR       = c.ReadVa32(plv + 0x25Cu).value_or(0xDEADBEEFu);
                const uint32_t pB       = c.ReadVa32(plv + 0x260u).value_or(0xDEADBEEFu);
                LOG(Trace, "[lva] ListView_GetSlotCountEx ENTRY #%u plv=0x%08X fWoSB=%d iWA=%d "
                    "flags1c=0x%08X(fGroupView=%u) ci.style=0x%08X sizeClient=(%u,%u) nWA=%d "
                    "rcBorder=(%d,%d,%d,%d) padding=(%u,%u,%u,%u) LR=0x%08X\n",
                    count, plv, c.regs[1], c.regs[2],
                    flags1c, (flags1c >> 5) & 1u, cistyle, cx, cy,
                    static_cast<int32_t>(nWA),
                    static_cast<int32_t>(bL), static_cast<int32_t>(bT),
                    static_cast<int32_t>(bR), static_cast<int32_t>(bB),
                    pL, pT, pR, pB, c.regs[14]);
            });
            tm.OnPcFiltered(kPcGetSlotCountExPostGetClient, expl_only, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count > 30 && (count % 1000u) != 0u) return;
                LOG(Trace, "[lva] GetSlotCountEx post-GetClientRect #%u "
                    "rcClientNoSB=(L=%d T=%d R=%d B=%d) v11(iWidth)=%d v12(iHeight)=%d LR=0x%08X\n",
                    count,
                    static_cast<int32_t>(c.regs[2]), static_cast<int32_t>(c.regs[3]),
                    static_cast<int32_t>(c.regs[0]), static_cast<int32_t>(c.regs[1]),
                    static_cast<int32_t>(c.regs[5]), static_cast<int32_t>(c.regs[4]),
                    c.regs[14]);
            });
            tm.OnPcFiltered(kPcCalcSlotRect, expl_only, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count <= 30 || (count % 5000u) == 0u) {
                    LOG(Trace, "[lva] _CalcSlotRect #%u plv=0x%08X pItem=0x%08X iSlot=%d cSlot=%d iWidth=%d iHeight=%d LR=0x%08X\n",
                        count, c.regs[0], c.regs[1],
                        static_cast<int32_t>(c.regs[2]), static_cast<int32_t>(c.regs[3]),
                        static_cast<int32_t>(c.ReadVa32(c.regs[13] + 0).value_or(0xDEADBEEFu)),
                        static_cast<int32_t>(c.ReadVa32(c.regs[13] + 4).value_or(0xDEADBEEFu)),
                        c.regs[14]);
                }
            });
            tm.OnPcFiltered(kPcListViewSetIconPos, expl_only, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count <= 30 || (count % 1000u) == 0u) {
                    LOG(Trace, "[lva] ListView_SetIconPos #%u plv=0x%08X pItem=0x%08X iSlot=%d cSlot=%d LR=0x%08X\n",
                        count, c.regs[0], c.regs[1],
                        static_cast<int32_t>(c.regs[2]), static_cast<int32_t>(c.regs[3]), c.regs[14]);
                }
            });
            tm.OnPcFiltered(kPcMsgQueueSendMessageWithOptions, expl_only, [](const TraceContext& c) {
                static uint32_t count = 0;
                static uint32_t wm_notify_to_fe130 = 0;
                static uint32_t wm_size_total = 0;
                static uint32_t wm_size_to_fe140 = 0;
                static uint32_t wm_wpc_to_fe140 = 0;
                static uint32_t wm_wpcing_to_fe140 = 0;
                ++count;
                const uint32_t hwnd = c.regs[0];
                const uint32_t msg  = c.regs[1];
                const uint32_t wp   = c.regs[2];
                const uint32_t lp   = c.regs[3];

                if (msg == 0x0005u) {
                    ++wm_size_total;
                    const uint32_t cx = lp & 0xFFFFu;
                    const uint32_t cy = (lp >> 16) & 0xFFFFu;
                    if (hwnd == 0xFE140002u) {
                        ++wm_size_to_fe140;
                        LOG(Trace, "[wm-size] *** SMWO WM_SIZE -> 0xFE140002 #%u "
                            "wParam=0x%X cx=%u cy=%u LR=0x%08X\n",
                            wm_size_to_fe140, wp, cx, cy, c.regs[14]);
                    } else if (wm_size_total <= 30 || (wm_size_total % 50u) == 0u) {
                        LOG(Trace, "[wm-size] SMWO WM_SIZE #%u hwnd=0x%08X "
                            "wParam=0x%X cx=%u cy=%u LR=0x%08X\n",
                            wm_size_total, hwnd, wp, cx, cy, c.regs[14]);
                    }
                    return;
                }

                if (msg == 0x0047u && hwnd == 0xFE140002u) {
                    ++wm_wpc_to_fe140;
                    uint32_t wp_hwnd  = c.ReadVa32(lp +  0).value_or(0xDEADBEEFu);
                    uint32_t wp_after = c.ReadVa32(lp +  4).value_or(0xDEADBEEFu);
                    uint32_t wp_x     = c.ReadVa32(lp +  8).value_or(0xDEADBEEFu);
                    uint32_t wp_y     = c.ReadVa32(lp + 12).value_or(0xDEADBEEFu);
                    uint32_t wp_cx    = c.ReadVa32(lp + 16).value_or(0xDEADBEEFu);
                    uint32_t wp_cy    = c.ReadVa32(lp + 20).value_or(0xDEADBEEFu);
                    uint32_t wp_flags = c.ReadVa32(lp + 24).value_or(0xDEADBEEFu);
                    LOG(Trace, "[wm-wpc] *** SMWO WM_WINDOWPOSCHANGED -> 0xFE140002 #%u "
                        "WINDOWPOS{hwnd=0x%08X after=0x%08X x=%d y=%d cx=%d cy=%d flags=0x%08X} LR=0x%08X\n",
                        wm_wpc_to_fe140, wp_hwnd, wp_after,
                        static_cast<int32_t>(wp_x), static_cast<int32_t>(wp_y),
                        static_cast<int32_t>(wp_cx), static_cast<int32_t>(wp_cy),
                        wp_flags, c.regs[14]);
                    return;
                }

                if (msg == 0x0046u && hwnd == 0xFE140002u) {
                    ++wm_wpcing_to_fe140;
                    uint32_t wp_cx    = c.ReadVa32(lp + 16).value_or(0xDEADBEEFu);
                    uint32_t wp_cy    = c.ReadVa32(lp + 20).value_or(0xDEADBEEFu);
                    uint32_t wp_flags = c.ReadVa32(lp + 24).value_or(0xDEADBEEFu);
                    LOG(Trace, "[wm-wpcing] *** SMWO WM_WINDOWPOSCHANGING -> 0xFE140002 #%u "
                        "WINDOWPOS{cx=%d cy=%d flags=0x%08X} LR=0x%08X\n",
                        wm_wpcing_to_fe140,
                        static_cast<int32_t>(wp_cx), static_cast<int32_t>(wp_cy),
                        wp_flags, c.regs[14]);
                    return;
                }

                /* msg=0x4E = WM_NOTIFY; lParam points at NMHDR; +0x8 = code. */
                if (msg == 0x4Eu && hwnd == 0xFE130002u) {
                    ++wm_notify_to_fe130;
                    if (wm_notify_to_fe130 <= 30 || (wm_notify_to_fe130 % 500u) == 0u) {
                        uint32_t nm_hwnd  = c.ReadVa32(lp + 0).value_or(0xDEADBEEFu);
                        uint32_t nm_idfrom = c.ReadVa32(lp + 4).value_or(0xDEADBEEFu);
                        uint32_t nm_code   = c.ReadVa32(lp + 8).value_or(0xDEADBEEFu);
                        LOG(Trace, "[sm-nm] WM_NOTIFY #%u → 0xFE130002 NMHDR{hwndFrom=0x%08X idFrom=0x%08X code=0x%08X (%d)} LR=0x%08X\n",
                            wm_notify_to_fe130, nm_hwnd, nm_idfrom, nm_code, static_cast<int32_t>(nm_code), c.regs[14]);
                    }
                    return;
                }
                if (count <= 100 || (count % 200u) == 0u) {
                    LOG(Trace, "[sm] SMWO #%u hwnd=0x%08X msg=0x%X wParam=0x%08X lParam=0x%08X LR=0x%08X\n",
                        count, hwnd, msg, wp, lp, c.regs[14]);
                }
            });
            /* User-mode wrapper xxx_WaitForMultipleObjects @ 0x40029FA8
               in coredll.dll — IDA-verified. Captures LR (= the caller
               in explorer's address space). */
            tm.OnPcFiltered(0x40029FA8u, expl_only, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count <= 30 || (count % 1000u) == 0u) {
                    uint32_t h0 = c.ReadVa32(c.regs[1]).value_or(0xDEADBEEFu);
                    uint32_t h1 = c.regs[0] >= 2 ? c.ReadVa32(c.regs[1] + 4u).value_or(0xDEADBEEFu) : 0;
                    LOG(Trace, "[wfm-um] xxx_WaitForMultipleObjects #%u cObjs=%u "
                        "h0=0x%08X h1=0x%08X fWaitAll=%u dwMs=%u LR=0x%08X SP=0x%08X\n",
                        count, c.regs[0], h0, h1, c.regs[2], c.regs[3],
                        c.regs[14], c.regs[13]);
                }
            });

            /* NKWaitForMultipleObjects entry @ 0x8C050B30 — IDA-verified
               function start in kernel.dll. Captures cObjs/h0/Timeout. */
            tm.OnPcFiltered(0x8C050B30u, expl_only, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count <= 50 || (count % 5000u) == 0u) {
                    uint32_t h0 = c.ReadVa32(c.regs[1]).value_or(0xDEADBEEFu);
                    LOG(Trace, "[wait-expl] NKWFMO #%u cObjs=%u h0=0x%08X fAll=%u "
                        "Timeout=%u LR=0x%08X SP=0x%08X R4=0x%08X R5=0x%08X R6=0x%08X R7=0x%08X\n",
                        count, c.regs[0], h0, c.regs[2], c.regs[3],
                        c.regs[14], c.regs[13],
                        c.regs[4], c.regs[5], c.regs[6], c.regs[7]);
                    /* Dump 24 stack words to find user-mode return chain. */
                    for (uint32_t i = 0; i < 24; ++i) {
                        const uint32_t a = c.regs[13] + i * 4u;
                        auto v = c.ReadVa32(a);
                        LOG(Trace, "[wait-expl]   stk #%u +0x%02X @0x%08X = 0x%08X\n",
                            count, i * 4u, a, v.value_or(0xDEADBEEFu));
                    }
                }
            });

            /* Poll explorer's PC every JIT iteration. Logs unique PCs +
               fire count to identify where explorer parks in the hang
               window (post t+50.79). */
            auto expl_pred = ce7_resolver::PidPredicateForName("explorer.exe");
            tm.OnRunLoopIter([counts = std::unordered_map<uint32_t, uint32_t>{},
                              last_pc = uint32_t{0}, fires = uint32_t{0},
                              pred = expl_pred]
                             (const TraceContext& c) mutable {
                if (!pred(c)) return;
                ++fires;
                const uint32_t pc_bucket = c.pc & ~0xFFFu;
                ++counts[pc_bucket];
                if (fires <= 30 || (fires % 5000u) == 0u || c.pc != last_pc) {
                    LOG(Trace, "[expl-pc-poll] #%u pc=0x%08X bucket=0x%08X "
                        "bucket_count=%u\n",
                        fires, c.pc, pc_bucket, counts[pc_bucket]);
                }
                last_pc = c.pc;
            });
        });
    }
};

REGISTER_SERVICE(TraceCe7ExplorerWmBisect);

}  /* namespace */

#endif  /* CERF_DEV_MODE */
