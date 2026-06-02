#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "../../jit/arm_mmu_state.h"
#include "ce7_bundle.h"

#include <cstdint>
#include <unordered_set>

#if CERF_DEV_MODE

namespace {

constexpr uint32_t kPThGweUser_0xA14       = 0xC0470A14u;
constexpr uint32_t kPThGweUser_0xBD48      = 0xC046BD48u;
constexpr uint32_t kPThGweUser_0x444       = 0xC0470444u;
constexpr uint32_t kPThGweUser_0x8AA0      = 0xC0458AA0u;
constexpr uint32_t kPThStartupScreenThread = 0xC0473198u;
constexpr uint32_t kPThExplorerMain        = 0xC04778F0u;

constexpr uint32_t kPcSchlWaitOneMore       = 0x8C03E224u;
constexpr uint32_t kPcDoWaitWithWaitStruct  = 0x8C050714u;
constexpr uint32_t kPcKernelMDCallUserHAPI  = 0x8C035958u;
constexpr uint32_t kPcKernelCallUserNotify  = 0x8C05F000u;
constexpr uint32_t kPcGwesCallWindowProcW_I = 0xEFD79178u;
constexpr uint32_t kPcKernelModeSwitchPre   = 0x8C035378u;
constexpr uint32_t kPcKernelModeSwitchMovs  = 0x8C03537Cu;
constexpr uint32_t kPcKernelServerCallReturn = 0x8C060CA0u;
constexpr uint32_t kPcKernelPrefetchAbortVec = 0xFFFF000Cu;
constexpr uint32_t kPcGwesGetEvent           = 0xEFD71404u;
constexpr uint32_t kPcGwesAddPaintRequest    = 0xEFD6DCE8u;
constexpr uint32_t kPcGwesGetMessageW_I      = 0xEFD7237Cu;
constexpr uint32_t kPcGwesPeekMessageW_I     = 0xEFD7250Cu;
constexpr uint32_t kPcGwesPeekMessageWInternal = 0xEFD71FA4u;
constexpr uint32_t kVaPCurThd               = 0xFFFFC824u;
constexpr uint32_t kVaPCurPrc               = 0xFFFFC800u;

const char* PthName(uint32_t pth) {
    if (pth == kPThGweUser_0xA14)       return "GweUser-0xC0470A14";
    if (pth == kPThGweUser_0xBD48)      return "GweUser-0xC046BD48";
    if (pth == kPThGweUser_0x444)       return "GweUser-0xC0470444";
    if (pth == kPThGweUser_0x8AA0)      return "GweUser-0xC0458AA0";
    if (pth == kPThStartupScreenThread) return "StartupScreenThread";
    if (pth == kPThExplorerMain)        return "Explorer-main";
    return nullptr;
}

void DumpWaitStruct(const TraceContext& c, const char* tag,
                    const char* who, uint32_t pcurthd) {
    const uint32_t pws = c.regs[0];
    const uint32_t cObjects = c.ReadVa32(pws +  0u).value_or(0u);
    const uint32_t phds     = c.ReadVa32(pws +  4u).value_or(0u);
    const uint32_t dwTout   = c.ReadVa32(pws +  8u).value_or(0xDEADBEEFu);
    const uint32_t pPxEnq   = c.ReadVa32(pws + 12u).value_or(0xDEADBEEFu);
    const uint32_t pPxPend  = c.ReadVa32(pws + 16u).value_or(0xDEADBEEFu);
    const uint32_t pMutex   = c.ReadVa32(pws + 20u).value_or(0xDEADBEEFu);
    const uint32_t fEnqueue = c.ReadVa32(pws + 24u).value_or(0xDEADBEEFu);
    const uint32_t pfnWait  = c.ReadVa32(pws + 28u).value_or(0xDEADBEEFu);
    const uint32_t dwUser   = c.ReadVa32(pws + 32u).value_or(0xDEADBEEFu);
    auto& mmu = c.emu.Get<ArmMmu>();
    const uint32_t ttbr = mmu.State()->translation_table_base.word
                        & 0xFFFFC000u;
    LOG(Trace,
        "[%s] WHO=%s pTh=0x%08X pws=0x%08X LR=0x%08X SP=0x%08X "
        "TTBR0=0x%08X cObjects=%u phds=0x%08X dwTimeout=0x%08X "
        "pProxyEnq=0x%08X pProxyPend=0x%08X pMutex=0x%08X "
        "fEnqueue=%u pfnWait=0x%08X dwUserData=0x%08X\n",
        tag, who, pcurthd, pws, c.regs[14], c.regs[13], ttbr,
        cObjects, phds, dwTout, pPxEnq, pPxPend, pMutex,
        fEnqueue, pfnWait, dwUser);
    if (phds != 0u && cObjects != 0u && cObjects <= 32u) {
        const uint32_t n = (cObjects > 4u) ? 4u : cObjects;
        for (uint32_t i = 0; i < n; ++i) {
            const uint32_t phd =
                c.ReadVa32(phds + i * 4u).value_or(0xDEADBEEFu);
            if (phd == 0u || phd == 0xDEADBEEFu) {
                LOG(Trace, "[%s]   phds[%u]=0x%08X (null/bad)\n",
                    tag, i, phd);
                continue;
            }
            const uint32_t pci    =
                c.ReadVa32(phd +  8u).value_or(0xDEADBEEFu);
            const uint32_t pvObj  =
                c.ReadVa32(phd + 12u).value_or(0xDEADBEEFu);
            const uint32_t dwData =
                c.ReadVa32(phd + 20u).value_or(0xDEADBEEFu);
            LOG(Trace, "[%s]   phds[%u]=0x%08X _HDATA{pci=0x%08X "
                "pvObj=0x%08X dwData=0x%08X}\n",
                tag, i, phd, pci, pvObj, dwData);
        }
    }
    const uint32_t sp = c.regs[13];
    for (uint32_t i = 0; i < 32u; ++i) {
        const uint32_t a = sp + i * 4u;
        const uint32_t v = c.ReadVa32(a).value_or(0xDEADBEEFu);
        LOG(Trace, "[%s]   stk[%2u] @0x%08X = 0x%08X\n", tag, i, a, v);
    }
}

class TraceCe7RenderParkProbe : public Service {
public:
    using Service::Service;
    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kCe7BundleCrc32, [&] {
            tm.OnPc(kPcDoWaitWithWaitStruct,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    const char* who = PthName(pcurthd);
                    if (!who) return;
                    DumpWaitStruct(c, "render-park-dwws", who, pcurthd);
                });

            tm.OnPc(kPcSchlWaitOneMore,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    const char* who = PthName(pcurthd);
                    if (!who) return;
                    DumpWaitStruct(c, "render-park-swom", who, pcurthd);
                });

            tm.OnPc(kPcGwesCallWindowProcW_I,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    const char* who = PthName(pcurthd);
                    if (!who) return;
                    const uint32_t wpp        = c.regs[0];
                    const uint32_t hwnd       = c.regs[1];
                    const uint32_t uMsg       = c.regs[2];
                    const uint32_t wParam     = c.regs[3];
                    const uint32_t lParam_sp  =
                        c.ReadVa32(c.regs[13]).value_or(0xDEADBEEFu);
                    const uint32_t wpp_ptr    =
                        c.ReadVa32(wpp +  0u).value_or(0xDEADBEEFu);
                    const uint32_t wpp_hProc  =
                        c.ReadVa32(wpp +  4u).value_or(0xDEADBEEFu);
                    const uint32_t wpp_lPtr   =
                        c.ReadVa32(wpp +  8u).value_or(0xDEADBEEFu);
                    auto& mmu = c.emu.Get<ArmMmu>();
                    const uint32_t ttbr =
                        mmu.State()->translation_table_base.word
                        & 0xFFFFC000u;
                    LOG(Trace,
                        "[render-park-cwpwi] WHO=%s pTh=0x%08X hwnd=0x%08X "
                        "uMsg=0x%04X wParam=0x%08X lParam=0x%08X "
                        "WindowProcPtr{m_Ptr=0x%08X m_hProc=0x%08X "
                        "m_PtrLong=0x%08X} LR=0x%08X SP=0x%08X TTBR0=0x%08X\n",
                        who, pcurthd, hwnd, uMsg, wParam, lParam_sp,
                        wpp_ptr, wpp_hProc, wpp_lPtr,
                        c.regs[14], c.regs[13], ttbr);
                });

            tm.OnPc(kPcKernelCallUserNotify,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    const char* who = PthName(pcurthd);
                    if (!who) return;
                    auto& mmu = c.emu.Get<ArmMmu>();
                    const uint32_t ttbr =
                        mmu.State()->translation_table_base.word
                        & 0xFFFFC000u;
                    LOG(Trace,
                        "[render-park-cun] WHO=%s pTh=0x%08X "
                        "R0(dwFlags*)=0x%08X R1(dwProcId)=0x%08X "
                        "R2(dwThrdId)=0x%08X R3(pHD)=0x%08X "
                        "LR=0x%08X SP=0x%08X TTBR0=0x%08X\n",
                        who, pcurthd, c.regs[0], c.regs[1],
                        c.regs[2], c.regs[3], c.regs[14], c.regs[13], ttbr);
                });

            tm.OnPc(kPcKernelModeSwitchMovs,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    const char* who = PthName(pcurthd);
                    if (!who) return;
                    auto& mmu = c.emu.Get<ArmMmu>();
                    const uint32_t ttbr =
                        mmu.State()->translation_table_base.word
                        & 0xFFFFC000u;
                    const uint32_t ctxidr = mmu.State()->contextidr;
                    const uint32_t pCurPrc =
                        c.ReadVa32(kVaPCurPrc).value_or(0xDEADBEEFu);
                    LOG(Trace,
                        "[render-park-movs] WHO=%s pTh=0x%08X v7(R12)=0x%08X "
                        "SP=0x%08X CPSR=0x%08X R0=0x%08X R1=0x%08X "
                        "R2=0x%08X R3=0x%08X TTBR0=0x%08X CTXIDR=0x%08X "
                        "pCurPrc=0x%08X\n",
                        who, pcurthd, c.regs[12], c.regs[13], c.cpsr,
                        c.regs[0], c.regs[1], c.regs[2], c.regs[3],
                        ttbr, ctxidr, pCurPrc);
                });

            tm.OnPc(kPcGwesGetMessageW_I,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    const char* who = PthName(pcurthd);
                    if (!who) return;
                    static uint32_t count = 0;
                    ++count;
                    if (count > 30 && (count % 100u) != 0u) return;
                    LOG(Trace,
                        "[render-park-getmsg] #%u WHO=%s pTh=0x%08X "
                        "pMsg=0x%08X hWnd=0x%08X filterMin=0x%X "
                        "filterMax=0x%X LR=0x%08X\n",
                        count, who, pcurthd,
                        c.regs[0], c.regs[1], c.regs[2], c.regs[3],
                        c.regs[14]);
                });

            tm.OnPc(kPcGwesPeekMessageWInternal,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    const char* who = PthName(pcurthd);
                    if (!who) return;
                    static uint32_t count = 0;
                    ++count;
                    if (count > 30 && (count % 200u) != 0u) return;
                    LOG(Trace,
                        "[render-park-peekmsg] #%u WHO=%s pTh=0x%08X "
                        "pMsg=0x%08X hWnd=0x%08X mgeFlags=0x%X LR=0x%08X\n",
                        count, who, pcurthd,
                        c.regs[0], c.regs[1], c.regs[4], c.regs[14]);
                });

            tm.OnPc(kPcGwesGetEvent,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    const char* who = PthName(pcurthd);
                    if (!who) return;
                    static uint32_t count = 0;
                    ++count;
                    if (count > 30 && (count % 100u) != 0u) return;
                    const uint32_t mq = c.regs[0];
                    const uint32_t mgeFlags = c.regs[1];
                    const uint32_t hwndFilter = c.regs[2];
                    const uint32_t hthdOwner =
                        c.ReadVa32(mq + 0x0Cu).value_or(0xDEADBEEFu);
                    const uint32_t paintHead =
                        c.ReadVa32(mq + 0xE4u).value_or(0xDEADBEEFu);
                    const uint32_t postedHead =
                        c.ReadVa32(mq + 0xC4u).value_or(0xDEADBEEFu);
                    const uint32_t msgqFlags =
                        c.ReadVa32(mq + 0x11Cu).value_or(0xDEADBEEFu);
                    LOG(Trace,
                        "[render-park-getevent] #%u WHO=%s pTh=0x%08X "
                        "MQ=0x%08X m_hthdOwner=0x%08X mgeFlags=0x%08X "
                        "hwndFilter=0x%08X m_pPaintHead=0x%08X "
                        "m_pPostedHead=0x%08X m_msgqFlags=0x%08X LR=0x%08X\n",
                        count, who, pcurthd, mq, hthdOwner, mgeFlags,
                        hwndFilter, paintHead, postedHead, msgqFlags,
                        c.regs[14]);
                });

            tm.OnPc(kPcKernelServerCallReturn,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    const char* who = PthName(pcurthd);
                    static uint32_t total_count = 0;
                    ++total_count;
                    if (!who && (total_count > 30 && (total_count % 500u) != 0u))
                        return;
                    auto& mmu = c.emu.Get<ArmMmu>();
                    const uint32_t ttbr =
                        mmu.State()->translation_table_base.word
                        & 0xFFFFC000u;
                    LOG(Trace,
                        "[render-park-scr] #%u WHO=%s pTh=0x%08X "
                        "R0=0x%08X R1=0x%08X R2=0x%08X R3=0x%08X "
                        "LR=0x%08X SP=0x%08X TTBR0=0x%08X CPSR=0x%08X\n",
                        total_count, who ? who : "(other)", pcurthd,
                        c.regs[0], c.regs[1], c.regs[2], c.regs[3],
                        c.regs[14], c.regs[13], ttbr, c.cpsr);
                });

            tm.OnPc(kPcKernelMDCallUserHAPI,
                [](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    const char* who = PthName(pcurthd);
                    if (!who) return;
                    const uint32_t phd = c.regs[0];
                    const uint32_t phc = c.regs[1];
                    uint32_t h[8], p[8];
                    for (int i = 0; i < 8; ++i) {
                        h[i] = c.ReadVa32(phd + i * 4u).value_or(0xDEADBEEFu);
                        p[i] = c.ReadVa32(phc + i * 4u).value_or(0xDEADBEEFu);
                    }
                    auto& mmu = c.emu.Get<ArmMmu>();
                    const uint32_t ttbr =
                        mmu.State()->translation_table_base.word
                        & 0xFFFFC000u;
                    LOG(Trace,
                        "[render-park-hapi] WHO=%s pTh=0x%08X phd=0x%08X "
                        "phc=0x%08X LR=0x%08X SP=0x%08X TTBR0=0x%08X "
                        "phd[0..7]={%08X %08X %08X %08X %08X %08X %08X %08X} "
                        "phc[0..7]={%08X %08X %08X %08X %08X %08X %08X %08X}\n",
                        who, pcurthd, phd, phc, c.regs[14], c.regs[13], ttbr,
                        h[0], h[1], h[2], h[3], h[4], h[5], h[6], h[7],
                        p[0], p[1], p[2], p[3], p[4], p[5], p[6], p[7]);
                });

            tm.OnRunLoopIter([
                seen = std::unordered_set<uint32_t>{},
                last = uint32_t{0}
            ] (const TraceContext& c) mutable {
                const uint32_t pcurthd =
                    c.ReadVa32(kVaPCurThd).value_or(0u);
                if (pcurthd == last) return;
                last = pcurthd;
                if (pcurthd == 0) return;
                if (seen.size() >= 40u) return;
                if (!seen.insert(pcurthd).second) return;
                auto& mmu = c.emu.Get<ArmMmu>();
                const uint32_t ttbr =
                    mmu.State()->translation_table_base.word
                    & 0xFFFFC000u;
                LOG(Trace,
                    "[render-park-pth-seen] #%zu pTh=0x%08X "
                    "TTBR0=0x%08X pc=0x%08X\n",
                    seen.size(), pcurthd, ttbr, c.pc);
            });
        });
    }
};

REGISTER_SERVICE(TraceCe7RenderParkProbe);

}  /* namespace */

#endif  /* CERF_DEV_MODE */
