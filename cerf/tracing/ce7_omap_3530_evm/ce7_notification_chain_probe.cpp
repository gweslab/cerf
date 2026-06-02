#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "../../jit/arm_mmu_state.h"
#include "ce7_bundle.h"

#include <cstdint>

#if CERF_DEV_MODE

namespace {

/* kernel.dll PCs (CE7 OMAP3530 ROM, CRC 0xC865A383). */
constexpr uint32_t kPcNkPslNotify          = 0x8C05F1B0u;
constexpr uint32_t kPcSaveDirectCall       = 0x8C05F4A4u;
constexpr uint32_t kPcDoValidateArgs       = 0x8C05FE34u;
constexpr uint32_t kPcSetupArguments       = 0x8C05FF78u;
constexpr uint32_t kPcNkWaitForMultipleObj = 0x8C050B30u;
constexpr uint32_t kPcEvntModify           = 0x8C04DC08u;
constexpr uint32_t kPcMsgQRead             = 0x8C0620B0u;
constexpr uint32_t kPcMsgQWrite            = 0x8C06249Cu;
/* Remaining 9 of 12 cinfEvent class methods. */
constexpr uint32_t kPcEvntCloseHandle      = 0x8C04DC68u;
constexpr uint32_t kPcMsgQPreClose         = 0x8C061D24u;
constexpr uint32_t kPcEvntGetData          = 0x8C04D98Cu;
constexpr uint32_t kPcEvntSetData          = 0x8C04D970u;
constexpr uint32_t kPcMsgQGetInfo          = 0x8C062830u;
constexpr uint32_t kPcWDStart              = 0x8C064520u;
constexpr uint32_t kPcWDStop               = 0x8C064668u;
constexpr uint32_t kPcWDRefresh            = 0x8C0646F8u;
constexpr uint32_t kPcEvntResumeMainThread = 0x8C04D9DCu;

/* Coredll user-mode event APIs (shared across all processes). */
constexpr uint32_t kPcCdEventModify        = 0x40029EACu;
constexpr uint32_t kPcCdCreateEventW       = 0x40029EF4u;
constexpr uint32_t kPcCdOpenEventW         = 0x40029F18u;
constexpr uint32_t kPcCdWaitForSingleObj   = 0x40029FE8u;

/* SetupArguments/SetupCallToUserServer chain — VM ops that may block. */
constexpr uint32_t kPcSetupCallToUserServer = 0x8C060494u;
constexpr uint32_t kPcSetupUmodeArgs       = 0x8C05FA8Cu;
constexpr uint32_t kPcVMReserve            = 0x8C03136Cu;
constexpr uint32_t kPcVMCreateStack        = 0x8C034D6Cu;
constexpr uint32_t kPcVMFastCopy           = 0x8C034B20u;
constexpr uint32_t kPcVMCommit             = 0x8C031204u;
/* Returns (last byte of function - 2, typical Thumb POP {.., PC}). */
constexpr uint32_t kPcVMReserveEnd         = 0x8C031402u;
constexpr uint32_t kPcVMCreateStackEnd     = 0x8C034F42u;
constexpr uint32_t kPcVMFastCopyEnd        = 0x8C034C4Au;
constexpr uint32_t kPcVMCommitEnd          = 0x8C031286u;
constexpr uint32_t kPcSetupUmodeArgsEnd    = 0x8C05FE2Au;
constexpr uint32_t kPcSetupCallToUserSrvEnd = 0x8C06074Au;

constexpr uint32_t kVaPCurThd = 0xFFFFC824u;

/* Known render-pipeline pTh values (from prior session findings). */
const char* PthName(uint32_t pth) {
    switch (pth) {
        case 0xC0473198u: return "StartupScreenThread";
        case 0xC04778F0u: return "Explorer-main";
        case 0xC0470A14u: return "GweUser-0xC0470A14";
        case 0xC046BD48u: return "GweUser-0xC046BD48";
        case 0xC0470444u: return "GweUser-0xC0470444";
        case 0xC0458AA0u: return "GweUser-0xC0458AA0";
        case 0xC0406000u: return "Thread-0xC0406000";
        default:          return nullptr;
    }
}

class TraceCe7NotificationChainProbe : public Service {
public:
    using Service::Service;
    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kCe7BundleCrc32, [&] {

            tm.OnPc(kPcNkPslNotify, [](const TraceContext& c) {
                const uint32_t pcurthd =
                    c.ReadVa32(kVaPCurThd).value_or(0u);
                const char* who = PthName(pcurthd);
                static uint32_t total = 0;
                ++total;
                if (!who && (total > 30 && (total % 500u) != 0u)) return;
                auto& mmu = c.emu.Get<ArmMmu>();
                const uint32_t ttbr =
                    mmu.State()->translation_table_base.word & 0xFFFFC000u;
                LOG(Trace,
                    "[nc] NKPSLNotify #%u WHO=%s pTh=0x%08X "
                    "R0=0x%08X R1=0x%08X R2=0x%08X R3=0x%08X "
                    "LR=0x%08X SP=0x%08X TTBR0=0x%08X\n",
                    total, who ? who : "(other)", pcurthd,
                    c.regs[0], c.regs[1], c.regs[2], c.regs[3],
                    c.regs[14], c.regs[13], ttbr);
            });

            tm.OnPc(kPcSaveDirectCall, [](const TraceContext& c) {
                const uint32_t pcurthd =
                    c.ReadVa32(kVaPCurThd).value_or(0u);
                const char* who = PthName(pcurthd);
                static uint32_t total = 0;
                ++total;
                if (!who && (total > 30 && (total % 500u) != 0u)) return;
                auto& mmu = c.emu.Get<ArmMmu>();
                const uint32_t ttbr =
                    mmu.State()->translation_table_base.word & 0xFFFFC000u;
                LOG(Trace,
                    "[nc] SaveDirectCall #%u WHO=%s pTh=0x%08X "
                    "R0=0x%08X R1=0x%08X LR=0x%08X TTBR0=0x%08X\n",
                    total, who ? who : "(other)", pcurthd,
                    c.regs[0], c.regs[1], c.regs[14], ttbr);
            });

            tm.OnPc(kPcDoValidateArgs, [](const TraceContext& c) {
                const uint32_t pcurthd =
                    c.ReadVa32(kVaPCurThd).value_or(0u);
                const char* who = PthName(pcurthd);
                static uint32_t total = 0;
                ++total;
                if (!who && (total > 30 && (total % 500u) != 0u)) return;
                auto& mmu = c.emu.Get<ArmMmu>();
                const uint32_t ttbr =
                    mmu.State()->translation_table_base.word & 0xFFFFC000u;
                LOG(Trace,
                    "[nc] DoValidateArgs #%u WHO=%s pTh=0x%08X "
                    "R0=0x%08X R1=0x%08X LR=0x%08X TTBR0=0x%08X\n",
                    total, who ? who : "(other)", pcurthd,
                    c.regs[0], c.regs[1], c.regs[14], ttbr);
            });

            tm.OnPc(kPcSetupArguments, [](const TraceContext& c) {
                const uint32_t pcurthd =
                    c.ReadVa32(kVaPCurThd).value_or(0u);
                const char* who = PthName(pcurthd);
                static uint32_t total = 0;
                ++total;
                if (!who && (total > 30 && (total % 500u) != 0u)) return;
                auto& mmu = c.emu.Get<ArmMmu>();
                const uint32_t ttbr =
                    mmu.State()->translation_table_base.word & 0xFFFFC000u;
                LOG(Trace,
                    "[nc] SetupArguments #%u WHO=%s pTh=0x%08X "
                    "R0=0x%08X R1=0x%08X LR=0x%08X TTBR0=0x%08X\n",
                    total, who ? who : "(other)", pcurthd,
                    c.regs[0], c.regs[1], c.regs[14], ttbr);
            });

            /* EVNTModify(lpe, type) — R0=event obj, R1=type (1=PULSE 2=RESET
               3=SET per CE7). Every event signal in the system goes through
               here. Log everything for known render threads; sample others. */
            tm.OnPc(kPcEvntModify, [](const TraceContext& c) {
                const uint32_t pcurthd =
                    c.ReadVa32(kVaPCurThd).value_or(0u);
                const char* who = PthName(pcurthd);
                static uint32_t total = 0;
                ++total;
                if (!who && (total > 50 && (total % 200u) != 0u)) return;
                auto& mmu = c.emu.Get<ArmMmu>();
                const uint32_t ttbr =
                    mmu.State()->translation_table_base.word & 0xFFFFC000u;
                /* Read event state byte BEFORE modification (lpe+17). */
                const uint32_t state_before =
                    c.ReadVa8(c.regs[0] + 17u).value_or(0xFFu);
                LOG(Trace,
                    "[nc] EVNTModify #%u WHO=%s pTh=0x%08X "
                    "lpe=0x%08X type=%u state_before=0x%02X "
                    "LR=0x%08X TTBR0=0x%08X\n",
                    total, who ? who : "(other)", pcurthd,
                    c.regs[0], c.regs[1], state_before,
                    c.regs[14], ttbr);
            });

            tm.OnPc(kPcMsgQRead, [](const TraceContext& c) {
                const uint32_t pcurthd =
                    c.ReadVa32(kVaPCurThd).value_or(0u);
                const char* who = PthName(pcurthd);
                static uint32_t total = 0;
                ++total;
                if (!who && (total > 30 && (total % 500u) != 0u)) return;
                auto& mmu = c.emu.Get<ArmMmu>();
                const uint32_t ttbr =
                    mmu.State()->translation_table_base.word & 0xFFFFC000u;
                LOG(Trace,
                    "[nc] MSGQRead #%u WHO=%s pTh=0x%08X "
                    "lpe=0x%08X lpBuf=0x%08X cbSize=%u Timeout=0x%08X "
                    "LR=0x%08X TTBR0=0x%08X\n",
                    total, who ? who : "(other)", pcurthd,
                    c.regs[0], c.regs[1], c.regs[2], c.regs[3],
                    c.regs[14], ttbr);
            });

            tm.OnPc(kPcMsgQWrite, [](const TraceContext& c) {
                const uint32_t pcurthd =
                    c.ReadVa32(kVaPCurThd).value_or(0u);
                const char* who = PthName(pcurthd);
                static uint32_t total = 0;
                ++total;
                if (!who && (total > 30 && (total % 500u) != 0u)) return;
                auto& mmu = c.emu.Get<ArmMmu>();
                const uint32_t ttbr =
                    mmu.State()->translation_table_base.word & 0xFFFFC000u;
                LOG(Trace,
                    "[nc] MSGQWrite #%u WHO=%s pTh=0x%08X "
                    "lpe=0x%08X lpBuf=0x%08X cbSize=%u Timeout=0x%08X "
                    "LR=0x%08X TTBR0=0x%08X\n",
                    total, who ? who : "(other)", pcurthd,
                    c.regs[0], c.regs[1], c.regs[2], c.regs[3],
                    c.regs[14], ttbr);
            });

            /* Remaining cinfEvent methods. Same shape: each entry takes
               lpe in R0. Log every fire that targets splash's event
               (lpe=0xC0477298) AND every 200th otherwise. */
            auto hook_method = [&tm](uint32_t pc, const char* name) {
                tm.OnPc(pc, [name](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    const char* who = PthName(pcurthd);
                    static thread_local uint32_t total = 0;
                    ++total;
                    const bool is_splash_evt =
                        c.regs[0] == 0xC0477298u;
                    if (!is_splash_evt && !who &&
                        (total > 20 && (total % 200u) != 0u))
                        return;
                    auto& mmu = c.emu.Get<ArmMmu>();
                    const uint32_t ttbr =
                        mmu.State()->translation_table_base.word
                        & 0xFFFFC000u;
                    LOG(Trace,
                        "[nc] %s%s #%u WHO=%s pTh=0x%08X "
                        "lpe=0x%08X R1=0x%08X R2=0x%08X R3=0x%08X "
                        "LR=0x%08X TTBR0=0x%08X\n",
                        is_splash_evt ? "*SPLASH-EVT* " : "",
                        name, total, who ? who : "(other)", pcurthd,
                        c.regs[0], c.regs[1], c.regs[2], c.regs[3],
                        c.regs[14], ttbr);
                });
            };
            hook_method(kPcEvntCloseHandle,      "EVNTCloseHandle");
            hook_method(kPcMsgQPreClose,         "MSGQPreClose");
            hook_method(kPcEvntGetData,          "EVNTGetData");
            hook_method(kPcEvntSetData,          "EVNTSetData");
            hook_method(kPcMsgQGetInfo,          "MSGQGetInfo");
            hook_method(kPcWDStart,              "WDStart");
            hook_method(kPcWDStop,               "WDStop");
            hook_method(kPcWDRefresh,            "WDRefresh");
            hook_method(kPcEvntResumeMainThread, "EVNTResumeMainThread");

            /* SetupArguments / VM chain — entry & exit per function, splash
               (and other known render threads) only. Whichever entry fires
               but exit doesn't is the hang point. */
            auto hook_enter = [&tm](uint32_t pc, const char* name) {
                tm.OnPc(pc, [name](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    const char* who = PthName(pcurthd);
                    if (!who) return;
                    auto& mmu = c.emu.Get<ArmMmu>();
                    const uint32_t ttbr =
                        mmu.State()->translation_table_base.word
                        & 0xFFFFC000u;
                    LOG(Trace,
                        "[nc-vm] %s ENTRY WHO=%s pTh=0x%08X "
                        "R0=0x%08X R1=0x%08X R2=0x%08X R3=0x%08X "
                        "LR=0x%08X TTBR0=0x%08X\n",
                        name, who, pcurthd,
                        c.regs[0], c.regs[1], c.regs[2], c.regs[3],
                        c.regs[14], ttbr);
                });
            };
            auto hook_exit = [&tm](uint32_t pc, const char* name) {
                tm.OnPc(pc, [name](const TraceContext& c) {
                    const uint32_t pcurthd =
                        c.ReadVa32(kVaPCurThd).value_or(0u);
                    const char* who = PthName(pcurthd);
                    if (!who) return;
                    LOG(Trace,
                        "[nc-vm] %s EXIT WHO=%s pTh=0x%08X R0(ret)=0x%08X\n",
                        name, who, pcurthd, c.regs[0]);
                });
            };

            hook_enter(kPcSetupCallToUserServer, "SetupCallToUserServer");
            hook_exit (kPcSetupCallToUserSrvEnd, "SetupCallToUserServer");
            hook_enter(kPcSetupUmodeArgs,        "SetupUmodeArgs");
            hook_exit (kPcSetupUmodeArgsEnd,     "SetupUmodeArgs");
            hook_enter(kPcVMReserve,             "VMReserve");
            hook_exit (kPcVMReserveEnd,          "VMReserve");
            hook_enter(kPcVMCreateStack,         "VMCreateStack");
            hook_exit (kPcVMCreateStackEnd,      "VMCreateStack");
            hook_enter(kPcVMFastCopy,            "VMFastCopy");
            hook_exit (kPcVMFastCopyEnd,         "VMFastCopy");
            hook_enter(kPcVMCommit,              "VMCommit");
            hook_exit (kPcVMCommitEnd,           "VMCommit");

            /* User-mode event signaler hunt. xxx_EventModify is the
               chokepoint for every user-mode EventModify call across all
               processes. If splash's handle ever gets signaled, this fires
               with R0=handle and LR=caller-in-coredll-caller. */
            tm.OnPc(kPcCdEventModify, [](const TraceContext& c) {
                const uint32_t pcurthd =
                    c.ReadVa32(kVaPCurThd).value_or(0u);
                const char* who = PthName(pcurthd);
                static uint32_t total = 0;
                ++total;
                if (!who && (total > 50 && (total % 200u) != 0u)) return;
                auto& mmu = c.emu.Get<ArmMmu>();
                const uint32_t ttbr =
                    mmu.State()->translation_table_base.word & 0xFFFFC000u;
                LOG(Trace,
                    "[nc-sig] xxx_EventModify #%u WHO=%s pTh=0x%08X "
                    "hEvent=0x%08X func=%u LR=0x%08X TTBR0=0x%08X\n",
                    total, who ? who : "(other)", pcurthd,
                    c.regs[0], c.regs[1], c.regs[14], ttbr);
            });

            /* xxx_CreateEventW(lpAttrs, bManualReset, bInitialState, lpName) */
            tm.OnPc(kPcCdCreateEventW, [](const TraceContext& c) {
                const uint32_t pcurthd =
                    c.ReadVa32(kVaPCurThd).value_or(0u);
                const char* who = PthName(pcurthd);
                static uint32_t total = 0;
                ++total;
                if (!who && (total > 50 && (total % 200u) != 0u)) return;
                auto& mmu = c.emu.Get<ArmMmu>();
                const uint32_t ttbr =
                    mmu.State()->translation_table_base.word & 0xFFFFC000u;
                /* Read up to 64 wide chars of name (R3). */
                wchar_t name[64] = {};
                if (c.regs[3] != 0) {
                    for (int i = 0; i < 63; ++i) {
                        auto w = c.ReadVa16(c.regs[3] + i * 2u);
                        if (!w || *w == 0) break;
                        name[i] = static_cast<wchar_t>(*w);
                    }
                }
                LOG(Trace,
                    "[nc-sig] xxx_CreateEventW #%u WHO=%s pTh=0x%08X "
                    "bManual=%u bInit=%u name='%ls' LR=0x%08X TTBR0=0x%08X\n",
                    total, who ? who : "(other)", pcurthd,
                    c.regs[1], c.regs[2], name, c.regs[14], ttbr);
            });

            tm.OnPc(kPcCdOpenEventW, [](const TraceContext& c) {
                const uint32_t pcurthd =
                    c.ReadVa32(kVaPCurThd).value_or(0u);
                const char* who = PthName(pcurthd);
                static uint32_t total = 0;
                ++total;
                if (!who && (total > 50 && (total % 200u) != 0u)) return;
                auto& mmu = c.emu.Get<ArmMmu>();
                const uint32_t ttbr =
                    mmu.State()->translation_table_base.word & 0xFFFFC000u;
                wchar_t name[64] = {};
                if (c.regs[2] != 0) {
                    for (int i = 0; i < 63; ++i) {
                        auto w = c.ReadVa16(c.regs[2] + i * 2u);
                        if (!w || *w == 0) break;
                        name[i] = static_cast<wchar_t>(*w);
                    }
                }
                LOG(Trace,
                    "[nc-sig] xxx_OpenEventW #%u WHO=%s pTh=0x%08X "
                    "access=0x%08X inherit=%u name='%ls' LR=0x%08X TTBR0=0x%08X\n",
                    total, who ? who : "(other)", pcurthd,
                    c.regs[0], c.regs[1], name, c.regs[14], ttbr);
            });

            tm.OnPc(kPcCdWaitForSingleObj, [](const TraceContext& c) {
                /* UNFILTERED — log every fire to see if splash actually
                   triggers the PC and what PCURTHD reads at that moment. */
                static uint32_t total = 0;
                ++total;
                if (total > 200 && (total % 200u) != 0u) return;
                const uint32_t pcurthd =
                    c.ReadVa32(kVaPCurThd).value_or(0xDEADBEEFu);
                const char* who = PthName(pcurthd);
                auto& mmu = c.emu.Get<ArmMmu>();
                const uint32_t ttbr =
                    mmu.State()->translation_table_base.word & 0xFFFFC000u;
                LOG(Trace,
                    "[nc-sig] xxx_WaitForSingleObject ANY #%u "
                    "WHO=%s pTh=0x%08X hHandle=0x%08X dwMs=0x%08X "
                    "LR=0x%08X TTBR0=0x%08X CPSR=0x%08X\n",
                    total, who ? who : "(other)", pcurthd,
                    c.regs[0], c.regs[1], c.regs[14], ttbr, c.cpsr);
            });

            /* ObjectCall (kernel API dispatcher entry). Reads pcstk->phd
               (+0x50) and pcstk->iMethod (+0x58) to identify exactly which
               API method splash is calling. Filtered to known render threads. */
            tm.OnPc(0x8C0601B8u, [](const TraceContext& c) {
                const uint32_t pcurthd =
                    c.ReadVa32(kVaPCurThd).value_or(0u);
                const char* who = PthName(pcurthd);
                if (!who) return;
                const uint32_t pcstk = c.regs[0];
                const uint32_t phd   = c.ReadVa32(pcstk + 0x50u).value_or(0u);
                const uint32_t imeth = c.ReadVa32(pcstk + 0x58u).value_or(0u);
                const uint32_t retA  = c.ReadVa32(pcstk + 0x3Cu).value_or(0u);
                const uint32_t prSp  = c.ReadVa32(pcstk + 0x40u).value_or(0u);
                const uint32_t pInfo = c.ReadVa32(pcstk + 0x44u).value_or(0u);
                auto& mmu = c.emu.Get<ArmMmu>();
                const uint32_t ttbr =
                    mmu.State()->translation_table_base.word & 0xFFFFC000u;
                LOG(Trace,
                    "[nc-oc] ObjectCall ENTRY WHO=%s pTh=0x%08X pcstk=0x%08X "
                    "phd=0x%08X iMethod=0x%08X retAddr=0x%08X dwPrevSP=0x%08X "
                    "dwPrcInfo=0x%08X LR=0x%08X TTBR0=0x%08X\n",
                    who, pcurthd, pcstk, phd, imeth, retA, prSp,
                    pInfo, c.regs[14], ttbr);
            });

            /* State-byte poll for splash's parked event (pvObj=0xC0477298,
               state at +17). If state ever flips to 1, something signaled
               the event (possibly bypassing EVNTModify). If it stays 0,
               no code path touches the byte. */
            tm.OnRunLoopIter([last_state = uint32_t{0xFFu},
                              last_pmsgq = uint32_t{0xFFFFFFFFu},
                              fired = false]
                             (const TraceContext& c) mutable {
                constexpr uint32_t kSplashEventVa  = 0xC0477298u;
                constexpr uint32_t kSplashStateVa  = kSplashEventVa + 17u;
                auto state = c.ReadVa8(kSplashStateVa);
                auto pmsgq = c.ReadVa32(kSplashEventVa);
                if (!state || !pmsgq) return;
                if (!fired && state.value() != 0xFFu) {
                    fired = true;
                    auto manual = c.ReadVa8(kSplashEventVa + 18u);
                    auto dwData = c.ReadVa32(kSplashEventVa + 8u);
                    auto phdIntr = c.ReadVa32(kSplashEventVa + 12u);
                    LOG(Trace,
                        "[nc-poll] splash-event @0x%08X INITIAL: "
                        "pMsgQ=0x%08X dwData=0x%08X phdIntr=0x%08X "
                        "state=0x%02X manualreset=0x%02X\n",
                        kSplashEventVa,
                        pmsgq.value_or(0u), dwData.value_or(0u),
                        phdIntr.value_or(0u),
                        state.value(), manual.value_or(0xFFu));
                    last_state = state.value();
                    last_pmsgq = pmsgq.value();
                    return;
                }
                if (state.value() != last_state) {
                    LOG(Trace,
                        "[nc-poll] splash-event @0x%08X STATE CHANGED: "
                        "0x%02X -> 0x%02X (pc=0x%08X)\n",
                        kSplashEventVa, last_state, state.value(), c.pc);
                    last_state = state.value();
                }
                if (pmsgq.value() != last_pmsgq) {
                    LOG(Trace,
                        "[nc-poll] splash-event @0x%08X pMsgQ CHANGED: "
                        "0x%08X -> 0x%08X (pc=0x%08X)\n",
                        kSplashEventVa, last_pmsgq, pmsgq.value(), c.pc);
                    last_pmsgq = pmsgq.value();
                }
            });
        });
    }
};

REGISTER_SERVICE(TraceCe7NotificationChainProbe);

}  /* namespace */

#endif  /* CERF_DEV_MODE */
