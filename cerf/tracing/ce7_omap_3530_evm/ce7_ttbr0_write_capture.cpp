#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "ce7_bundle.h"

namespace {

/* Capture R1 (= new TTBR0 value) at the two kernel.dll TTBR0-write sites
   that UND under v6+ helper validation. PC 0x8C0359E4 / 0x8C035A00 both
   execute `MCR p15, 0, R1, c2, c0, 0`; the rejection means the masked
   base PA is not a host-RAM region per EmulatedMemory::TryTranslateWrite. */
constexpr uint32_t kPcTtbr0WriteA = 0x8C0359E4u;
constexpr uint32_t kPcTtbr0WriteB = 0x8C035A00u;
constexpr uint32_t kPcSetupTtbr1Entry = 0x8C0359A8u;
constexpr uint32_t kPcSetupTtbr1Write = 0x8C0359B0u;
constexpr uint32_t kPcSetupTtbcrWrite = 0x8C0359B4u;
constexpr uint32_t kPcInitAsidEntry   = 0x8C040594u;
constexpr uint32_t kPcInitAsidCaller  = 0x8C02D2ACu;
constexpr uint32_t kPcGetCpuIdReturn     = 0x8C00C0F4u;
constexpr uint32_t kPcGetCpuIdKdllReturn = 0x8C035064u;
constexpr uint32_t kPcNkStartupEntry     = 0x8C02D2D8u;
constexpr uint32_t kPcArchIdUbfx         = 0x8C02D320u;  /* UBFX R3, R9, #16, #4 */
constexpr uint32_t kPcArchIdPostUbfx     = 0x8C02D324u;  /* MOV R6, #2 — first insn after UBFX */
constexpr uint32_t kPcArchIdStore        = 0x8C02D340u;  /* STR R3, [R5, #0x2A0] */
constexpr uint32_t kPcArchIdCmp          = 0x8C02D344u;  /* CMP R3, #7 */

class TraceCe7Ttbr0WriteCapture : public Service {
public:
    using Service::Service;
    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kCe7BundleCrc32, [&] {
            auto hit = [](const char* tag) {
                return [tag](const TraceContext& c) {
                    LOG(Trace,
                        "[%s] PC=0x%08X R0=0x%08X R1=0x%08X R2=0x%08X "
                        "R3=0x%08X R5=0x%08X R9=0x%08X "
                        "LR=0x%08X SP=0x%08X CPSR=0x%08X mode=0x%X\n",
                        tag, c.pc, c.regs[0], c.regs[1], c.regs[2],
                        c.regs[3], c.regs[5], c.regs[9],
                        c.regs[14], c.regs[13], c.cpsr, c.cpsr & 0x1F);
                };
            };
            tm.OnPc(kPcTtbr0WriteA,     hit("TTBR0_WR_A"));
            tm.OnPc(kPcTtbr0WriteB,     hit("TTBR0_WR_B"));
            tm.OnPc(kPcSetupTtbr1Entry, hit("SetupTTBR1_ENTRY"));
            tm.OnPc(kPcSetupTtbr1Write, hit("SetupTTBR1_WR"));
            tm.OnPc(kPcSetupTtbcrWrite, hit("SetupTTBCR_WR"));
            tm.OnPc(kPcInitAsidEntry,   hit("InitASID_ENTRY"));
            tm.OnPc(kPcInitAsidCaller,  hit("InitASID_CALLER"));
            tm.OnPc(kPcGetCpuIdReturn,     hit("GetCpuId_NK_RET"));
            tm.OnPc(kPcGetCpuIdKdllReturn, hit("GetCpuId_KDLL_RET"));
            tm.OnPc(kPcNkStartupEntry,     hit("NKStartup_ENTRY"));
            tm.OnPc(kPcArchIdUbfx,         hit("ARCHID_UBFX_PRE"));
            tm.OnPc(kPcArchIdPostUbfx,     hit("ARCHID_POST_UBFX"));
            tm.OnPc(kPcArchIdStore,        hit("ARCHID_STORE_PRE"));
            tm.OnPc(kPcArchIdCmp,          hit("ARCHID_CMP_PRE"));

            /* Poll the kernel's architecture-id slot every JIT::Run
               iteration; log the first change. WinCE NK references
               this VA via MEMORY[0xFFFFCAA0] in compiled v6+ checks. */
            tm.OnRunLoopIter([last = uint32_t{0xDEADBEEFu}]
                             (const TraceContext& c) mutable {
                auto v = c.ReadVa32(0xFFFFCAA0u);
                if (!v) return;
                if (*v == last) return;
                last = *v;
                LOG(Trace, "[ARCHID_POLL] *(0xFFFFCAA0)=0x%08X\n", *v);
            });
            /* Poll pCurThread pointer at PCB+0x024 (ksarm.h:148). */
            tm.OnRunLoopIter([last = uint32_t{0xDEADBEEFu}]
                             (const TraceContext& c) mutable {
                auto v = c.ReadVa32(0xFFFFC824u);
                if (!v) return;
                if (*v == last) return;
                last = *v;
                LOG(Trace, "[PCURTHD_POLL] *(0xFFFFC824)=0x%08X\n", *v);
            });
        });
    }
};

REGISTER_SERVICE(TraceCe7Ttbr0WriteCapture);

}  /* namespace */
