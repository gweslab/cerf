#include "../trace_manager.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "bundle.h"

#include <atomic>

#if CERF_DEV_MODE

namespace {

/* Read a guest UTF-16 string into ASCII for logging (non-ASCII -> '?'). */
void ReadWStr(const TraceContext& c, uint32_t va, char* out, int cap) {
    int n = 0;
    for (; n < cap - 1; ++n) {
        auto wc = c.ReadVa16(va + n * 2u);
        if (!wc || *wc == 0) break;
        out[n] = (*wc < 0x80u) ? static_cast<char>(*wc) : '?';
    }
    out[n] = 0;
}

/* sub_800F425C = OAL OEMInterruptEnable(R0=sysintr); sub_800F33D4 = OAL
   OEMInterruptHandler (reads INTC ICIP). Logs which sysintr the driver last
   enables + OST-tick activity, to pin what the parked guest waits on. */
class Falcon4220IrqHangDiag : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kFalcon4220BundleCrc32, [&] {
            tm.OnPc(0x800F425Cu, [](const TraceContext& c) {
                LOG(Trace, "[FALCON] OEMInterruptEnable sysintr=%d LR=0x%08X\n",
                    static_cast<int>(c.regs[0]), c.regs[14]);
            });

            /* coredll exports (shared XIP VA → R0 wide-string names the target):
               last LoadLibraryW/ActivateDeviceEx before the park = the blocking
               driver. DO NOT add a process filter — want all callers. */
            tm.OnPc(0x3F883A0u, [](const TraceContext& c) {   /* CreateProcessW */
                /* lpAppName(R0) is often NULL with the exe in lpCmdLine(R1). */
                char app[80]; ReadWStr(c, c.regs[0], app, 80);
                char cmd[80]; ReadWStr(c, c.regs[1], cmd, 80);
                LOG(Trace, "[FALCON] CreateProcessW app='%s' cmd='%s' R0=0x%08X LR=0x%08X\n",
                    app, cmd, c.regs[0], c.regs[14]);
            });
            tm.OnPc(0x3F84120u, [](const TraceContext& c) {   /* LoadLibraryW */
                char s[80]; ReadWStr(c, c.regs[0], s, 80);
                LOG(Trace, "[FALCON] LoadLibraryW '%s'\n", s);
            });
            tm.OnPc(0x3F82D10u, [](const TraceContext& c) {   /* ActivateDeviceEx */
                char s[96]; ReadWStr(c, c.regs[0], s, 96);
                LOG(Trace, "[FALCON] ActivateDeviceEx key='%s'\n", s);
            });

            /* sub_800EA200 = InterruptInitialize(R0=sysintr, R1=hEvent) binds an
               IST event to a sysintr; logs each bind + caller bytes (LR-8..LR+4)
               so the binding driver DLL is identified by .text signature. */
            tm.OnPc(0x800EA200u, [](const TraceContext& c) {
                const uint32_t pid = c.emu.Get<ArmMmu>().State()->process_id;
                const uint32_t lr = c.regs[14];
                auto b0 = c.ReadVa32(lr - 8), b1 = c.ReadVa32(lr - 4),
                     b2 = c.ReadVa32(lr), b3 = c.ReadVa32(lr + 4);
                LOG(Trace, "[FALCON] InterruptInitialize sysintr=%u slot=%u "
                           "evt=0x%08X LR=0x%08X bytes=%08X %08X %08X %08X\n",
                    c.regs[0], pid >> 25, c.regs[1], lr,
                    b0.value_or(0), b1.value_or(0), b2.value_or(0), b3.value_or(0));
            });

            /* 0x03F87888 = coredll!InterruptInitialize just after the kernel-trap
               return; SP is the userspace stack holding the wrapper-saved driver
               return addr. DO NOT add a process filter (want every bind, by slot). */
            tm.OnPc(0x03F87888u, [](const TraceContext& c) {
                const uint32_t pid = c.emu.Get<ArmMmu>().State()->process_id;
                if ((pid >> 25) != 3u) return;   /* only device.exe driver binds. */
                const uint32_t sp = c.regs[13];
                char buf[200]; int n = 0;
                for (uint32_t i = 0; i < 0x38u && n < 180; i += 4) {
                    auto v = c.ReadVa32(sp + i);
                    if (!v || *v < 0x01700000u || *v >= 0x01950000u) continue;
                    auto code = c.ReadVa32(*v);   /* instruction bytes at the driver code addr. */
                    n += std::snprintf(buf + n, sizeof(buf) - n, "%08X:%08X ",
                                       *v, code.value_or(0));
                }
                LOG(Trace, "[FALCON] drv-code SP=0x%08X %s\n", sp, buf);
            });

            /* 0x800F33F0 = just after OEMInterruptHandler's `LDR R1,[0xBB200000]`
               (ICIP read). R1 = the ICIP value the handler sees. If bit26(OST) is
               0 here while the OST just asserted, the tick branch is skipped =
               the deassert/assert race that kills the tick. */
            static std::atomic<uint64_t> icip_hits{0};
            tm.OnPc(0x800F33F0u, [](const TraceContext& c) {
                const uint64_t n = icip_hits.fetch_add(1, std::memory_order_relaxed);
                if (n < 500u)
                    LOG(Trace, "[FALCON] OEMIH ICIP=0x%08X bit26=%u\n",
                        c.regs[1], (c.regs[1] >> 26) & 1u);
            });

            static std::atomic<uint64_t> handler_hits{0};
            tm.OnPc(0x800F33D4u, [](const TraceContext& c) {
                const uint64_t n = handler_hits.fetch_add(1, std::memory_order_relaxed);
                /* Throttle: first 200, then 1 per 256, so the tail before the
                   park is visible without flooding. R0=a1 (handler arg). */
                if (n < 200 || (n & 0xFFu) == 0u) {
                    LOG(Trace, "[FALCON] OEMInterruptHandler n=%llu R0=0x%08X "
                               "LR=0x%08X\n",
                        static_cast<unsigned long long>(n), c.regs[0], c.regs[14]);
                }
            });

            /* sub_800BEA2C = OAL IRQ-dispatch (calls OEMInterruptHandler); fires
               iff the guest IRQ vector is reached. CPSR bit7 = IRQ mask. */
            static std::atomic<uint64_t> dispatch_hits{0};
            tm.OnPc(0x800BEA2Cu, [](const TraceContext& c) {
                const uint64_t n = dispatch_hits.fetch_add(1, std::memory_order_relaxed);
                if (n < 200 || (n & 0xFFu) == 0u) {
                    LOG(Trace, "[FALCON] OAL_IRQdispatch n=%llu CPSR=0x%08X\n",
                        static_cast<unsigned long long>(n), c.cpsr);
                }
            });
        });
    }
};

}  /* namespace */

REGISTER_SERVICE(Falcon4220IrqHangDiag);

#endif  /* CERF_DEV_MODE */
