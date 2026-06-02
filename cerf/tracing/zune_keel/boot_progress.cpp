#include "../trace_manager.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "bundle.h"

#include <atomic>

#if CERF_DEV_MODE

namespace {

class ZuneKeelBootProgress : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kZuneKeelBundleCrc32, [&] {
            static std::atomic<uint64_t> iter_count{0};
            static std::atomic<uint64_t> hits_big_init{0};
            static std::atomic<uint64_t> hits_big_init_exit{0};
            static std::atomic<uint64_t> hits_pmic_wrap{0};
            static std::atomic<uint64_t> hits_pmic_rmw{0};
            static std::atomic<uint64_t> last_dump_iter{0};

            tm.OnRunLoopIter([](const TraceContext& c) {
                const uint64_t n = iter_count.fetch_add(1, std::memory_order_relaxed);
                if (n < 2000) {
                    LOG(Trace, "[BOOT] iter=%llu pc=0x%08X lr=0x%08X "
                               "sp=0x%08X cpsr=0x%08X\n",
                        static_cast<unsigned long long>(n), c.pc, c.regs[14],
                        c.regs[13], c.cpsr);
                }
                /* Kernel ms-tick counter advanced by the EPIT ISR
                   (sub_8823C20C: MEMORY[0x88FDE934] += convert(elapsed)).
                   Tracks guest-time-per-wallclock to settle tick calibration. */
                if ((n % 100000) == 0) {
                    auto t = c.ReadVa32(0x88FDE934u);
                    LOG(Trace, "[BOOT] tickcount=%d pc=0x%08X lr=0x%08X\n",
                        t.has_value() ? static_cast<int>(*t) : -1,
                        c.pc, c.regs[14]);
                }
                const uint64_t last = last_dump_iter.load(std::memory_order_relaxed);
                if (n - last >= 100000) {
                    last_dump_iter.store(n, std::memory_order_relaxed);
                    LOG(Trace, "[BOOT][COUNTERS] iter=%llu "
                               "big_init_enter=%llu big_init_exit=%llu "
                               "pmic_wrap=%llu pmic_rmw=%llu\n",
                        static_cast<unsigned long long>(n),
                        static_cast<unsigned long long>(
                            hits_big_init.load(std::memory_order_relaxed)),
                        static_cast<unsigned long long>(
                            hits_big_init_exit.load(std::memory_order_relaxed)),
                        static_cast<unsigned long long>(
                            hits_pmic_wrap.load(std::memory_order_relaxed)),
                        static_cast<unsigned long long>(
                            hits_pmic_rmw.load(std::memory_order_relaxed)));
                }
            });

            tm.OnPc(0x80201A70u, [](const TraceContext& c) {
                LOG(Trace, "[BOOT] start-end PC=0x%08X CPSR=0x%08X SP=0x%08X "
                           "LR=0x%08X\n",
                    c.pc, c.cpsr, c.regs[13], c.regs[14]);
            });

            /* Track every SCTLR transition: settles whether the kernel ever
               runs XP=1 (bit23) — decides MMU-walker fix vs SCTLR-handler. */
            static std::atomic<uint32_t> last_sctlr{0xFFFFFFFFu};
            tm.OnRunLoopIter([](const TraceContext& c) {
                const uint32_t s = c.emu.Get<ArmMmu>().State()->control_register.word;
                if (s != last_sctlr.exchange(s, std::memory_order_relaxed)) {
                    LOG(Trace, "[BOOT] SCTLR=0x%08X M=%u XP(b23)=%u V(b13)=%u "
                               "pc=0x%08X lr=0x%08X pid=0x%08X\n",
                        s, s & 1u, (s >> 23) & 1u, (s >> 13) & 1u,
                        c.pc, c.regs[14],
                        c.emu.Get<ArmMmu>().State()->process_id);
                }
            });

            tm.OnPc(0x80213870u, [](const TraceContext& c) {
                LOG(Trace, "[BOOT] kernel-init entry PC=0x%08X CPSR=0x%08X "
                           "R0=0x%08X SP=0x%08X LR=0x%08X\n",
                    c.pc, c.cpsr, c.regs[0], c.regs[13], c.regs[14]);
            });

            tm.OnPc(0x8823D5DCu, [](const TraceContext& c) {
                const uint64_t n = hits_big_init.fetch_add(1, std::memory_order_relaxed);
                if (n < 4) {
                    LOG(Trace, "[BOOT] big_init enter n=%llu LR=0x%08X SP=0x%08X\n",
                        static_cast<unsigned long long>(n), c.regs[14], c.regs[13]);
                }
            });

            tm.OnPc(0x8823D87Cu, [](const TraceContext& c) {
                const uint64_t n = hits_big_init_exit.fetch_add(1, std::memory_order_relaxed);
                if (n < 4) {
                    LOG(Trace, "[BOOT] big_init exit n=%llu R0=0x%08X LR=0x%08X\n",
                        static_cast<unsigned long long>(n), c.regs[0], c.regs[14]);
                }
            });

            tm.OnPc(0x8823F320u, [](const TraceContext& c) {
                const uint64_t n = hits_pmic_wrap.fetch_add(1, std::memory_order_relaxed);
                if (n < 8) {
                    LOG(Trace, "[BOOT] pmic_wrap n=%llu R0=0x%08X R1=0x%08X LR=0x%08X\n",
                        static_cast<unsigned long long>(n),
                        c.regs[0], c.regs[1], c.regs[14]);
                }
            });

            tm.OnPc(0x8823F2D0u, [](const TraceContext& /*c*/) {
                hits_pmic_rmw.fetch_add(1, std::memory_order_relaxed);
            });

            /* Progress markers inside sub_8823D5DC after the PMIC wrap, to
               locate where big_init wedges. */
            static std::atomic<uint64_t> hits_timer_init{0};
            static std::atomic<uint64_t> hits_after_pmic{0};
            static std::atomic<uint64_t> hits_bigtail{0};
            tm.OnPc(0x8823C05Cu, [](const TraceContext& c) {
                const uint64_t n = hits_timer_init.fetch_add(1, std::memory_order_relaxed);
                if (n < 2) LOG(Trace, "[BOOT] timer_init(sub_8823C05C) n=%llu R0=%u R1=0x%08X R2=0x%08X\n",
                    static_cast<unsigned long long>(n), c.regs[0], c.regs[1], c.regs[2]);
            });
            tm.OnPc(0x8823F048u, [](const TraceContext& c) {
                const uint64_t n = hits_after_pmic.fetch_add(1, std::memory_order_relaxed);
                if (n < 2) LOG(Trace, "[BOOT] after_pmic(sub_8823F048) n=%llu R0=0x%08X\n",
                    static_cast<unsigned long long>(n), c.regs[0]);
            });
            tm.OnPc(0x88204D74u, [](const TraceContext& c) {
                const uint64_t n = hits_bigtail.fetch_add(1, std::memory_order_relaxed);
                if (n < 2) LOG(Trace, "[BOOT] big_tail(sub_88204D74) n=%llu R0=0x%08X\n",
                    static_cast<unsigned long long>(n), c.regs[0]);
            });

            /* sub_8823ED68 + 0x14: R0 = EPIT clock the kernel read from
               BSP_ARGS+0xE8 — the value driving the ms-tick scale. */
            static std::atomic<uint64_t> hits_epitclk{0};
            tm.OnPc(0x8823ED7Cu, [](const TraceContext& c) {
                const uint64_t n = hits_epitclk.fetch_add(1, std::memory_order_relaxed);
                if (n < 4) LOG(Trace, "[BOOT] epit_clk(sub_8823ED68)=%u (0x%08X)\n",
                    c.regs[0], c.regs[0]);
            });

            /* sub_88211588 dispatcher field offsets, from entry disasm:
               pCurThread=*(0xFFFFC894); v4=*(pCurThread+0x18); faultPC=*(v4+4);
               *(v4+0xC) lo-byte=signed type / hi16=FSR; BVA=*(v4+0x10).
               type: -1=SW/PSL, 1=undef-instr, 3=data-abort, 4=prefetch-abort. */
            static std::atomic<uint64_t> hits_dispatch{0};
            tm.OnPc(0x88211588u, [](const TraceContext& c) {
                const uint64_t n = hits_dispatch.fetch_add(1, std::memory_order_relaxed);
                if (n >= 64 && (n & 0xFFF) != 0) return;
                uint32_t fpc = 0, typfsr = 0, bva = 0;
                auto pcur = c.ReadVa32(0xFFFFC894u);
                if (pcur) {
                    auto v4 = c.ReadVa32(*pcur + 0x18u);
                    if (v4) {
                        auto a = c.ReadVa32(*v4 + 0x04u);
                        auto b = c.ReadVa32(*v4 + 0x0Cu);
                        auto d = c.ReadVa32(*v4 + 0x10u);
                        fpc    = a ? *a : 0;
                        typfsr = b ? *b : 0;
                        bva    = d ? *d : 0;
                    }
                }
                LOG(Trace, "[BOOT] exc-dispatch n=%llu type=%d fsr=0x%04X "
                           "faultPC=0x%08X BVA=0x%08X a1=0x%08X LR=0x%08X "
                           "cpsr=0x%08X\n",
                    static_cast<unsigned long long>(n),
                    static_cast<int>(static_cast<int8_t>(typfsr & 0xFF)),
                    (typfsr >> 16) & 0xFFFF, fpc, bva,
                    c.regs[0], c.regs[14], c.cpsr);

                /* Settle CERF-bug vs kernel-never-maps for the frozen
                   data-abort: walk the live guest L1/L2 descriptor for the
                   fault VA. Kernel cached-DRAM mapping is VA=PA+0x08000000
                   (tick counter PA 0x80FDE934 = VA 0x88FDE934). */
                static std::atomic<uint64_t> dumped{0};
                if (bva == 0x06170000u &&
                    dumped.fetch_add(1, std::memory_order_relaxed) < 6) {
                    auto* st = c.emu.Get<ArmMmu>().State();
                    const uint32_t ttbr = st->translation_table_base.word & 0xFFFFC000u;
                    const uint32_t l1pa = ttbr + ((bva >> 20) << 2);
                    auto l1 = c.ReadVa32(l1pa + 0x08000000u);
                    uint32_t l2d = 0; bool l2ok = false;
                    if (l1 && (*l1 & 3u) == 1u) {
                        const uint32_t l2pa =
                            (*l1 & 0xFFFFFC00u) + (((bva >> 12) & 0xFFu) << 2);
                        auto l2 = c.ReadVa32(l2pa + 0x08000000u);
                        if (l2) { l2d = *l2; l2ok = true; }
                    }
                    auto instr = c.ReadVa32(fpc);
                    LOG(Trace, "[BOOT] PTE-dump bva=0x%08X ttbr0=0x%08X "
                               "l1desc=%s0x%08X l2desc=%s0x%08X contextidr=0x%08X "
                               "procid=0x%08X fsr=0x%08X far=0x%08X "
                               "instr@faultPC=%s0x%08X sctlr=0x%08X\n",
                        bva, ttbr,
                        l1 ? "" : "(nomap)", l1 ? *l1 : 0,
                        l2ok ? "" : "(n/a)", l2d,
                        st->contextidr, st->process_id,
                        st->fault_status.word, st->fault_address,
                        instr ? "" : "(nomap)", instr ? *instr : 0,
                        st->control_register.word);
                }
            });

        });
    }
};

}  /* namespace */

REGISTER_SERVICE(ZuneKeelBootProgress);

#endif  /* CERF_DEV_MODE */
