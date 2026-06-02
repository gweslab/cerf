#include "../trace_manager.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../jit/arm_cpu.h"
#include "../../jit/cpu_state.h"
#include "../../jit/arm_mmu.h"
#include "../../jit/arm_mmu_state.h"
#include "bundle.h"

#include <atomic>
#include <cstdint>
#include <cstring>

#if CERF_DEV_MODE

namespace {

constexpr uint32_t kKernelStartVa = 0x80040000u;
constexpr uint32_t kKernelEndVa   = 0x8008E000u;
constexpr uint32_t kCoredllStart  = 0x8017C000u;
constexpr uint32_t kCoredllEnd    = 0x801E6000u;
constexpr uint32_t kHookStride    = 0x100u;

class Ppc2002StuckPcProbe : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kPpc2002BundleCrc32, [&] {
            InstallHooksOverRange(tm, kKernelStartVa, kKernelEndVa);
            InstallHooksOverRange(tm, kCoredllStart,  kCoredllEnd);
            LOG(Trace, "[STUCK_PROBE] installed OnPc hooks across "
                       "nk.exe [0x%08X..0x%08X) and coredll [0x%08X..0x%08X) "
                       "stride=0x%X\n",
                kKernelStartVa, kKernelEndVa,
                kCoredllStart,  kCoredllEnd, kHookStride);

            /* 0x800606DC = data-abort fast path, AFTER MRC reads
               of R0=FAR, R1=FSR. R2 will be loaded with FCSE_PID
               next; sample here so we see the raw FAR before the
               TST/ORREQ slot-0 translation. */
            tm.OnPc(0x800606DCu, [](const TraceContext& c) {
                static std::atomic<uint64_t> sample_count{0};
                static std::atomic<uint32_t> last_l1_F00{0xDEADBEEFu};
                const uint32_t k = static_cast<uint32_t>(
                    sample_count.fetch_add(1, std::memory_order_relaxed));
                /* TTBR0_VA = 0x8C0C0000. L1[0xF00] for VA 0xF0000000-
                   0xF00FFFFF section is at TTBR0_VA + 0xF00*4. */
                auto l1_F00 = c.ReadVa32(0x8C0C0000u + 0xF00u * 4u);
                if (!l1_F00) return;
                const uint32_t now = *l1_F00;
                const uint32_t prev = last_l1_F00.exchange(now, std::memory_order_relaxed);
                if (k < 5 || now != prev) {
                    LOG(Trace, "[L1F00] k=%u L1[0xF00 for 0xF000_0000]: "
                               "0x%08X -> 0x%08X FAR=0x%08X\n",
                        k, prev, now, c.regs[0]);
                }
            });

            /* 0x800606F8 = right after BLEQ sub_80069FF0 returns.
               R0 = return value (0 = unfixable). When R0=0 we're
               about to enter the inf loop at 0x80060700. */
            tm.OnPc(0x800606F8u, [](const TraceContext& c) {
                static std::atomic<uint64_t> nfix{0};
                static std::atomic<uint64_t> nfail{0};
                const bool failed = (c.regs[0] == 0);
                const uint64_t k = failed
                    ? nfail.fetch_add(1, std::memory_order_relaxed)
                    : nfix.fetch_add(1, std::memory_order_relaxed);
                if (k < 20 || (k & 0xFFFFu) == 0u) {
                    LOG(Trace, "[FIX_RET] failed=%d k=%llu R0=0x%08X R1=0x%08X "
                               "R2=0x%08X R3=0x%08X lr=0x%08X sp=0x%08X\n",
                        failed ? 1 : 0,
                        static_cast<unsigned long long>(k),
                        c.regs[0], c.regs[1], c.regs[2], c.regs[3],
                        c.regs[14], c.regs[13]);
                }
            });

            /* 0x800606AC = right after MSR CPSR_fc, R2 at 0x800606A8.
               c.regs[13] = SP_<oldmode> after the mode switch.
               c.cpsr = CPSR after MSR. R2 still holds the SPSR value. */
            /* 0x8006066C = MSR SPSR_fc, R2 — sets SPSR_svc = R2 right
               before MOVS PC, LR. R2 should hold the ORIGINAL SPSR
               (mode of the faulted code), loaded from frame at 0x80060638. */
            /* 0x80060A74 = SUB SP, SP, #0x48 — first instruction of a kernel
               function that's a frequent MOVS PC, LR return target (XRET LR).
               After return CPSR.mode should be SYS (0x1F). If it's ABT (0x17),
               that confirms the JIT didn't transition mode on MOVS PC, LR. */
            /* Track inside fast-path of abort handler — sub_80069FF0
               page-table walk steps. Any of these LDRs faulting from ABT
               mode triggers a recursive abort. */
            /* sub_80069D68 entry — the big abort handler. If reached,
               kernel is past the cascade and into actual fault resolution. */
            /* sub_80069D68 RETURN PC — log return value (R0 = thread struct or 0). */
            tm.OnPc(0x80069FC4u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                if (k < 30 || (k & 0xFFFu) == 0u) {
                    LOG(Trace, "[BIG_RET] k=%llu R0=0x%08X sp=0x%08X lr=0x%08X "
                               "cpsr=0x%08X\n",
                        static_cast<unsigned long long>(k),
                        c.regs[0], c.regs[13], c.regs[14], c.cpsr);
                }
            });

            tm.OnPc(0x8006A248u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                if (k < 50 || (k & 0xFFFu) == 0u) {
                    LOG(Trace, "[A248_ENT] k=%llu R0=0x%08X cpsr=0x%08X lr=0x%08X\n",
                        static_cast<unsigned long long>(k),
                        c.regs[0], c.cpsr, c.regs[14]);
                }
            });
            tm.OnPc(0x8006A654u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                if (k < 30 || (k & 0xFFFu) == 0u) {
                    LOG(Trace, "[A248_BL] k=%llu v12=R9=%d v11=R10=0x%08X\n",
                        static_cast<unsigned long long>(k),
                        static_cast<int32_t>(c.regs[9]), c.regs[10]);
                }
            });
            tm.OnPc(0x8006A328u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                if (k < 50 || (k & 0xFFFu) == 0u) {
                    LOG(Trace, "[A248_v12] k=%llu v12=R9=%d v11=R10=0x%08X\n",
                        static_cast<unsigned long long>(k),
                        static_cast<int32_t>(c.regs[9]), c.regs[10]);
                }
            });
            tm.OnPc(0x8006A26Cu, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                if (k < 50 || (k & 0xFFFu) == 0u) {
                    auto v4_val = c.ReadVa32(c.regs[6]);
                    LOG(Trace, "[A248_V4] k=%llu R6(v4)=0x%08X *v4=0x%08X "
                               "(*v4)&1=%u\n",
                        static_cast<unsigned long long>(k),
                        c.regs[6], v4_val.value_or(0xDEADBEEFu),
                        v4_val.value_or(0) & 1u);
                }
            });
            tm.OnPc(0x8007E18Cu, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                if (k < 200 || (k & 0xFFFu) == 0u) {
                    LOG(Trace, "[SOFTTLB_POP] k=%llu FAR=0x%08X lr=0x%08X\n",
                        static_cast<unsigned long long>(k),
                        c.regs[0], c.regs[14]);
                }
            });

            tm.OnPc(0x8007E054u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                if (k < 200 || (k & 0xFFFu) == 0u) {
                    LOG(Trace, "[E054_POP] k=%llu R0=0x%08X lr=0x%08X cpsr=0x%08X\n",
                        static_cast<unsigned long long>(k),
                        c.regs[0], c.regs[14], c.cpsr);
                }
            });

            tm.OnPc(0x8006794Cu, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                if (k < 200 || (k & 0xFFFu) == 0u) {
                    LOG(Trace, "[SEH_WALK] k=%llu R0=0x%08X R1=0x%08X R2=0x%08X lr=0x%08X cpsr=0x%08X\n",
                        static_cast<unsigned long long>(k),
                        c.regs[0], c.regs[1], c.regs[2],
                        c.regs[14], c.cpsr);
                }
            });

            tm.OnPc(0x80080038u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                if (k < 200 || (k & 0xFFFu) == 0u) {
                    LOG(Trace, "[K80038] k=%llu R0=0x%08X R1=0x%08X R2=0x%08X R3=0x%08X lr=0x%08X cpsr=0x%08X\n",
                        static_cast<unsigned long long>(k),
                        c.regs[0], c.regs[1], c.regs[2], c.regs[3],
                        c.regs[14], c.cpsr);
                }
            });

            tm.OnPc(0x8007E1FCu, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                if (k < 200 || (k & 0xFFFu) == 0u) {
                    LOG(Trace, "[E1FC] k=%llu R0=0x%08X R1=0x%08X lr=0x%08X cpsr=0x%08X\n",
                        static_cast<unsigned long long>(k),
                        c.regs[0], c.regs[1], c.regs[14], c.cpsr);
                }
            });

            tm.OnPc(0x8006A344u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                if (k < 200 || (k & 0xFFFu) == 0u) {
                    LOG(Trace, "[A248_CASE4_PRE_E054] k=%llu R0=R10=0x%08X R9=v12=%d R5=v13=0x%04X lr=0x%08X cpsr=0x%08X\n",
                        static_cast<unsigned long long>(k),
                        c.regs[0], static_cast<int32_t>(c.regs[9]),
                        c.regs[5] & 0xFFFFu, c.regs[14], c.cpsr);
                }
            });

            tm.OnPc(0x8006A518u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                if (k < 200 || (k & 0xFFFu) == 0u) {
                    LOG(Trace, "[A248_PRE_SEH1] k=%llu R9=v12=%d R10=v11=0x%08X cpsr=0x%08X\n",
                        static_cast<unsigned long long>(k),
                        static_cast<int32_t>(c.regs[9]), c.regs[10], c.cpsr);
                }
            });

            tm.OnPc(0x8006A588u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                if (k < 200 || (k & 0xFFFu) == 0u) {
                    LOG(Trace, "[A248_PRE_K80038] k=%llu R9=v12=%d cpsr=0x%08X\n",
                        static_cast<unsigned long long>(k),
                        static_cast<int32_t>(c.regs[9]), c.cpsr);
                }
            });

            tm.OnPc(0x8007BFF0u, [](const TraceContext& c) {
                if (c.regs[0] != 5) return;
                LOG(Trace, "[HEAP5_ENT] R0=heap_id=5 lr=0x%08X\n", c.regs[14]);
            });
            tm.OnPc(0x8007C058u, [](const TraceContext& c) {
                LOG(Trace, "[HEAP_RET] R0_result=0x%08X\n", c.regs[0]);
            });

            tm.OnPc(0x80069D68u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                if (k < 200 || (k & 0xFFFu) == 0u) {
                    LOG(Trace, "[BIG_HANDLER] k=%llu R0=0x%08X R1=0x%08X "
                               "R2=0x%08X R3=0x%08X sp=0x%08X lr=0x%08X cpsr=0x%08X\n",
                        static_cast<unsigned long long>(k),
                        c.regs[0], c.regs[1], c.regs[2], c.regs[3],
                        c.regs[13], c.regs[14], c.cpsr);
                }
            });

            tm.OnPc(0x80058838u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                if (k < 10 || (k & 0xFFFFu) == 0u) {
                    LOG(Trace, "[OST_SPIN] k=%llu OSMR0=R11=0x%08X OSCR=R3_pre=? "
                               "diff_R3_post=0x%08X (=OSMR0-OSCR)\n",
                        static_cast<unsigned long long>(k),
                        c.regs[11], c.regs[3]);
                }
            });

            tm.OnPc(0x8005C3E4u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                LOG(Trace, "[DELAYMS_ENT] k=%llu R0_ms=%d lr=0x%08X\n",
                    static_cast<unsigned long long>(k),
                    static_cast<int32_t>(c.regs[0]), c.regs[14]);
            });

            tm.OnPc(0x8005C418u, [](const TraceContext& c) {
                (void)c;
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                LOG(Trace, "[DELAYMS_EXIT] k=%llu\n",
                    static_cast<unsigned long long>(k));
            });

            /* Poll thread 0x8FF66000 saved context PC at +0x9C; log every
               change. If it stays the same across many IRQs, the thread is
               in a tight loop at that PC. */
            tm.OnRunLoopIter([](const TraceContext& c) {
                static std::atomic<uint32_t> last_pc{0xCAFEBABEu};
                static std::atomic<uint64_t> tick{0};
                const uint64_t k = tick.fetch_add(1, std::memory_order_relaxed);
                auto pc = c.ReadVa32(0x8FF66000u + 0x9Cu);
                if (!pc) return;
                const uint32_t prev = last_pc.exchange(*pc, std::memory_order_relaxed);
                if (*pc != prev) {
                    LOG(Trace, "[THR66K_PC] iter=%llu ctx.pc 0x%08X -> 0x%08X\n",
                        static_cast<unsigned long long>(k), prev, *pc);
                }
            });

            /* Poll kernel CurMSec at 0x8C0D3600 (the tick counter incremented
               by sub_800585C8's OST branch). If it stops advancing, the
               OST IRQ branch isn't being taken — wrong INTPEND bit. */
            tm.OnRunLoopIter([](const TraceContext& c) {
                static std::atomic<uint32_t> last_ms{0xCAFEBABEu};
                static std::atomic<uint64_t> tick{0};
                static std::atomic<uint64_t> last_change_tick{0};
                const uint64_t k = tick.fetch_add(1, std::memory_order_relaxed);
                auto ms = c.ReadVa32(0x8C0D3600u);
                if (!ms) return;
                const uint32_t prev = last_ms.exchange(*ms, std::memory_order_relaxed);
                if (*ms != prev) {
                    const uint64_t prev_k = last_change_tick.exchange(k,
                        std::memory_order_relaxed);
                    LOG(Trace, "[CURMS] iter=%llu (gap=%llu) 0x8C0D3600: 0x%08X -> 0x%08X\n",
                        static_cast<unsigned long long>(k),
                        static_cast<unsigned long long>(k - prev_k),
                        prev, *ms);
                }
            });

            /* Sample SA1110 INTPEND (0xA9050000) every JIT iteration. Log
               every distinct value. Tells us which IRQ bits the kernel
               sees set at handler entry. */
            tm.OnRunLoopIter([](const TraceContext& c) {
                static std::atomic<uint32_t> last_pend{0xCAFEBABEu};
                static std::atomic<uint64_t> tick{0};
                const uint64_t k = tick.fetch_add(1, std::memory_order_relaxed);
                auto pend = c.ReadVa32(0xA9050000u);
                if (!pend) return;
                const uint32_t prev = last_pend.exchange(*pend, std::memory_order_relaxed);
                if (*pend != prev) {
                    LOG(Trace, "[INTPEND] iter=%llu ICIP 0xA9050000: 0x%08X -> 0x%08X\n",
                        static_cast<unsigned long long>(k), prev, *pend);
                }
            });

            /* Hook idle/halt sub_8005D328 — the halt-wait kernel calls when
               no thread is runnable. */
            tm.OnPc(0x8005D328u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                if (k < 20 || (k & 0xFFu) == 0u) {
                    LOG(Trace, "[IDLE_ENT] k=%llu R0=0x%08X\n",
                        static_cast<unsigned long long>(k), c.regs[0]);
                }
            });

            tm.OnPc(0x80064020u, [](const TraceContext& c) {
                auto cur = c.ReadVa32(0xFFFFC894u);
                if (!cur || *cur != 0x8FF66000u) return;
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                auto polled = c.ReadVa32(0xA801000Cu);
                if (k < 30 || (k & 0xFFu) == 0u) {
                    LOG(Trace, "[WAIT_ENT_66K] k=%llu R1_timeout=%u "
                               "*(0xA801000C)=0x%08X (bit0x10=%d)\n",
                        static_cast<unsigned long long>(k),
                        c.regs[1], polled.value_or(0xDEADBEEFu),
                        polled ? ((*polled & 0x10) ? 1 : 0) : -1);
                }
            });

            /* Hook keybddr.dll Sleep(1) loop just after the LDR — captures
               R0 = base ptr keybddr is using, R3 = value just loaded.
               Tells us what value CERF returns for the polled address. */
            tm.OnPcFiltered(0x01F33BD4u,
                [](const TraceContext& c) {
                    auto cur = c.ReadVa32(0xFFFFC894u);
                    return cur && *cur == 0x8FF66000u;
                },
                [](const TraceContext& c) {
                    static std::atomic<uint64_t> n{0};
                    const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                    if (k < 15 || (k & 0xFFu) == 0u) {
                        LOG(Trace, "[KEYBDDR_POLL] k=%llu base_R0=0x%08X "
                                   "loaded_R3=0x%08X bit0x10=%d\n",
                            static_cast<unsigned long long>(k),
                            c.regs[0], c.regs[3],
                            (c.regs[3] & 0x10) ? 1 : 0);
                    }
                });

            /* OnPc hook at user VA 0x01FA187C with thread filter — fires
               when thread 0x8FF66000 reaches the userspace polling site.
               Dumps register state + LR + a few bytes around. */
            tm.OnPcFiltered(0x01FA187Cu,
                [](const TraceContext& c) {
                    auto cur = c.ReadVa32(0xFFFFC894u);
                    return cur && *cur == 0x8FF66000u;
                },
                [](const TraceContext& c) {
                    static std::atomic<uint64_t> n{0};
                    const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                    if (k < 10 || (k & 0xFFu) == 0u) {
                        LOG(Trace, "[USER_PC_HIT] k=%llu R0=0x%08X R1=0x%08X "
                                   "R2=0x%08X R3=0x%08X sp=0x%08X lr=0x%08X "
                                   "cpsr=0x%08X\n",
                            static_cast<unsigned long long>(k),
                            c.regs[0], c.regs[1], c.regs[2], c.regs[3],
                            c.regs[13], c.regs[14], c.cpsr);
                    }
                    if (k == 0) {
                        LOG(Trace, "[USER_PC_HIT] bytes around 0x01FA1860:\n");
                        for (uint32_t off = 0; off < 0x40; off += 4) {
                            auto v = c.ReadVa32(0x01FA1860u + off);
                            LOG(Trace, "[USER_PC_HIT]   +0x%02X (va=0x%08X) = 0x%08X\n",
                                off, 0x01FA1860u + off, v.value_or(0xDEADBEEFu));
                        }
                    }
                });

            /* One-shot at t+8s+ — walk kernel sleep list at 0x8C0D4DF0,
               dump each thread + its wait_obj. The threads in this list
               are all the blocked threads we can't see otherwise. */
            tm.OnRunLoopIter([](const TraceContext& c) {
                static std::atomic<bool> done{false};
                if (done.load(std::memory_order_relaxed)) return;
                /* Wait until at least one CURTHREAD-switch happened past t=8s.
                   Approximate via guest tick advance — use M[0x8C0D3600] CurMSec. */
                auto curms = c.ReadVa32(0x8C0D3600u);
                if (!curms || *curms < 0x2000u) return;  /* ~8s into simulated boot */
                bool exp = false;
                if (!done.compare_exchange_strong(exp, true)) return;
                /* Walk MEMORY[0x8C0D4DF0] as head of thread sleep list.
                   Each thread has +160 (=0xA0) = next pointer per sub_80063ED0. */
                auto head = c.ReadVa32(0x8C0D4DF0u);
                LOG(Trace, "[BLOCKED_LIST] head=0x%08X\n",
                    head.value_or(0xDEADBEEFu));
                uint32_t cur = head.value_or(0);
                int idx = 0;
                while (cur && idx < 30) {
                    auto next = c.ReadVa32(cur + 0xA0u);
                    auto wake = c.ReadVa32(cur + 0x28u);  /* +40 = wake target */
                    auto pc   = c.ReadVa32(cur + 0x9Cu);  /* +0x9C = ctx PC */
                    auto pri  = c.ReadVa32(cur + 0x14u);  /* +0x14 = priority */
                    LOG(Trace, "[BLOCKED] [%d] thr=0x%08X prio=%u "
                               "wake_target=0x%08X ctx.pc=0x%08X next=0x%08X\n",
                        idx, cur, pri.value_or(0),
                        wake.value_or(0), pc.value_or(0),
                        next.value_or(0));
                    cur = next.value_or(0);
                    ++idx;
                }
                LOG(Trace, "[BLOCKED] total walked=%d\n", idx);
            });

            /* Dump thread 8FF5B400 + 8FF4D0A4 structures (the two waiters
               on 8FF66000) — fields tell us which process owns them. */
            tm.OnRunLoopIter([](const TraceContext& c) {
                static std::atomic<bool> done5B{false};
                static std::atomic<bool> done4D{false};
                if (!done5B.load(std::memory_order_relaxed)) {
                    auto cur = c.ReadVa32(0xFFFFC894u);
                    if (cur && *cur == 0x8FF5B400u) {
                        bool exp = false;
                        if (done5B.compare_exchange_strong(exp, true)) {
                            LOG(Trace, "[THR_5B400_DUMP]\n");
                            for (uint32_t off = 0; off <= 0xB0; off += 4) {
                                auto v = c.ReadVa32(0x8FF5B400u + off);
                                LOG(Trace, "[THR_5B400] +0x%02X = 0x%08X\n",
                                    off, v.value_or(0xDEADBEEFu));
                            }
                        }
                    }
                }
                if (!done4D.load(std::memory_order_relaxed)) {
                    auto cur = c.ReadVa32(0xFFFFC894u);
                    if (cur && *cur == 0x8FF4D0A4u) {
                        bool exp = false;
                        if (done4D.compare_exchange_strong(exp, true)) {
                            LOG(Trace, "[THR_4D0A4_DUMP]\n");
                            for (uint32_t off = 0; off <= 0xB0; off += 4) {
                                auto v = c.ReadVa32(0x8FF4D0A4u + off);
                                LOG(Trace, "[THR_4D0A4] +0x%02X = 0x%08X\n",
                                    off, v.value_or(0xDEADBEEFu));
                            }
                        }
                    }
                }
            });

            /* Hook sub_80063ED0 entry = the wait-condition callback called
               from sub_800609E4. a1 = wait struct; *(a1) = current wait
               object (or 0 for fresh). Tells us which thread is waiting
               on what object. */
            tm.OnPc(0x80063ED0u, [](const TraceContext& c) {
                auto cur = c.ReadVa32(0xFFFFC894u);
                auto a1 = c.regs[0];
                auto wait_obj = c.ReadVa32(a1);
                auto wait_tok = c.ReadVa32(a1 + 4u);
                auto wait_tgt = c.ReadVa32(a1 + 8u);
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                if (k < 50 || (k & 0xFFu) == 0u) {
                    LOG(Trace, "[WAITCB] k=%llu CURTHR=0x%08X a1=0x%08X "
                               "wait_obj=0x%08X token=0x%08X target=0x%08X "
                               "lr=0x%08X\n",
                        static_cast<unsigned long long>(k),
                        cur.value_or(0), a1,
                        wait_obj.value_or(0xDEADBEEFu),
                        wait_tok.value_or(0xDEADBEEFu),
                        wait_tgt.value_or(0xDEADBEEFu),
                        c.regs[14]);
                }
            });

            /* Unfiltered intentional — adding a filter breaks enumeration. */
            tm.OnPc(0x01FA1880u, [](const TraceContext& c) {
                auto cur = c.ReadVa32(0xFFFFC894u);
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                LOG(Trace, "[NEW_THREAD] k=%llu CURTHR=0x%08X proc_R0=0x%08X "
                           "arg_R1=0x%08X\n",
                    static_cast<unsigned long long>(k),
                    cur.value_or(0), c.regs[0], c.regs[1]);
            });

            /* Unfiltered intentional — a process filter would drop every
               CreateThread call in every other process, defeating enumeration. */
            tm.OnPc(0x01F9D998u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                auto cur = c.ReadVa32(0xFFFFC894u);
                LOG(Trace, "[CT] k=%llu CURTHR=0x%08X "
                           "R0=0x%08X R1=0x%08X R2=0x%08X R3=0x%08X "
                           "lr=0x%08X\n",
                    static_cast<unsigned long long>(k), cur.value_or(0),
                    c.regs[0], c.regs[1], c.regs[2], c.regs[3], c.regs[14]);
            });

            /* Unfiltered intentional — every process's main thread enters
               via this address; filter would drop all but one process. */
            tm.OnPc(0x01FA1794u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                auto cur = c.ReadVa32(0xFFFFC894u);
                LOG(Trace, "[MAIN_THR] k=%llu CURTHR=0x%08X "
                           "entry_R0=0x%08X R1=0x%08X R2=0x%08X "
                           "R3=0x%08X lr=0x%08X\n",
                    static_cast<unsigned long long>(k), cur.value_or(0),
                    c.regs[0], c.regs[1], c.regs[2], c.regs[3], c.regs[14]);
            });

            /* sub_8006A92C = kernel thread-init. R0 = new TCB, R3 = entry.
               R3 == trampoline(0x8006FA7C) marks a process MAIN thread; pair
               with the preceding CREATE_PROC name to map name->TCB reliably
               (the trampoline arg-block name is racy across reused slots). */
            tm.OnPc(0x8006A92Cu, [](const TraceContext& c) {
                if (c.regs[3] != 0x8006FA7Cu) return;
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                LOG(Trace, "[MAINTHR_NEW] k=%llu new_TCB=0x%08X entry_R3=0x%08X "
                           "lr=0x%08X\n",
                    static_cast<unsigned long long>(k), c.regs[0], c.regs[3],
                    c.regs[14]);
            });

            /* sub_8006FA7C entry = process-startup trampoline. Fires when a
               main thread first runs. *(R1) = EXE name ptr. Absence of a
               process here means its main thread was never scheduled. */
            tm.OnPc(0x8006FA7Cu, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                auto cur = c.ReadVa32(0xFFFFC894u);
                wchar_t name[17] = {};
                auto nameptr = c.ReadVa32(c.regs[1]);
                if (nameptr) {
                    for (int i = 0; i < 16; ++i) {
                        auto w = c.ReadVa32(*nameptr + i * 2);
                        if (!w) break;
                        name[i] = static_cast<wchar_t>(*w & 0xFFFF);
                        if (name[i] == 0) break;
                    }
                }
                uint32_t prio = 0xFF;
                if (cur) { auto p = c.ReadVa8(*cur + 0x41u); if (p) prio = *p; }
                LOG(Trace, "[TRAMP_ENTRY] k=%llu CURTHR=0x%08X prio=%u "
                           "name=%ls R0=0x%08X R1=0x%08X\n",
                    static_cast<unsigned long long>(k), cur.value_or(0),
                    prio, name, c.regs[0], c.regs[1]);
            });

            /* Trampoline PE-load sequence points: sub_8006FA7C calls these
               in order before the sub_8006A9AC landmark. The last one a
               failing process reaches localizes where load aborts. */
            tm.OnPc(0x8006E1BCu, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                auto cur = c.ReadVa32(0xFFFFC894u);
                LOG(Trace, "[TRAMP_E1BC] k=%llu CURTHR=0x%08X lr=0x%08X\n",
                    static_cast<unsigned long long>(k), cur.value_or(0),
                    c.regs[14]);
            });
            tm.OnPc(0x8006F240u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                auto cur = c.ReadVa32(0xFFFFC894u);
                LOG(Trace, "[TRAMP_F240] k=%llu CURTHR=0x%08X lr=0x%08X\n",
                    static_cast<unsigned long long>(k), cur.value_or(0),
                    c.regs[14]);
            });
            /* +4: STUCK_PROBE owns the 0x100-aligned 0x8006DC00. */
            tm.OnPc(0x8006DC04u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                auto cur = c.ReadVa32(0xFFFFC894u);
                LOG(Trace, "[TRAMP_DC00] k=%llu CURTHR=0x%08X lr=0x%08X\n",
                    static_cast<unsigned long long>(k), cur.value_or(0),
                    c.regs[14]);
            });
            /* Trampoline aborts with error 14 when 0x8C0CA110 == 31. */
            tm.OnRunLoopIter([](const TraceContext& c) {
                static std::atomic<uint32_t> last{0xCAFEBABEu};
                auto v = c.ReadVa32(0x8C0CA110u);
                if (!v) return;
                const uint32_t prev = last.exchange(*v,
                    std::memory_order_relaxed);
                if (*v != prev) {
                    LOG(Trace, "[CA110] 0x8C0CA110: 0x%08X -> 0x%08X\n",
                        prev, *v);
                }
            });

            /* sub_8006A9AC: process-startup-trampoline success-path landmark
               (builds user-mode stack args, reached only after PE load +
               section map succeed). CURTHR identifies which main thread. */
            tm.OnPc(0x8006A9ACu, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                auto cur = c.ReadVa32(0xFFFFC894u);
                LOG(Trace, "[TRAMP_USERARG] k=%llu CURTHR=0x%08X "
                           "R0=0x%08X R1=0x%08X R2=0x%08X R3=0x%08X "
                           "lr=0x%08X\n",
                    static_cast<unsigned long long>(k), cur.value_or(0),
                    c.regs[0], c.regs[1], c.regs[2], c.regs[3], c.regs[14]);
            });

            /* Poll shell32.exe main thread (= 0x8FF47748 in current run) for
               its saved-context PC (TCB+0x9C). When it's not CURTHREAD, this
               shows where it parked (= entry to a kernel wait stub). */
            tm.OnRunLoopIter([](const TraceContext& c) {
                static std::atomic<uint32_t> last_pc{0xCAFEBABEu};
                auto pc = c.ReadVa32(0x8FF47748u + 0x9Cu);
                if (!pc) return;
                const uint32_t prev = last_pc.exchange(*pc,
                    std::memory_order_relaxed);
                if (*pc != prev) {
                    LOG(Trace, "[SHELL32_PC] 0x8FF47748+0x9C: "
                               "0x%08X -> 0x%08X\n", prev, *pc);
                }
            });

            /* Unfiltered intentional — a process filter would drop every
               CreateProcessW call in every other process. */
            tm.OnPc(0x01F9D908u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                auto cur = c.ReadVa32(0xFFFFC894u);
                wchar_t name[17] = {};
                for (int i = 0; i < 16; ++i) {
                    auto w = c.ReadVa32(c.regs[0] + i * 2);
                    if (!w) break;
                    name[i] = static_cast<wchar_t>(*w & 0xFFFF);
                    if (name[i] == 0) break;
                }
                LOG(Trace, "[CPW] k=%llu CURTHR=0x%08X name=%ls "
                           "R0=0x%08X lr=0x%08X\n",
                    static_cast<unsigned long long>(k), cur.value_or(0),
                    name, c.regs[0], c.regs[14]);
            });

            tm.OnPc(0x80074DA0u, [](const TraceContext& c) {
                (void)c;
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                LOG(Trace, "[RUNAPPS_ENT] k=%llu\n",
                    static_cast<unsigned long long>(k));
            });

            tm.OnPc(0x80074E0Cu, [](const TraceContext& c) {
                (void)c;
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                LOG(Trace, "[RUNAPPS_FILESYS_LAUNCHED] k=%llu\n",
                    static_cast<unsigned long long>(k));
            });

            tm.OnPc(0x80074E20u, [](const TraceContext& c) {
                (void)c;
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                LOG(Trace, "[RUNAPPS_FILESYS_SIGNALED] k=%llu\n",
                    static_cast<unsigned long long>(k));
            });

            tm.OnPc(0x80074E34u, [](const TraceContext& c) {
                (void)c;
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                LOG(Trace, "[RUNAPPS_POST_REGISTER] k=%llu\n",
                    static_cast<unsigned long long>(k));
            });

            /* Hook sub_80068B40 entry = kernel CreateProcess. R0 = wide-char
               name pointer of process being launched. Capture each launch. */
            tm.OnPc(0x80068B40u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                /* Read up to 16 wchars (32 bytes) of the name pointer. */
                wchar_t name[17] = {};
                for (int i = 0; i < 16; ++i) {
                    auto w = c.ReadVa32(c.regs[0] + i * 2);
                    if (!w) break;
                    name[i] = static_cast<wchar_t>(*w & 0xFFFF);
                    if (name[i] == 0) break;
                }
                LOG(Trace, "[CREATE_PROC] k=%llu R0=0x%08X name=%ls "
                           "lr=0x%08X\n",
                    static_cast<unsigned long long>(k),
                    c.regs[0], name, c.regs[14]);
            });

            /* Hook sub_80065B80 entry = kernel WaitForApi/wait-for-signal.
               R1 = signal id. */
            tm.OnPc(0x80065B80u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                if (k < 20 || (k & 0xFFu) == 0u) {
                    LOG(Trace, "[WAITAPI] k=%llu R0=0x%08X R1=0x%08X R3=0x%08X "
                               "lr=0x%08X\n",
                        static_cast<unsigned long long>(k),
                        c.regs[0], c.regs[1], c.regs[3], c.regs[14]);
                }
            });

            /* Track every change in MEMORY[0xFFFFC800] (pCurPrc) and
               MEMORY[0x8C0D4E24] (next-thread). The process struct ptr +
               whatever process owns the stuck thread. */
            tm.OnRunLoopIter([](const TraceContext& c) {
                static std::atomic<uint32_t> last_proc{0xCAFEBABEu};
                static std::atomic<uint64_t> tick{0};
                const uint64_t k = tick.fetch_add(1, std::memory_order_relaxed);
                auto pproc = c.ReadVa32(0xFFFFC800u);
                if (!pproc) return;
                const uint32_t prev = last_proc.exchange(*pproc,
                    std::memory_order_relaxed);
                if (*pproc != prev) {
                    /* CE3 process struct: name pointer typically at +0x8C or
                       similar. Dump bytes around to find name. */
                    auto name_ptr = c.ReadVa32(*pproc + 0x8Cu);
                    LOG(Trace, "[PCURPRC] iter=%llu MEMORY[0xFFFFC800] "
                               "0x%08X -> 0x%08X name_ptr@+0x8C=0x%08X\n",
                        static_cast<unsigned long long>(k),
                        prev, *pproc, name_ptr.value_or(0xDEADBEEFu));
                    for (uint32_t off = 0; off <= 0xC0; off += 4) {
                        auto v = c.ReadVa32(*pproc + off);
                        LOG(Trace, "[PCURPRC] proc+0x%02X = 0x%08X\n",
                            off, v.value_or(0xDEADBEEFu));
                    }
                }
            });

            tm.OnPc(0x8008B008u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                if (k < 20 || (k & 0xFFu) == 0u) {
                    LOG(Trace, "[WFI_ENT] k=%llu R0=0x%08X lr=0x%08X\n",
                        static_cast<unsigned long long>(k), c.regs[0], c.regs[14]);
                }
            });

            /* Hook sub_8008B000 return (last instruction). */
            tm.OnPc(0x8008B01Cu, [](const TraceContext& c) {
                (void)c;
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                if (k < 20 || (k & 0xFFu) == 0u) {
                    LOG(Trace, "[WFI_EXIT] k=%llu\n",
                        static_cast<unsigned long long>(k));
                }
            });

            /* Hook sub_8006308C entry — the "timer-expired wakeup processor"
               that the scheduler calls when WAIT_FLAG was 1 and cleared. */
            tm.OnPc(0x8006308Cu, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                if (k < 20 || (k & 0xFFu) == 0u) {
                    LOG(Trace, "[TIMERWAKE_ENT] k=%llu R0=0x%08X\n",
                        static_cast<unsigned long long>(k), c.regs[0]);
                }
            });

            /* One-shot: dump process descriptor at 0x8FFFF024 (= thread+0xA0)
               to identify owning process. */
            tm.OnRunLoopIter([](const TraceContext& c) {
                static std::atomic<bool> done{false};
                if (done.load(std::memory_order_relaxed)) return;
                auto cur = c.ReadVa32(0xFFFFC894u);
                if (!cur || *cur != 0x8FF66000u) return;
                auto pname_ptr = c.ReadVa32(0x8FFFF024u + 0x8u);
                auto vmbase = c.ReadVa32(0x8FFFF024u + 0x80u);
                auto e32entry = c.ReadVa32(0x8FFFF024u + 0x84u);
                if (!pname_ptr) return;
                bool expected = false;
                if (!done.compare_exchange_strong(expected, true)) return;
                LOG(Trace, "[PROC_8FFFF024] +0x08(name?)=0x%08X +0x80(vmbase?)=0x%08X "
                           "+0x84(entry?)=0x%08X\n",
                    pname_ptr.value_or(0), vmbase.value_or(0),
                    e32entry.value_or(0));
                for (uint32_t off = 0; off <= 0x100; off += 4) {
                    auto v = c.ReadVa32(0x8FFFF024u + off);
                    LOG(Trace, "[PROC_8FFFF024] +0x%02X = 0x%08X\n",
                        off, v.value_or(0xDEADBEEFu));
                }
            });

            /* Poll head of sleep list at 0x8C0D4DF0 + sentinel at 0x8C0D43F0
               + thread+40 wake target. Identifies which list our thread
               landed in. */
            tm.OnRunLoopIter([](const TraceContext& c) {
                static std::atomic<uint32_t> last_4df0{0xCAFEBABEu};
                static std::atomic<uint32_t> last_43f0{0xCAFEBABEu};
                static std::atomic<uint32_t> last_thr40{0xCAFEBABEu};
                static std::atomic<uint64_t> tick{0};
                const uint64_t k = tick.fetch_add(1, std::memory_order_relaxed);
                auto a = c.ReadVa32(0x8C0D4DF0u);
                auto b = c.ReadVa32(0x8C0D43F0u);
                auto t = c.ReadVa32(0x8FF66000u + 0x28u);
                if (!a || !b || !t) return;
                const uint32_t pa = last_4df0.exchange(*a, std::memory_order_relaxed);
                const uint32_t pb = last_43f0.exchange(*b, std::memory_order_relaxed);
                const uint32_t pt = last_thr40.exchange(*t, std::memory_order_relaxed);
                if (*a != pa || *b != pb || *t != pt) {
                    LOG(Trace, "[SLEEPLIST] iter=%llu head_4DF0=0x%08X "
                               "head_43F0=0x%08X thr66K+0x28=0x%08X\n",
                        static_cast<unsigned long long>(k),
                        *a, *b, *t);
                }
            });

            /* Poll the two pending-wake target tick globals in the OST ISR's
               reschedule-decision: M[0x8C0D4DAC] and M[0x8C0D4D54]. */
            tm.OnRunLoopIter([](const TraceContext& c) {
                static std::atomic<uint32_t> last_4dac{0xCAFEBABEu};
                static std::atomic<uint32_t> last_4d54{0xCAFEBABEu};
                static std::atomic<uint64_t> tick{0};
                const uint64_t k = tick.fetch_add(1, std::memory_order_relaxed);
                auto a = c.ReadVa32(0x8C0D4DACu);
                auto b = c.ReadVa32(0x8C0D4D54u);
                if (!a || !b) return;
                const uint32_t pa = last_4dac.exchange(*a, std::memory_order_relaxed);
                const uint32_t pb = last_4d54.exchange(*b, std::memory_order_relaxed);
                if (*a != pa || *b != pb) {
                    LOG(Trace, "[WAKETGT] iter=%llu 4DAC=0x%08X (was 0x%08X) "
                               "4D54=0x%08X (was 0x%08X)\n",
                        static_cast<unsigned long long>(k),
                        *a, pa, *b, pb);
                }
            });

            tm.OnPc(0x800585C8u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                LOG(Trace, "[OSTISR_ENT] k=%llu R0=0x%08X lr=0x%08X cpsr=0x%08X\n",
                    static_cast<unsigned long long>(k),
                    c.regs[0], c.regs[14], c.cpsr);
            });

            tm.OnPc(0x80058890u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                LOG(Trace, "[OSTISR_EXIT] k=%llu R0=0x%08X cpsr=0x%08X\n",
                    static_cast<unsigned long long>(k),
                    c.regs[0], c.cpsr);
            });

            tm.OnPc(0x8006071Cu, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                auto& cpu_state = *c.emu.Get<ArmCpu>().State();
                const uint32_t spsr_active = cpu_state.spsr.word;
                LOG(Trace, "[IRQ_VEC] k=%llu cpsr=0x%08X spsr_active=0x%08X "
                           "pre_mode=0x%02X lr=0x%08X\n",
                    static_cast<unsigned long long>(k),
                    c.cpsr, spsr_active, spsr_active & 0x1Fu, c.regs[14]);
            });

            tm.OnPcFiltered(
                0x01FA1790u,
                [](const TraceContext& c) {
                    auto& mmu = *c.emu.Get<ArmMmu>().State();
                    return mmu.process_id == 0x08000000u;
                },
                [](const TraceContext& c) {
                    static std::atomic<uint64_t> n{0};
                    const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                    auto& mmu_state = *c.emu.Get<ArmMmu>().State();
                    LOG(Trace, "[MTBF_ENT] k=%llu R0_entry=0x%08X R1=0x%08X "
                               "R2=0x%08X R3=0x%08X cp13=0x%08X cpsr=0x%08X\n",
                        static_cast<unsigned long long>(k),
                        c.regs[0], c.regs[1], c.regs[2], c.regs[3],
                        mmu_state.process_id, c.cpsr);
                });

            /* L1[0x11F] poll — does it ever become non-zero? */
            tm.OnRunLoopIter([](const TraceContext& c) {
                static std::atomic<uint32_t> last_l1{0xCAFEBABEu};
                auto& mem = c.emu.Get<EmulatedMemory>();
                auto& mmu_state = *c.emu.Get<ArmMmu>().State();
                const uint32_t ttbr0_pa = mmu_state.translation_table_base.word
                                          & 0xFFFFC000u;
                uint32_t v = 0;
                if (auto* p = mem.TryTranslate(ttbr0_pa + 0x11Fu * 4u)) {
                    std::memcpy(&v, p, sizeof(v));
                }
                const uint32_t prev = last_l1.exchange(v, std::memory_order_relaxed);
                if (v != prev) {
                    LOG(Trace, "[L1_11F] L1[0x11F]: 0x%08X -> 0x%08X "
                               "ttbr0=0x%08X\n", prev, v, ttbr0_pa);
                }
            });

            /* L1[0x3F] poll — slot 1 high range that XRET k=33 returned to. */
            tm.OnRunLoopIter([](const TraceContext& c) {
                static std::atomic<uint32_t> last_l1{0xCAFEBABEu};
                auto& mem = c.emu.Get<EmulatedMemory>();
                auto& mmu_state = *c.emu.Get<ArmMmu>().State();
                const uint32_t ttbr0_pa = mmu_state.translation_table_base.word
                                          & 0xFFFFC000u;
                uint32_t v = 0;
                if (auto* p = mem.TryTranslate(ttbr0_pa + 0x03Fu * 4u)) {
                    std::memcpy(&v, p, sizeof(v));
                }
                const uint32_t prev = last_l1.exchange(v, std::memory_order_relaxed);
                if (v != prev) {
                    LOG(Trace, "[L1_03F] L1[0x03F]: 0x%08X -> 0x%08X\n",
                        prev, v);
                }
            });

            /* L1[0x080] poll — slot 4 low range (where 0x08012E50 lives). */
            tm.OnRunLoopIter([](const TraceContext& c) {
                static std::atomic<uint32_t> last_l1{0xCAFEBABEu};
                auto& mem = c.emu.Get<EmulatedMemory>();
                auto& mmu_state = *c.emu.Get<ArmMmu>().State();
                const uint32_t ttbr0_pa = mmu_state.translation_table_base.word
                                          & 0xFFFFC000u;
                uint32_t v = 0;
                if (auto* p = mem.TryTranslate(ttbr0_pa + 0x080u * 4u)) {
                    std::memcpy(&v, p, sizeof(v));
                }
                const uint32_t prev = last_l1.exchange(v, std::memory_order_relaxed);
                if (v != prev) {
                    LOG(Trace, "[L1_080] L1[0x080]: 0x%08X -> 0x%08X\n",
                        prev, v);
                }
            });

            tm.OnRunLoopIter([](const TraceContext& c) {
                static std::atomic<uint32_t> last_l1{0xCAFEBABEu};
                auto& mem = c.emu.Get<EmulatedMemory>();
                auto& mmu_state = *c.emu.Get<ArmMmu>().State();
                const uint32_t ttbr0_pa = mmu_state.translation_table_base.word
                                          & 0xFFFFC000u;
                uint32_t v = 0;
                if (auto* p = mem.TryTranslate(ttbr0_pa + 0x100u * 4u)) {
                    std::memcpy(&v, p, sizeof(v));
                }
                const uint32_t prev = last_l1.exchange(v, std::memory_order_relaxed);
                if (v != prev) {
                    LOG(Trace, "[L1_100] L1[0x100 = slot 8 low]: 0x%08X -> 0x%08X\n",
                        prev, v);
                }
            });

            tm.OnRunLoopIter([](const TraceContext& c) {
                static std::atomic<uint32_t> last_softtlb{0xCAFEBABEu};
                auto v = c.ReadVa32(0x8FFE1CB0u);
                if (!v) return;
                const uint32_t prev = last_softtlb.exchange(
                    *v, std::memory_order_relaxed);
                if (*v != prev) {
                    LOG(Trace, "[SOFTTLB_S4P12] [0x8FFE1CB0]: "
                               "0x%08X -> 0x%08X\n", prev, *v);
                }
            });

            /* Also watch the process_struct[1] pointer itself — if it changes,
               the kernel is re-allocating/re-pointing slot 4's soft-TLB struct. */
            tm.OnRunLoopIter([](const TraceContext& c) {
                static std::atomic<uint32_t> last_pt4{0xCAFEBABEu};
                auto v = c.ReadVa32(0xFFFFC8B0u);
                if (!v) return;
                const uint32_t prev = last_pt4.exchange(
                    *v, std::memory_order_relaxed);
                if (*v != prev) {
                    LOG(Trace, "[PROCTBL_4] ProcessTable[4] @ 0xFFFFC8B0: "
                               "0x%08X -> 0x%08X\n", prev, *v);
                }
            });

            /* L2[F5] poll + CONTINUOUS RE-INJECT. Every iter, if L2[F4] is
               non-zero AND L2[F5] is different from L2[F4], rewrite L2[F5] to
               alias L2[F4]. Log every re-inject (so we see how often kernel
               clears it). */
            tm.OnRunLoopIter([](const TraceContext& c) {
                static std::atomic<uint64_t> reinject_count{0};
                auto& mem = c.emu.Get<EmulatedMemory>();
                uint32_t l2_f5 = 0;
                if (auto* p = mem.TryTranslate(0xC00C9C00u + 0xF5u * 4u)) {
                    std::memcpy(&l2_f5, p, sizeof(l2_f5));
                }
                uint32_t l2_f4 = 0;
                if (auto* p = mem.TryTranslate(0xC00C9C00u + 0xF4u * 4u)) {
                    std::memcpy(&l2_f4, p, sizeof(l2_f4));
                }
                if (l2_f4 == 0) return;
                struct { uint8_t idx; uint32_t pa_base; bool also_fix_f4; } inject[] = {
                    { 0xF1, 0xC0501000u, false },
                    { 0xF3, 0xC0503000u, false },
                    { 0xF5, 0xC0505000u, false },
                    { 0xF7, 0xC0507000u, false },
                    { 0xF8, 0xC0508000u, false },
                    { 0xF9, 0xC0509000u, false },
                    { 0xFA, 0xC050A000u, false },
                    { 0xFB, 0xC050B000u, false },
                    { 0xFD, 0xC050D000u, false },
                    { 0xFE, 0xC050E000u, false },
                    { 0xFF, 0xC050F000u, false },
                };
                bool wrote_anything = false;
                for (const auto& e : inject) {
                    const uint32_t target = e.pa_base | 0x55Eu;
                    const uint32_t l2_pa = 0xC00C9C00u + e.idx * 4u;
                    uint32_t cur = 0;
                    if (auto* p = mem.TryTranslate(l2_pa)) {
                        std::memcpy(&cur, p, sizeof(cur));
                    }
                    if (cur == target) continue;
                    if (auto* p = mem.TryTranslateWrite(l2_pa)) {
                        std::memcpy(p, &target, sizeof(target));
                        wrote_anything = true;
                    }
                }
                /* Also force L2[F4] AP to all-1 (override the kernel's 0x850). */
                const uint32_t f4_target = (l2_f4 & 0xFFFFF00Fu) | 0x550u;
                if (l2_f4 != f4_target) {
                    if (auto* p = mem.TryTranslateWrite(0xC00C9C00u + 0xF4u * 4u)) {
                        std::memcpy(p, &f4_target, sizeof(f4_target));
                        wrote_anything = true;
                    }
                }
                if (wrote_anything) {
                    const uint64_t k = reinject_count.fetch_add(1,
                        std::memory_order_relaxed);
                    if (k < 5 || (k & 0xFFFu) == 0u) {
                        LOG(Trace, "[L2_FFFx_BROAD] k=%llu mapped 0xFFFFxxxx gaps "
                                   "to PA 0xC0501000+ with AP=1, fixed L2[F4] AP\n",
                            static_cast<unsigned long long>(k));
                    }
                }
            });

            tm.OnRunLoopIter([](const TraceContext& c) {
                static std::atomic<bool> dumped_entries{false};
                if (dumped_entries.load(std::memory_order_relaxed)) goto skip_dump;
                {
                    auto& mem = c.emu.Get<EmulatedMemory>();
                    struct { const char* name; uint32_t e32_pa; } mods[] = {
                        {"nk.exe",     0x0008BF14u},
                        {"coredll",    0x00111F0Cu},
                        {"filesys",    0x00112D20u},
                        {"gwes",       0x00112DECu},
                        {"device",     0x00112EB8u},
                    };
                    bool any = false;
                    for (const auto& m : mods) {
                        uint32_t entry = 0xDEADBEEFu, vbase = 0xDEADBEEFu;
                        if (auto* p = mem.TryTranslate(m.e32_pa + 4u)) {
                            std::memcpy(&entry, p, 4);
                            any = true;
                        }
                        if (auto* p = mem.TryTranslate(m.e32_pa + 8u)) {
                            std::memcpy(&vbase, p, 4);
                        }
                        LOG(Trace, "[E32ENTRY] %-12s e32=0x%08X "
                                   "entry_rva=0x%08X vbase=0x%08X\n",
                            m.name, m.e32_pa, entry, vbase);
                    }
                    if (any) {
                        dumped_entries.store(true,
                            std::memory_order_relaxed);
                    }
                }
            skip_dump:;
            });

            tm.OnRunLoopIter([](const TraceContext& c) {
                static std::atomic<uint32_t> last_l2_12{0xCAFEBABEu};
                static std::atomic<uint32_t> last_l2_13{0xCAFEBABEu};
                static std::atomic<uint32_t> last_l2_16{0xCAFEBABEu};
                auto& mem = c.emu.Get<EmulatedMemory>();
                uint32_t l2_12 = 0, l2_13 = 0, l2_16 = 0;
                if (auto* p = mem.TryTranslate(0xC00C4848u)) std::memcpy(&l2_12, p, 4);
                if (auto* p = mem.TryTranslate(0xC00C484Cu)) std::memcpy(&l2_13, p, 4);
                if (auto* p = mem.TryTranslate(0xC00C4858u)) std::memcpy(&l2_16, p, 4);
                const uint32_t p12 = last_l2_12.exchange(l2_12, std::memory_order_relaxed);
                const uint32_t p13 = last_l2_13.exchange(l2_13, std::memory_order_relaxed);
                const uint32_t p16 = last_l2_16.exchange(l2_16, std::memory_order_relaxed);
                if (l2_12 != p12) LOG(Trace, "[ARML2_12] [0xC00C4848 = ARM L2 for VA 0x08012000]: "
                                              "0x%08X -> 0x%08X\n", p12, l2_12);
                if (l2_13 != p13) LOG(Trace, "[ARML2_13] [0xC00C484C = ARM L2 for VA 0x08013000]: "
                                              "0x%08X -> 0x%08X\n", p13, l2_13);
                if (l2_16 != p16) LOG(Trace, "[ARML2_16] [0xC00C4858 = ARM L2 for VA 0x08016000]: "
                                              "0x%08X -> 0x%08X\n", p16, l2_16);
            });

            tm.OnRunLoopIter([](const TraceContext& c) {
                static std::atomic<bool> done{false};
                if (done.load(std::memory_order_relaxed)) return;
                auto reg18 = c.ReadVa32(0x8FFE1D78u + 0x18u);
                auto reg5C = c.ReadVa32(0x8FFE1D78u + 0x5Cu);
                auto reg9C = c.ReadVa32(0x8FFE1D78u + 0x9Cu);
                if (!reg18) return;
                static std::atomic<uint64_t> last_iter{0};
                const uint64_t k = last_iter.fetch_add(1, std::memory_order_relaxed);
                if ((k & 0x3FFFu) != 0u) return;
                LOG(Trace, "[REGUPD_THREAD] iter=%llu +0x18(pcstkTop)=0x%08X "
                           "+0x5C(ctx.Psr)=0x%08X +0x9C(ctx.Pc)=0x%08X\n",
                    static_cast<unsigned long long>(k),
                    reg18.value_or(0), reg5C.value_or(0), reg9C.value_or(0));
                for (uint32_t off = 0; off <= 0xB0; off += 4) {
                    auto v = c.ReadVa32(0x8FFE1D78u + off);
                    LOG(Trace, "[REGUPD_THREAD] +0x%02X = 0x%08X\n",
                        off, v.value_or(0xDEADBEEFu));
                }
                done.store(true, std::memory_order_relaxed);
            });

            tm.OnRunLoopIter([](const TraceContext& c) {
                static std::atomic<bool> done{false};
                if (done.load(std::memory_order_relaxed)) return;
                auto cur = c.ReadVa32(0xFFFFC894u);
                if (!cur || *cur != 0x8FF66000u) return;
                auto pcstkTop = c.ReadVa32(0x8FF66000u + 0x18u);
                auto ctx_pc = c.ReadVa32(0x8FF66000u + 0x5Cu);
                if (!pcstkTop || (*pcstkTop == 0 && (!ctx_pc || *ctx_pc == 0))) return;
                done.store(true, std::memory_order_relaxed);
                for (uint32_t off = 0; off <= 0xB0; off += 4) {
                    auto v = c.ReadVa32(0x8FF66000u + off);
                    LOG(Trace, "[THREAD_8FF66000] +0x%02X = 0x%08X\n",
                        off, v.value_or(0xDEADBEEFu));
                }
            });

            tm.OnRunLoopIter([](const TraceContext& c) {
                static std::atomic<uint32_t> last_thread{0xCAFEBABEu};
                static std::atomic<uint32_t> last_exc{0xCAFEBABEu};
                auto thread = c.ReadVa32(0xFFFFC894u);
                if (!thread) return;
                const uint32_t prev_t = last_thread.exchange(*thread,
                    std::memory_order_relaxed);
                if (*thread != prev_t) {
                    LOG(Trace, "[CURTHREAD] *(0xFFFFC894): 0x%08X -> 0x%08X\n",
                        prev_t, *thread);
                }
                if (*thread == 0) return;
                auto exc = c.ReadVa32(*thread + 24u);
                if (!exc) return;
                const uint32_t prev_e = last_exc.exchange(*exc,
                    std::memory_order_relaxed);
                if (*exc != prev_e) {
                    LOG(Trace, "[CURTHREAD_EXC] *(thread+24) @ 0x%08X: "
                               "0x%08X -> 0x%08X (thread=0x%08X)\n",
                        *thread + 24u, prev_e, *exc, *thread);
                }
            });

            /* Flag at 0xFFFFC884 — the wait-loop terminator. Poll it. */
            tm.OnRunLoopIter([](const TraceContext& c) {
                static std::atomic<uint32_t> last_flag{0xFFu};
                auto v = c.ReadVa8(0xFFFFC884u);
                if (!v) return;
                const uint32_t prev = last_flag.exchange(*v, std::memory_order_relaxed);
                if (*v != prev) {
                    LOG(Trace, "[WAIT_FLAG] byte at 0xFFFFC884: %u -> %u\n",
                        prev, *v);
                }
            });

            tm.OnRunLoopIter([](const TraceContext& c) {
                static std::atomic<bool> dumped{false};
                if (dumped.load(std::memory_order_relaxed)) return;
                auto& mem = c.emu.Get<EmulatedMemory>();
                uint32_t und_tgt = 0;
                if (auto* p = mem.TryTranslate(0xC00C83E4u)) {
                    std::memcpy(&und_tgt, p, sizeof(und_tgt));
                }
                if (und_tgt == 0) return;
                bool expected = false;
                if (!dumped.compare_exchange_strong(expected, true)) return;
                static const char* kVectorNames[8] = {
                    "RESET", "UND", "SWI", "PFA", "DABT", "RSVD", "IRQ", "FIQ"
                };
                for (uint32_t i = 0; i < 8; ++i) {
                    const uint32_t vec_pa = 0xC00C8000u + i * 4u;
                    uint32_t instr = 0;
                    if (auto* p = mem.TryTranslate(vec_pa)) {
                        std::memcpy(&instr, p, sizeof(instr));
                    }
                    const uint32_t vec_va = 0xFFFF0000u + i * 4u;
                    /* Decode B (0x0A000000) and BL (0x0B000000) — cond
                       in top nibble, low 24 bits = sign-extended offset
                       (in words), target = pc + 8 + offset*4 where pc = vec_va. */
                    char decode[80] = "?";
                    if ((instr & 0x0F000000u) == 0x0A000000u) {
                        int32_t off = static_cast<int32_t>(instr << 8) >> 6;
                        const uint32_t tgt = vec_va + 8u + static_cast<uint32_t>(off);
                        snprintf(decode, sizeof(decode),
                                 "B -> 0x%08X", tgt);
                    } else if ((instr & 0x0FFFF000u) == 0x059FF000u) {
                        /* LDR PC, [PC, #imm12] — load PC from data table.
                           Target word at vec_va + 8 + imm12. */
                        const uint32_t imm12 = instr & 0xFFFu;
                        const uint32_t data_va = vec_va + 8u + imm12;
                        /* data_va is in the same page; PA = same offset */
                        const uint32_t data_pa = 0xC00C8000u + (data_va & 0xFFFu);
                        uint32_t data_val = 0;
                        if (auto* p = mem.TryTranslate(data_pa)) {
                            std::memcpy(&data_val, p, sizeof(data_val));
                        }
                        snprintf(decode, sizeof(decode),
                                 "LDR PC,[PC,#0x%X] => *0x%08X = 0x%08X",
                                 imm12, data_va, data_val);
                    }
                    LOG(Trace, "[VECTORS] %s @ VA 0x%08X (PA 0x%08X): "
                               "0x%08X  %s\n",
                        kVectorNames[i], vec_va, vec_pa, instr, decode);
                }
                /* Also dump the data-area DWORDs at 0xC00C8020..0xC00C803C
                   in case vectors use LDR PC with offsets into this region. */
                for (uint32_t i = 0; i < 8; ++i) {
                    const uint32_t pa = 0xC00C8020u + i * 4u;
                    uint32_t v = 0;
                    if (auto* p = mem.TryTranslate(pa)) {
                        std::memcpy(&v, p, sizeof(v));
                    }
                    LOG(Trace, "[VECTORS] data slot %u @ PA 0x%08X "
                               "(VA 0xFFFF%04X): 0x%08X\n",
                        i, pa, 0x0020u + i * 4u, v);
                }
            });

            tm.OnRunLoopIter([](const TraceContext& c) {
                static std::atomic<uint32_t> last_ca114{0xCAFEBABEu};
                static std::atomic<uint32_t> last_c800_8{0xCAFEBABEu};
                auto& mem = c.emu.Get<EmulatedMemory>();
                uint32_t ca114 = 0;
                if (auto* p = mem.TryTranslate(0xC00CA114u)) {
                    std::memcpy(&ca114, p, sizeof(ca114));
                }
                const uint32_t prev_a = last_ca114.exchange(ca114,
                    std::memory_order_relaxed);
                if (ca114 != prev_a) {
                    LOG(Trace, "[CA114] *(0x8C0CA114): 0x%08X -> 0x%08X\n",
                        prev_a, ca114);
                }
                auto c800_8 = c.ReadVa32(0xFFFFC808u);
                if (c800_8) {
                    const uint32_t prev = last_c800_8.exchange(*c800_8,
                        std::memory_order_relaxed);
                    if (*c800_8 != prev) {
                        LOG(Trace, "[C808] *(0xFFFFC808): 0x%08X -> 0x%08X "
                                   "(bit1=%u)\n",
                            prev, *c800_8, (*c800_8 >> 1) & 1u);
                    }
                }
            });

            tm.OnPc(0x8007CA0Cu, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                if (k < 100 || (k & 0xFFFu) == 0u) {
                    LOG(Trace, "[VALLOC_ENT] k=%llu a1=0x%08X a2=0x%08X "
                               "a3=0x%08X a4=0x%08X lr=0x%08X\n",
                        static_cast<unsigned long long>(k),
                        c.regs[0], c.regs[1], c.regs[2], c.regs[3],
                        c.regs[14]);
                }
            });
            tm.OnPc(0x8007EF9Cu, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                if (k < 200 || (k & 0xFFFu) == 0u) {
                    LOG(Trace, "[PAGEALLOC_ENT] k=%llu lr=0x%08X\n",
                        static_cast<unsigned long long>(k), c.regs[14]);
                }
            });
            tm.OnPc(0x8007EFACu, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                if (k < 200 || (k & 0xFFFu) == 0u) {
                    LOG(Trace, "[PAGEALLOC_RES] k=%llu R0_from_alloc=0x%08X "
                               "(0=FAILED)\n",
                        static_cast<unsigned long long>(k), c.regs[0]);
                }
            });

            tm.OnRunLoopIter([](const TraceContext& c) {
                static std::atomic<uint32_t> last_caf{0xCAFEBABEu};
                static std::atomic<uint32_t> last_cb4{0xCAFEBABEu};
                auto cac = c.ReadVa32(0x8FFE1CACu);
                auto cb4 = c.ReadVa32(0x8FFE1CB4u);
                if (cac) {
                    const uint32_t prev = last_caf.exchange(*cac,
                        std::memory_order_relaxed);
                    if (*cac != prev) {
                        LOG(Trace, "[ADJ_CAC] [0x8FFE1CAC]: 0x%08X -> 0x%08X\n",
                            prev, *cac);
                    }
                }
                if (cb4) {
                    const uint32_t prev = last_cb4.exchange(*cb4,
                        std::memory_order_relaxed);
                    if (*cb4 != prev) {
                        LOG(Trace, "[ADJ_CB4] [0x8FFE1CB4]: 0x%08X -> 0x%08X\n",
                            prev, *cb4);
                    }
                }
            });

            tm.OnPc(0x800604CCu, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                if (k < 30 || (k & 0xFFFFu) == 0u) {
                    LOG(Trace, "[B_R1_1] k=%llu cpsr=0x%08X mode=0x%02X "
                               "sp=0x%08X lr=0x%08X r0=0x%08X\n",
                        static_cast<unsigned long long>(k), c.cpsr,
                        c.cpsr & 0x1Fu, c.regs[13], c.regs[14], c.regs[0]);
                }
            });
            tm.OnPc(0x80060718u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                if (k < 30 || (k & 0xFFFFu) == 0u) {
                    LOG(Trace, "[B_R1_4] k=%llu cpsr=0x%08X mode=0x%02X\n",
                        static_cast<unsigned long long>(k), c.cpsr,
                        c.cpsr & 0x1Fu);
                }
            });
            tm.OnPc(0x800607C8u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                if (k < 30 || (k & 0xFFFFu) == 0u) {
                    LOG(Trace, "[B_R1_0] k=%llu cpsr=0x%08X mode=0x%02X\n",
                        static_cast<unsigned long long>(k), c.cpsr,
                        c.cpsr & 0x1Fu);
                }
            });

            tm.OnPc(0x80069FF0u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                if (k < 50 || (k & 0xFFFFu) == 0u) {
                    LOG(Trace, "[FIX_ENTER] k=%llu FAR=0x%08X cpsr=0x%08X "
                               "mode=0x%02X sp=0x%08X lr=0x%08X\n",
                        static_cast<unsigned long long>(k),
                        c.regs[0], c.cpsr, c.cpsr & 0x1Fu,
                        c.regs[13], c.regs[14]);
                }
            });

            tm.OnPc(0x80060A74u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                static std::atomic<uint32_t> last_mode{0xFFu};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                const uint32_t mode = c.cpsr & 0x1Fu;
                const uint32_t prev = last_mode.exchange(mode, std::memory_order_relaxed);
                if (k < 30 || mode != prev || (k & 0xFFFFu) == 0u) {
                    LOG(Trace, "[POST_XRET] k=%llu cpsr_mode=0x%02X sp=0x%08X "
                               "cpsr=0x%08X\n",
                        static_cast<unsigned long long>(k),
                        mode, c.regs[13], c.cpsr);
                }
            });

            tm.OnPc(0x8006066Cu, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                static std::atomic<uint32_t> last_r2{0xCAFEBABEu};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                const uint32_t r2 = c.regs[2];
                const uint32_t prev = last_r2.exchange(r2, std::memory_order_relaxed);
                const bool changed = (r2 != prev);
                if (k < 50 || changed || (k & 0xFFFFu) == 0u) {
                    LOG(Trace, "[SPSR_RESTORE] k=%llu R2=0x%08X R2.mode=0x%02X "
                               "cpsr=0x%08X\n",
                        static_cast<unsigned long long>(k),
                        r2, r2 & 0x1Fu, c.cpsr);
                }
            });

            /* PREFETCH fast-path success return — POPNE {R0-R3,R12,PC}^. Loads
               PC from the saved LR_abt (= user PC + 4). Log cross-slot returns. */
            tm.OnPc(0x800605CCu, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                /* SP points at the saved frame: SP[5] = saved LR_abt. */
                const uint32_t sp = c.regs[13];
                auto saved_lr = c.ReadVa32(sp + 5u * 4u);
                const uint32_t lr_target = saved_lr.value_or(0);
                /* Subtract 0xF0000004 to undo ADD LR,LR,#0xF0000000 + prefetch +4. */
                const uint32_t user_pc = lr_target - 0xF0000004u;
                const bool cross_slot = (user_pc >= 0x02000000u && user_pc < 0x80000000u);
                if (k < 30 || cross_slot || (k & 0xFFFFu) == 0u) {
                    auto& mmu_state = *c.emu.Get<ArmMmu>().State();
                    LOG(Trace, "[PFA_RET] k=%llu user_pc=0x%08X raw_lr=0x%08X "
                               "cp13=0x%08X cpsr=0x%08X\n",
                        static_cast<unsigned long long>(k),
                        user_pc, lr_target, mmu_state.process_id, c.cpsr);
                }
            });

            /* DATA fast-path success return — POPNE {R0-R3,R12,PC}^. */
            tm.OnPc(0x800606FCu, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                const uint32_t sp = c.regs[13];
                auto saved_lr = c.ReadVa32(sp + 5u * 4u);
                const uint32_t lr_target = saved_lr.value_or(0);
                /* Data abort path: SUB LR, LR, #8 already done, so saved_lr = user_pc. */
                const uint32_t user_pc = lr_target;
                const bool cross_slot = (user_pc >= 0x02000000u && user_pc < 0x80000000u);
                if (k < 30 || cross_slot || (k & 0xFFFFu) == 0u) {
                    auto& mmu_state = *c.emu.Get<ArmMmu>().State();
                    LOG(Trace, "[DFA_RET] k=%llu user_pc=0x%08X cp13=0x%08X "
                               "cpsr=0x%08X\n",
                        static_cast<unsigned long long>(k),
                        user_pc, mmu_state.process_id, c.cpsr);
                }
            });

            tm.OnPc(0x80060678u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                const uint32_t lr = c.regs[14];
                /* Always log non-slot-0 user dispatches (cross-slot returns). */
                const bool cross_slot = (lr >= 0x02000000u && lr < 0x80000000u);
                if (k < 50 || cross_slot || (k & 0xFFFFu) == 0u) {
                    auto& mmu_state = *c.emu.Get<ArmMmu>().State();
                    LOG(Trace, "[XRET] k=%llu cpsr=0x%08X mode=0x%02X "
                               "LR(target)=0x%08X cp13_pid=0x%08X R0=0x%08X "
                               "R2=0x%08X sp_svc=0x%08X\n",
                        static_cast<unsigned long long>(k),
                        c.cpsr, c.cpsr & 0x1Fu,
                        lr, mmu_state.process_id,
                        c.regs[0], c.regs[2], c.regs[13]);
                }
            });

            tm.OnPc(0x80060684u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                /* R0 holds the base address — LDM loads R0..R15 from
                   [R0..R0+0x3C]. Saved PC is at R0+0x3C. */
                auto pc_target = c.ReadVa32(c.regs[0] + 0x3Cu);
                auto saved_sp  = c.ReadVa32(c.regs[0] + 0x34u);
                auto saved_lr  = c.ReadVa32(c.regs[0] + 0x38u);
                if (k < 50 || (k & 0xFFFu) == 0u) {
                    LOG(Trace, "[XRET_NS] k=%llu cpsr=0x%08X mode=0x%02X "
                               "base=0x%08X R2=0x%08X pc_tgt=0x%08X "
                               "sp_tgt=0x%08X lr_tgt=0x%08X\n",
                        static_cast<unsigned long long>(k),
                        c.cpsr, c.cpsr & 0x1Fu,
                        c.regs[0], c.regs[2],
                        pc_target.value_or(0xDEADBEEFu),
                        saved_sp.value_or(0xDEADBEEFu),
                        saved_lr.value_or(0xDEADBEEFu));
                }
            });

            tm.OnPc(0x800606ACu, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                static std::atomic<uint32_t> last_sp{0xCAFEBABEu};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                const uint32_t sp = c.regs[13];
                const uint32_t prev = last_sp.exchange(sp, std::memory_order_relaxed);
                const bool changed = (sp != prev);
                if (k < 30 || changed || (k & 0xFFFFu) == 0u) {
                    LOG(Trace, "[NON_SVC_PATH] k=%llu sp=0x%08X r0=0x%08X "
                               "r2=0x%08X cpsr=0x%08X cpsr_mode=0x%02X "
                               "stm_addr_will_be=0x%08X\n",
                        static_cast<unsigned long long>(k),
                        sp, c.regs[0], c.regs[2], c.cpsr,
                        c.cpsr & 0x1Fu, sp + 0x70u);
                }
            });

            /* 5 bail-progression hooks. Each fires at the BEQ check point.
               If BAIL hook for step N fires but PASS hook for step N+1 doesn't,
               step N bailed. */
            tm.OnPc(0x8006A1A4u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                if (k < 100 || (k & 0xFFFFu) == 0u) {
                    LOG(Trace, "[FIX_BAIL] k=%llu lr=0x%08X "
                               "R0=0x%08X R1=0x%08X R2=0x%08X R3=0x%08X "
                               "R10=0x%08X\n",
                        static_cast<unsigned long long>(k),
                        c.regs[14],
                        c.regs[0], c.regs[1], c.regs[2], c.regs[3],
                        c.regs[10]);
                }
            });
            /* Hook AFTER each check's BEQ (= check passed). */
            tm.OnPc(0x8006A014u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                if (k < 50 || (k & 0xFFFFu) == 0u) {
                    LOG(Trace, "[FIX_PASS_1] k=%llu (ProcTbl[slot] OK) FAR=0x%08X "
                               "R1=ProcTbl[slot]=0x%08X slot=%u\n",
                        static_cast<unsigned long long>(k),
                        c.regs[0], c.regs[1], c.regs[3]);
                }
            });
            tm.OnPc(0x8006A02Cu, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                if (k < 50 || (k & 0xFFFFu) == 0u) {
                    LOG(Trace, "[FIX_PASS_2] k=%llu (top-entry!=0) FAR=0x%08X "
                               "R2=top_entry=0x%08X\n",
                        static_cast<unsigned long long>(k),
                        c.regs[0], c.regs[2]);
                }
            });
            tm.OnPc(0x8006A034u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                if (k < 50 || (k & 0xFFFFu) == 0u) {
                    LOG(Trace, "[FIX_PASS_3] k=%llu (top-entry!=1) FAR=0x%08X "
                               "R2=top_entry=0x%08X\n",
                        static_cast<unsigned long long>(k),
                        c.regs[0], c.regs[2]);
                }
            });
            tm.OnPc(0x8006A04Cu, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                if (k < 50 || (k & 0xFFFFu) == 0u) {
                    LOG(Trace, "[FIX_PASS_4] k=%llu (perm OK) FAR=0x%08X "
                               "R1=perm_word=0x%08X R3=perm_mask=0x%08X\n",
                        static_cast<unsigned long long>(k),
                        c.regs[0], c.regs[1], c.regs[3]);
                }
            });
            tm.OnPc(0x8006A064u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                if (k < 50 || (k & 0xFFFFu) == 0u) {
                    LOG(Trace, "[FIX_PASS_5] k=%llu (V bit set) FAR=0x%08X "
                               "R10=sub_entry=0x%08X — SUCCESS PATH\n",
                        static_cast<unsigned long long>(k),
                        c.regs[0], c.regs[10]);
                }
            });

            tm.OnPc(0x800605ACu, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                static std::atomic<uint32_t> last_spsr_mode{0xFFu};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                auto& cpu_state = *c.emu.Get<ArmCpu>().State();
                auto& mmu_state = *c.emu.Get<ArmMmu>().State();
                const uint32_t spsr = cpu_state.spsr.word;
                const uint32_t mode = spsr & 0x1Fu;
                const uint32_t prev = last_spsr_mode.exchange(mode, std::memory_order_relaxed);
                const bool changed = (mode != prev);
                const uint32_t raw_pc = c.regs[14] - 4u;
                const uint32_t folded = (raw_pc & 0xFE000000u) == 0u
                                            ? (raw_pc | mmu_state.process_id)
                                            : raw_pc;
                const uint32_t l1_idx = folded >> 20;
                const uint32_t ttbr0_pa = mmu_state.translation_table_base.word & 0xFFFFC000u;
                auto& mem = c.emu.Get<EmulatedMemory>();
                uint32_t l1_val = 0xDEADBEEFu;
                if (auto* p = mem.TryTranslate(ttbr0_pa + l1_idx * 4u)) {
                    std::memcpy(&l1_val, p, sizeof(l1_val));
                }
                /* Also peek L2 entry if L1 is coarse PT. */
                uint32_t l2_val = 0xDEADBEEFu;
                if ((l1_val & 0x3u) == 0x1u) {  /* coarse PT */
                    const uint32_t l2_pa = (l1_val & 0xFFFFFC00u)
                                         + ((folded >> 12) & 0xFFu) * 4u;
                    if (auto* p = mem.TryTranslate(l2_pa)) {
                        std::memcpy(&l2_val, p, sizeof(l2_val));
                    }
                }
                if (k < 30 || changed || (k & 0xFFFFu) == 0u) {
                    const char* mode_str =
                        mode == 0x10 ? "USR"  :
                        mode == 0x11 ? "FIQ"  :
                        mode == 0x12 ? "IRQ"  :
                        mode == 0x13 ? "SVC"  :
                        mode == 0x17 ? "ABT"  :
                        mode == 0x1B ? "UND"  :
                        mode == 0x1F ? "SYS"  : "???";
                    LOG(Trace, "[PFA_ENT] k=%llu spsr_mode=0x%02X (%s) "
                               "raw_pc=0x%08X folded=0x%08X pid=0x%08X "
                               "ttbr0=0x%08X L1[0x%03X]=0x%08X L2[%02X]=0x%08X "
                               "sp_abt=0x%08X\n",
                        static_cast<unsigned long long>(k),
                        mode, mode_str,
                        raw_pc, folded, mmu_state.process_id,
                        ttbr0_pa, l1_idx, l1_val,
                        (folded >> 12) & 0xFFu, l2_val,
                        c.regs[13]);
                }
            });

            /* 0x800606C0 = DATA abort fast path entry.
               BEFORE SUB LR, LR, #8. LR = faulting_PC + 8 (raw).
               state->spsr.word = SPSR_abt = captured CPSR at fault time. */
            /* Hook AT the STM PC. Dump SP, target addr, L2[F5] at firing time. */
            tm.OnPc(0x800606B0u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                if (k >= 5 && (k & 0xFFFFu) != 0u) return;
                auto& mem = c.emu.Get<EmulatedMemory>();
                uint32_t l2_f5 = 0;
                if (auto* p = mem.TryTranslate(0xC00C9C00u + 0xF5u * 4u)) {
                    std::memcpy(&l2_f5, p, sizeof(l2_f5));
                }
                LOG(Trace, "[STM_AT] k=%llu sp=0x%08X r0=0x%08X cpsr=0x%08X "
                           "L2[F5]=0x%08X\n",
                    static_cast<unsigned long long>(k),
                    c.regs[13], c.regs[0], c.cpsr, l2_f5);
            });

            tm.OnPc(0x800606C0u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                static std::atomic<uint32_t> last_spsr_mode{0xFFu};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                auto& state = *c.emu.Get<ArmCpu>().State();
                const uint32_t spsr = state.spsr.word;
                const uint32_t mode = spsr & 0x1Fu;
                const uint32_t prev = last_spsr_mode.exchange(mode, std::memory_order_relaxed);
                const bool changed = (mode != prev);
                if (k < 20 || changed || (k & 0xFFFFu) == 0u) {
                    const char* mode_str =
                        mode == 0x10 ? "USR"  :
                        mode == 0x11 ? "FIQ"  :
                        mode == 0x12 ? "IRQ"  :
                        mode == 0x13 ? "SVC"  :
                        mode == 0x17 ? "ABT"  :
                        mode == 0x1B ? "UND"  :
                        mode == 0x1F ? "SYS"  : "???";
                    LOG(Trace, "[DFA_ENT] k=%llu spsr_mode=0x%02X (%s) spsr=0x%08X "
                               "lr_abt=0x%08X faulting_pc=0x%08X sp_abt=0x%08X\n",
                        static_cast<unsigned long long>(k),
                        mode, mode_str, spsr,
                        c.regs[14], c.regs[14] - 8u, c.regs[13]);
                }
            });

            /* 0x80060600 = AFTER AND R0, R2, #0x1F at 0x800605FC.
               R0 = SPSR.mode (the mode that took the fault). R2 = SPSR. */
            tm.OnPc(0x80060604u, [](const TraceContext& c) {
                static std::atomic<uint64_t> n{0};
                static std::atomic<uint32_t> last_mode{0xFFu};
                static std::atomic<bool> cascade_dumped{false};
                const uint64_t k = n.fetch_add(1, std::memory_order_relaxed);
                const uint32_t mode = c.regs[0] & 0x1Fu;
                const uint32_t prev = last_mode.exchange(mode, std::memory_order_relaxed);
                const bool changed = (mode != prev);

                /* One-shot full state dump at first non-USR/SYS entry. */
                if (mode != 0x10u && mode != 0x1Fu) {
                    bool expected = false;
                    if (cascade_dumped.compare_exchange_strong(expected, true)) {
                        auto& cpu_state = *c.emu.Get<ArmCpu>().State();
                        auto& mmu_state = *c.emu.Get<ArmMmu>().State();
                        auto& mem = c.emu.Get<EmulatedMemory>();
                        const uint32_t ttbr0_pa =
                            mmu_state.translation_table_base.word & 0xFFFFC000u;
                        auto rd_pa = [&](uint32_t pa) -> uint32_t {
                            uint32_t v = 0xDEADBEEFu;
                            if (auto* p = mem.TryTranslate(pa)) std::memcpy(&v, p, 4);
                            return v;
                        };
                        LOG(Trace, "[CASCADE_DUMP] cpsr=0x%08X svc_lr=0x%08X svc_sp=0x%08X "
                                   "spsr_und=0x%08X spsr_abt=0x%08X r0_mode=0x%02X r2_spsr=0x%08X\n",
                            c.cpsr, c.regs[14], c.regs[13],
                            cpu_state.spsr_und, cpu_state.spsr_abt,
                            mode, c.regs[2]);
                        LOG(Trace, "[CASCADE_DUMP] ttbr0=0x%08X fcse_pid=0x%08X sctlr=0x%08X "
                                   "sp_abt_bank=0x%08X sp_und_bank=0x%08X\n",
                            ttbr0_pa, mmu_state.process_id,
                            mmu_state.control_register.word,
                            cpu_state.gprs_abt[0], cpu_state.gprs_und[0]);
                        LOG(Trace, "[CASCADE_DUMP] L1[0x03F]=0x%08X L1[0x040]=0x%08X "
                                   "L1[0x080]=0x%08X L1[0x100]=0x%08X "
                                   "L1[0x11F]=0x%08X L1[0xFFF]=0x%08X\n",
                            rd_pa(ttbr0_pa + 0x03Fu * 4u),
                            rd_pa(ttbr0_pa + 0x040u * 4u),
                            rd_pa(ttbr0_pa + 0x080u * 4u),
                            rd_pa(ttbr0_pa + 0x100u * 4u),
                            rd_pa(ttbr0_pa + 0x11Fu * 4u),
                            rd_pa(ttbr0_pa + 0xFFFu * 4u));
                        const uint32_t l1_080 = rd_pa(ttbr0_pa + 0x080u*4u);
                        const uint32_t l2_slot4_base = l1_080 & 0xFFFFFC00u;
                        for (uint32_t idx = 0x10; idx <= 0x17; ++idx) {
                            LOG(Trace, "[CASCADE_DUMP] slot4 L2[%02X] @ PA "
                                       "0x%08X = 0x%08X (VA 0x080%X000)\n",
                                idx, l2_slot4_base + idx * 4u,
                                rd_pa(l2_slot4_base + idx * 4u), idx);
                        }
                        for (uint32_t l2_idx = 0xF0u; l2_idx <= 0xFFu; ++l2_idx) {
                            const uint32_t l2_pa = 0xC00C9C00u + l2_idx * 4u;
                            LOG(Trace, "[CASCADE_DUMP] L2[%02X]@0x%08X=0x%08X "
                                       "(VA 0xFFFF%X000)\n",
                                l2_idx, l2_pa, rd_pa(l2_pa), l2_idx & 0xFu);
                        }
                    }
                }

                if (k < 30 || changed || (k & 0xFFFFu) == 0u) {
                    const char* mode_str =
                        mode == 0x10 ? "USR"  :
                        mode == 0x11 ? "FIQ"  :
                        mode == 0x12 ? "IRQ"  :
                        mode == 0x13 ? "SVC"  :
                        mode == 0x17 ? "ABT"  :
                        mode == 0x1B ? "UND"  :
                        mode == 0x1F ? "SYS"  : "???";
                    LOG(Trace, "[ABT_ENT] k=%llu spsr_mode=0x%02X (%s) spsr=0x%08X "
                               "sp_abt=0x%08X lr_abt=0x%08X cpsr=0x%08X\n",
                        static_cast<unsigned long long>(k),
                        mode, mode_str, c.regs[2],
                        c.regs[13], c.regs[14], c.cpsr);
                }
            });
        });
    }

private:
    static std::atomic<uint32_t> last_pc_;
    static std::atomic<uint64_t> total_fires_;
    static std::atomic<uint32_t> stable_pc_;
    static std::atomic<uint32_t> stable_count_;

    static void Handler(const TraceContext& c) {
        last_pc_.store(c.pc, std::memory_order_relaxed);
        const uint64_t n = total_fires_.fetch_add(1, std::memory_order_relaxed);

        const uint32_t prev = stable_pc_.load(std::memory_order_relaxed);
        if (prev == c.pc) {
            stable_count_.fetch_add(1, std::memory_order_relaxed);
        } else {
            stable_pc_.store(c.pc, std::memory_order_relaxed);
            stable_count_.store(1, std::memory_order_relaxed);
        }

        if ((n & 0xFFFFu) == 0u) {
            LOG(Trace, "[STUCK_PROBE] fire=%llu pc=0x%08X "
                       "r0=0x%08X r1=0x%08X r2=0x%08X r3=0x%08X "
                       "lr=0x%08X sp=0x%08X cpsr=0x%08X "
                       "stable_pc=0x%08X stable_count=%u\n",
                static_cast<unsigned long long>(n), c.pc,
                c.regs[0], c.regs[1], c.regs[2], c.regs[3],
                c.regs[14], c.regs[13], c.cpsr,
                stable_pc_.load(std::memory_order_relaxed),
                stable_count_.load(std::memory_order_relaxed));
        }
    }

    static void InstallHooksOverRange(TraceManager& tm,
                                      uint32_t start_va, uint32_t end_va) {
        for (uint32_t pc = start_va; pc < end_va; pc += kHookStride) {
            tm.OnPc(pc, &Ppc2002StuckPcProbe::Handler);
        }
    }
};

std::atomic<uint32_t> Ppc2002StuckPcProbe::last_pc_{0};
std::atomic<uint64_t> Ppc2002StuckPcProbe::total_fires_{0};
std::atomic<uint32_t> Ppc2002StuckPcProbe::stable_pc_{0};
std::atomic<uint32_t> Ppc2002StuckPcProbe::stable_count_{0};

REGISTER_SERVICE(Ppc2002StuckPcProbe);

}  /* namespace */

#endif  /* CERF_DEV_MODE */
