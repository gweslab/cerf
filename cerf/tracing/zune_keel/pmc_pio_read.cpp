#include "../trace_manager.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "bundle.h"
#include "zune_process_resolver.h"

#include <atomic>
#include <cstdint>

#if CERF_DEV_MODE

namespace {

/* pmc_atapi sub_3055790 = PIO transfer (a1=ctx r0, a2=req r1, a3=dir r2). The
   read loop returns 30 if it breaks (per-iter DRQ wait vtbl[6] or IRQ-gated
   CHECK 1 on a1+68 fails). Log the sector-size fields + SG to decide single vs
   multi-chunk and whether IRQ mode (a1+68) is on. */
class ZuneKeelPmcPioRead : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kZuneKeelBundleCrc32, [&] {
            const TracePredicate dev =
                zune_resolver::PidPredicateForName("device.exe");
            /* 0x30558D0: after MUL R7,R2,R7 — R2=v3[426] (bytes/sector),
               R7=v17 (expected bytes this chunk), [R6+0x9B0]=sectors this chunk.
               v17>512 vs CERF's single 512-byte sector = the read-loop mismatch. */
            tm.OnPcFiltered(0x30558D0u, dev, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                if (n.fetch_add(1) >= 6u) return;
                auto secs = c.ReadVa32(c.regs[6] + 0x9B0u);
                LOG(Trace, "[PMC-PIO] chunk: bps(v3[426])=%u v17_bytes=%u "
                           "sectors_this_chunk=%d\n",
                    c.regs[2], c.regs[7],
                    secs.has_value() ? (int)*secs : -1);
            });
            /* 0x3055C80: single return point, R5 = return code (0=success,
               0x1E=30, 0x57=87, 0x1D=29). Settles whether the read fails here
               or above (sub_30567B8/sub_30551C4). */
            tm.OnPcFiltered(0x3055C80u, dev, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                if (n.fetch_add(1) >= 6u) return;
                LOG(Trace, "[PMC-PIO] sub_3055790 RETURN code=%u\n", c.regs[5]);
            });
            /* sub_30517D0 = the ATA-IRQ wait. 0x30517D0 entry: R1=timeout.
               0x3051804 after WaitForSingleObject: R0=result (0=signaled,
               0x102=258=WAIT_TIMEOUT). Distinguishes event-never-signaled
               (timeout) from signaled-but-completion-flag-never-set. */
            tm.OnPcFiltered(0x30517D0u, dev, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                if (n.fetch_add(1) >= 8u) return;
                LOG(Trace, "[PMC-PIO] IRQ-wait entry timeout=%u (0x%08X)\n",
                    c.regs[1], c.regs[1]);
            });
            tm.OnPcFiltered(0x3051804u, dev, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                const uint32_t i = n.fetch_add(1);
                if (i >= 12u && (i & 0x3Fu) != 0u) return;
                LOG(Trace, "[PMC-PIO] WFSO #%u result=%u (0=signaled,258=timeout)\n",
                    i, c.regs[0]);
            });
            /* 0x3055C28: v18 += chunk (R11=v18 bytes so far, R9=this chunk,
               R7=v17 total). Shows whether the read loop advances toward v17
               or stalls — and whether it needs more FIFO-chunk IRQs than CERF
               emits (1 per sector). */
            tm.OnPcFiltered(0x3055C28u, dev, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                const uint32_t i = n.fetch_add(1);
                if (i >= 12u && (i & 0x3Fu) != 0u) return;
                LOG(Trace, "[PMC-PIO] loop #%u v18=%u += chunk=%u (v17=%u)\n",
                    i, c.regs[11], c.regs[9], c.regs[7]);
            });
            /* 0x3051848: R3 = INTERRUPT_PENDING (offset 0x28) value sub_30517D0
               read; it loops while bit 7 (ata_intrq1, 0x80) is clear. Bit 7
               clear here confirms CERF clears the latch on STATUS-read instead
               of holding it until INTERRUPT_CLEAR (W1C). */
            tm.OnPcFiltered(0x3051848u, dev, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                const uint32_t i = n.fetch_add(1);
                if (i >= 10u && (i & 0x7Fu) != 0u) return;
                LOG(Trace, "[PMC-PIO] INT_PENDING read #%u = 0x%02X "
                           "(b7/intrq1=%d)\n",
                    i, c.regs[3] & 0xFF, (c.regs[3] & 0x80) ? 1 : 0);
            });
            /* Pure path bisection inside sub_3055790: 0x30558F8 = after the
               sub_3056F84 command issue (R0=result); 0x3055AA4 = inner-read-loop
               entry. Locate where execution stops (no theory). */
            tm.OnPcFiltered(0x30558F8u, dev, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                if (n.fetch_add(1) >= 8u) return;
                LOG(Trace, "[PMC-PIO] after-cmd sub_3056F84 result=%u\n", c.regs[0]);
            });
            tm.OnPcFiltered(0x3055AA4u, dev, [](const TraceContext&) {
                static std::atomic<uint32_t> n{0};
                const uint32_t i = n.fetch_add(1);
                if (i >= 8u && (i & 0x3FFu) != 0u) return;
                LOG(Trace, "[PMC-PIO] inner-loop entry #%u\n", i);
            });
            /* 0x3055BB4 = inner word-read (LDRH R3,[R0],#2); R0=source addr.
               Counts words the read actually transfers — 0 = no data flow. */
            tm.OnPcFiltered(0x3055BB4u, dev, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                const uint32_t i = n.fetch_add(1);
                if (i < 3u || (i & 0xFFu) == 0u)
                    LOG(Trace, "[PMC-PIO] word-read #%u from=0x%08X\n", i, c.regs[0]);
            });
            /* 0x3055918 CMP R3,R9: R3=v60 (max chunk = a1[1872]*bps), R9=v17-v18
               (bytes remaining). v19=min(R3,R9); v60==0 -> v19=0 -> no transfer,
               v18 never advances = the no-data-flow hang. */
            tm.OnPcFiltered(0x3055918u, dev, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                const uint32_t i = n.fetch_add(1);
                if (i >= 8u && (i & 0x3Fu) != 0u) return;
                LOG(Trace, "[PMC-PIO] chunk-calc #%u v60(maxchunk)=%u remaining=%u\n",
                    i, c.regs[3], c.regs[9]);
            });
            tm.OnPcFiltered(0x3055790u, dev, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                if (n.fetch_add(1) >= 6u) return;
                const uint32_t a1 = c.regs[0];
                const uint32_t a2 = c.regs[1];
                auto irq  = c.ReadVa32(a1 + 68u);     /* v3[17] IRQ-mode flag */
                auto tot  = c.ReadVa32(a1 + 1700u);   /* disk total sectors */
                auto bps1 = c.ReadVa32(a1 + 1704u);   /* v3[426] */
                auto bps2 = c.ReadVa32(a1 + 2484u);   /* >>9 sector unit */
                auto sg   = c.ReadVa32(a2 + 24u);     /* SG_REQ ptr */
                uint32_t start = 0, count = 0, nsg = 0;
                if (sg) {
                    start = c.ReadVa32(*sg + 0u).value_or(0xFFFFFFFFu);
                    count = c.ReadVa32(*sg + 4u).value_or(0xFFFFFFFFu);
                    nsg   = c.ReadVa32(*sg + 8u).value_or(0xFFFFFFFFu);
                }
                LOG(Trace, "[PMC-PIO] sub_3055790 dir=%u irqmode=%d total=%d "
                           "bps1=%d bps2=%d | SG start=%u count=%u nsg=%u\n",
                    c.regs[2], irq.has_value() ? (int)*irq : -1,
                    tot.has_value() ? (int)*tot : -1,
                    bps1.has_value() ? (int)*bps1 : -1,
                    bps2.has_value() ? (int)*bps2 : -1, start, count, nsg);
            });
        });
    }
};

REGISTER_SERVICE(ZuneKeelPmcPioRead);

}  /* namespace */

#endif  /* CERF_DEV_MODE */
