#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../jit/arm_mmu.h"
#include "../../jit/arm_mmu_state.h"
#include "ce7_bundle.h"

#include <cstring>

namespace {

class TraceCe7DisplayInitProbe : public Service {
public:
    using Service::Service;
    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kCe7BundleCrc32, [&] {
            /* ddi_tievm3530.dll IDA imagebase = runtime base. */

            tm.OnPc(0xEF0180BCu, [](const TraceContext& c) {
                LOG(Trace, "[disp] LcdPdd_GetMemory entry R0(pLen)=0x%08X "
                    "R1(pAddr)=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[14]);
            });

            tm.OnPc(0xEF016968u, [](const TraceContext& c) {
                LOG(Trace, "[disp] FlatSurfMgr::Initialize entry this=0x%08X "
                    "R1(dwOffscreenMem)=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[14]);
            });

            tm.OnPc(0xEF016B48u, [](const TraceContext& c) {
                LOG(Trace, "[disp] FlatSurfMgr::Initialize return R7(ret)=0x%08X "
                    "this=0x%08X\n", c.regs[7], c.regs[5]);
                if (auto v = c.ReadVa32(c.regs[5] + 0x04))
                    LOG(Trace, "[disp]   m_dwDisplayBufferSize  = 0x%08X\n", *v);
                if (auto v = c.ReadVa32(c.regs[5] + 0x08))
                    LOG(Trace, "[disp]   m_dwPhysicalDisplayAddr = 0x%08X\n", *v);
                if (auto v = c.ReadVa32(c.regs[5] + 0x0C))
                    LOG(Trace, "[disp]   m_pVirtualDisplayBuffer = 0x%08X\n", *v);
                if (auto v = c.ReadVa32(c.regs[5] + 0x10))
                    LOG(Trace, "[disp]   m_hHeap                = 0x%08X\n", *v);
            });

            tm.OnPc(0xEF016B44u, [](const TraceContext& c) {
                LOG(Trace, "[disp] FlatSurfMgr::Initialize CLEANUP (fail) "
                    "this=0x%08X\n", c.regs[5]);
            });

            tm.OnPc(0xEF01B410u, [](const TraceContext& c) {
                static uint32_t count = 0;
                static uint32_t primary_hits = 0;
                ++count;
                auto pvScan0 = c.ReadVa32(c.regs[0] + 0x20);
                const uint32_t dst_va = pvScan0.value_or(0u);
                const bool primary_range = (dst_va >= 0xD18F0000u &&
                                            dst_va <  0xD2900000u);
                if (primary_range && ++primary_hits <= 10) {
                    LOG(Trace, "[disp] DrvBitBlt #%u PRIMARY hit "
                        "psoTrg->pvScan0=0x%08X LR=0x%08X\n",
                        count, dst_va, c.regs[14]);
                }
                if (count > 5 && (count % 50) != 0 && !primary_range) return;
                LOG(Trace, "[disp] DrvBitBlt #%u psoTrg=0x%08X "
                    "pvScan0=0x%08X primary=%d LR=0x%08X\n",
                    count, c.regs[0], dst_va, primary_range ? 1 : 0,
                    c.regs[14]);
                /* Full page-table walk for VA 0xD18F0000 (the driver's
                   primary surface VA) to see if VirtualCopy actually
                   created a mapping in RAM tables. ReadVa32 only peeks
                   TLB — useless for a cold lookup. */
                auto& mmu = c.emu.Get<ArmMmu>();
                auto& mem = c.emu.Get<EmulatedMemory>();
                const auto& m = *mmu.State();
                const uint32_t va = 0xD18F0000u;
                const uint32_t ttbcr_n = m.ttbcr & 7u;
                const uint32_t ttbr0_mask = ttbcr_n
                    ? ~((1u << (14u - ttbcr_n)) - 1u)
                    : 0xFFFFC000u;
                const bool use_ttbr1 = ttbcr_n != 0u &&
                                       (va >> (32u - ttbcr_n)) != 0u;
                const uint32_t l1_base = use_ttbr1
                    ? (m.ttbr1 & 0xFFFFC000u)
                    : (m.translation_table_base.word & ttbr0_mask);
                LOG(Trace, "[disp] walk va=0x%08X TTBR0=0x%08X TTBR1=0x%08X "
                    "TTBCR=0x%08X N=%u use_ttbr1=%u l1_base=0x%08X DACR=0x%08X "
                    "pid=0x%08X CTXIDR=0x%08X SCTLR.M=%u\n",
                    va, m.translation_table_base.word, m.ttbr1, m.ttbcr,
                    ttbcr_n, use_ttbr1, l1_base, m.domain_access_control,
                    m.process_id, m.contextidr, m.control_register.bits.m);
                const uint32_t l1_pa = l1_base | ((va >> 20) << 2);
                uint32_t l1 = 0xDEADBEEFu;
                if (uint8_t* h = mem.TryTranslate(l1_pa))
                    std::memcpy(&l1, h, 4);
                const uint32_t l1_type = l1 & 3u;
                if (l1_type == 2u) {
                    const uint32_t pa = (l1 & 0xFFF00000u) | (va & 0xFFFFFu);
                    LOG(Trace, "[disp]   L1@0x%08X=0x%08X SECTION pa=0x%08X\n",
                        l1_pa, l1, pa);
                } else if (l1_type == 1u) {
                    const uint32_t l2_pa = (l1 & 0xFFFFFC00u) |
                                           (((va >> 12) & 0xFFu) << 2);
                    uint32_t l2 = 0xDEADBEEFu;
                    if (uint8_t* h = mem.TryTranslate(l2_pa))
                        std::memcpy(&l2, h, 4);
                    const uint32_t l2_type = l2 & 3u;
                    uint32_t pa = 0;
                    if (l2_type == 2u || l2_type == 3u)
                        pa = (l2 & 0xFFFFF000u) | (va & 0xFFFu);
                    else if (l2_type == 1u)
                        pa = (l2 & 0xFFFF0000u) | (va & 0xFFFFu);
                    LOG(Trace, "[disp]   L1@0x%08X=0x%08X COARSE l2_pa=0x%08X "
                        "L2=0x%08X type=%u pa=0x%08X\n",
                        l1_pa, l1, l2_pa, l2, l2_type, pa);
                } else {
                    LOG(Trace, "[disp]   L1@0x%08X=0x%08X UNMAPPED (type=%u)\n",
                        l1_pa, l1, l1_type);
                }
                /* And what's actually at PA 0x84800000 — host-side. */
                const uint8_t* pa_host = mem.TryTranslate(0x84800000u);
                LOG(Trace, "[disp]   PA 0x84800000 host=%p first8=%02X%02X "
                    "%02X%02X %02X%02X %02X%02X\n",
                    (const void*)pa_host,
                    pa_host ? pa_host[0] : 0, pa_host ? pa_host[1] : 0,
                    pa_host ? pa_host[2] : 0, pa_host ? pa_host[3] : 0,
                    pa_host ? pa_host[4] : 0, pa_host ? pa_host[5] : 0,
                    pa_host ? pa_host[6] : 0, pa_host ? pa_host[7] : 0);
            });

            tm.OnPc(0xEF01AAD0u, [](const TraceContext& c) {
                static uint32_t count = 0;
                if (++count <= 5 || (count % 100) == 0) {
                    LOG(Trace, "[disp] AnyBlt #%u entry LR=0x%08X\n",
                        count, c.regs[14]);
                }
            });

            tm.OnPc(0xEF045580u, [](const TraceContext& c) {
                LOG(Trace, "[disp] OMAPDDGPE ctor — about to call "
                    "FlatSurfMgr::Initialize R0=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[14]);
            });

            tm.OnPc(0xEF00F690u, [](const TraceContext& c) {
                static uint32_t count = 0;
                if (++count > 5) return;
                const uint32_t parms = c.regs[1];
                auto pDst = c.ReadVa32(parms + 0x04);
                LOG(Trace, "[disp] OMAPDDGPE::DMAFill #%u parms=0x%08X "
                    "pDst=0x%08X LR=0x%08X\n",
                    count, parms, pDst.value_or(0u), c.regs[14]);
                if (pDst && *pDst) {
                    auto vt   = c.ReadVa32(*pDst + 0x00);
                    auto va   = c.ReadVa32(*pDst + 0x04);
                    auto strd = c.ReadVa32(*pDst + 0x08);
                    LOG(Trace, "[disp]   DMAFill pDst: vtbl=0x%08X "
                        "m_pVirtAddr=0x%08X stride=0x%08X\n",
                        vt.value_or(0u), va.value_or(0u),
                        strd.value_or(0u));
                }
            });

            tm.OnPc(0xEF00F908u, [](const TraceContext& c) {
                static uint32_t count = 0;
                if (++count <= 3) {
                    LOG(Trace, "[disp] OMAPDDGPE::DMASrcCopy #%u R0=0x%08X "
                        "R1(parms)=0x%08X LR=0x%08X\n",
                        count, c.regs[0], c.regs[1], c.regs[14]);
                }
            });

            tm.OnPc(0xEF01C5B4u, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count > 50 && (count % 200u) != 0u) return;
                const uint32_t parms = c.regs[1];
                auto pDst = c.ReadVa32(parms + 0x04);
                auto pSrc = c.ReadVa32(parms + 0x08);
                uint32_t dst_va = 0xDEADBEEFu;
                if (pDst) dst_va = c.ReadVa32(*pDst + 0x04).value_or(0xDEADBEEFu);
                LOG(Trace, "[disp] EmulatedBlt_Internal #%u parms=0x%08X "
                    "pDst=0x%08X pDst.m_pVirtAddr=0x%08X pSrc=0x%08X LR=0x%08X\n",
                    count, parms, pDst.value_or(0u), dst_va,
                    pSrc.value_or(0u), c.regs[14]);
            });
            tm.OnPc(0xEF01A70Cu, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count > 50 && (count % 200u) != 0u) return;
                const uint32_t parms = c.regs[1];
                auto pDst = c.ReadVa32(parms + 0x04);
                uint32_t dst_va = 0xDEADBEEFu;
                if (pDst) dst_va = c.ReadVa32(*pDst + 0x04).value_or(0xDEADBEEFu);
                /* Dump 16 dwords of GPEBltParms to find prclDst / prclClip
                   offsets and content. */
                uint32_t pd[16];
                for (int i = 0; i < 16; ++i) {
                    pd[i] = c.ReadVa32(parms + (uint32_t)(i * 4)).value_or(0xDEADBEEFu);
                }
                LOG(Trace, "[disp] ClipBlt #%u parms=0x%08X pDst=0x%08X "
                    "pDst.m_pVirtAddr=0x%08X pBlt=0x%08X bltFlags=0x%08X "
                    "rop4=0x%08X LR=0x%08X\n",
                    count, parms, pDst.value_or(0u), dst_va,
                    pd[0], pd[9], pd[10], c.regs[14]);
                /* prclDst @ parms[5], prclSrc @ parms[6], prclClip @ parms[7].
                   Each RECT = {left, top, right, bottom}. */
                uint32_t r[12] = {0};
                for (int i = 0; i < 4; ++i) {
                    r[i + 0] = c.ReadVa32(pd[5] + (uint32_t)(i * 4)).value_or(0xDEAD0001u);
                    r[i + 4] = c.ReadVa32(pd[6] + (uint32_t)(i * 4)).value_or(0xDEAD0001u);
                    r[i + 8] = c.ReadVa32(pd[7] + (uint32_t)(i * 4)).value_or(0xDEAD0001u);
                }
                LOG(Trace, "[disp]   prclDst@%08X=(%d,%d)-(%d,%d) prclSrc@%08X=(%d,%d)-(%d,%d) "
                    "prclClip@%08X=(%d,%d)-(%d,%d)\n",
                    pd[5], (int)r[0], (int)r[1], (int)r[2], (int)r[3],
                    pd[6], (int)r[4], (int)r[5], (int)r[6], (int)r[7],
                    pd[7], (int)r[8], (int)r[9], (int)r[10], (int)r[11]);
            });
            tm.OnPc(0xEF0336ECu, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count > 50 && (count % 200u) != 0u) return;
                const uint32_t parms = c.regs[1];
                auto pDst = c.ReadVa32(parms + 0x04);
                auto pSrc = c.ReadVa32(parms + 0x08);
                uint32_t dst_va = 0xDEADBEEFu, dst_stride = 0xDEADBEEFu;
                uint32_t src_va = 0xDEADBEEFu;
                if (pDst) {
                    dst_va = c.ReadVa32(*pDst + 0x04).value_or(0xDEADBEEFu);
                    dst_stride = c.ReadVa32(*pDst + 0x08).value_or(0xDEADBEEFu);
                }
                if (pSrc) src_va = c.ReadVa32(*pSrc + 0x04).value_or(0xDEADBEEFu);
                /* Read prclDst rect (parms+0x14 = prclDst). */
                auto prclDst = c.ReadVa32(parms + 0x14);
                int rl = 0, rt = 0, rr = 0, rb = 0;
                if (prclDst) {
                    rl = (int)c.ReadVa32(*prclDst + 0).value_or(0);
                    rt = (int)c.ReadVa32(*prclDst + 4).value_or(0);
                    rr = (int)c.ReadVa32(*prclDst + 8).value_or(0);
                    rb = (int)c.ReadVa32(*prclDst + 12).value_or(0);
                }
                auto& mem = c.emu.Get<EmulatedMemory>();
                uint32_t pa_dst[4] = {0xDEAD0002u, 0xDEAD0002u, 0xDEAD0002u, 0xDEAD0002u};
                uint32_t pa_src[4] = {0xDEAD0002u, 0xDEAD0002u, 0xDEAD0002u, 0xDEAD0002u};
                if (const uint8_t* h = mem.TryTranslate(0x84800000u))
                    std::memcpy(pa_dst, h, 16);
                if (const uint8_t* h = mem.TryTranslate(0x84896000u))
                    std::memcpy(pa_src, h, 16);
                LOG(Trace, "[disp] EmulatedBltSrcCopy1616 #%u parms=0x%08X "
                    "pDst=0x%08X dst_va=0x%08X pSrc=0x%08X src_va=0x%08X "
                    "rcDst=(%d,%d)-(%d,%d) | PA0x84800000=%08X%08X%08X%08X "
                    "| PA0x84896000=%08X%08X%08X%08X\n",
                    count, parms, pDst.value_or(0u), dst_va,
                    pSrc.value_or(0u), src_va, rl, rt, rr, rb,
                    pa_dst[0], pa_dst[1], pa_dst[2], pa_dst[3],
                    pa_src[0], pa_src[1], pa_src[2], pa_src[3]);
            });
            tm.OnPc(0xEF0246C0u, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count > 80 && (count % 200u) != 0u) return;
                const uint32_t parms = c.regs[1];
                auto pDst = c.ReadVa32(parms + 0x04);
                uint32_t dst_va = 0xDEADBEEFu;
                if (pDst) dst_va = c.ReadVa32(*pDst + 0x04).value_or(0xDEADBEEFu);
                LOG(Trace, "[disp] SelectBlt-FINAL-BLX #%u parms=0x%08X "
                    "pBlt(R4)=0x%08X pDst=0x%08X dst_va=0x%08X\n",
                    count, parms, c.regs[4], pDst.value_or(0u), dst_va);
            });
            tm.OnPc(0xEF024728u, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count > 50 && (count % 200u) != 0u) return;
                const uint32_t parms = c.regs[1];
                auto pDst = c.ReadVa32(parms + 0x04);
                uint32_t dst_va = 0xDEADBEEFu;
                uint32_t fmt = 0xDEADBEEFu;
                if (pDst) {
                    dst_va = c.ReadVa32(*pDst + 0x04).value_or(0xDEADBEEFu);
                    /* m_eFormat is somewhere in the surface; try several offsets. */
                    for (uint32_t off = 0x0C; off <= 0x40; off += 4) {
                        auto v = c.ReadVa32(*pDst + off);
                        if (v && *v < 32) { fmt = (off << 16) | *v; break; }
                    }
                }
                LOG(Trace, "[disp] GPE::EmulatedBlt #%u parms=0x%08X pDst=0x%08X "
                    "dst_va=0x%08X fmt=0x%08X LR=0x%08X\n",
                    count, parms, pDst.value_or(0u), dst_va, fmt, c.regs[14]);
            });
            tm.OnPc(0xEF00E198u, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count > 50 && (count % 200u) != 0u) return;
                const uint32_t parms = c.regs[1];
                auto pDst = c.ReadVa32(parms + 0x04);
                uint32_t dst_va = 0xDEADBEEFu;
                if (pDst) dst_va = c.ReadVa32(*pDst + 0x04).value_or(0xDEADBEEFu);
                LOG(Trace, "[disp] BltComplete #%u parms=0x%08X pDst=0x%08X "
                    "pDst.m_pVirtAddr=0x%08X LR=0x%08X\n",
                    count, parms, pDst.value_or(0u), dst_va, c.regs[14]);
            });

            tm.OnPc(0xEF02A844u, [](const TraceContext& c) {
                static uint32_t count = 0;
                if (++count <= 3) {
                    LOG(Trace, "[disp] RectFillBlt #%u R0=0x%08X R1=0x%08X "
                        "LR=0x%08X\n", count, c.regs[0], c.regs[1],
                        c.regs[14]);
                }
            });

            tm.OnPc(0xEF018B50u, [](const TraceContext& c) {
                static uint32_t count = 0;
                if (++count <= 3) {
                    LOG(Trace, "[disp] DDGPE::PerformBlt #%u R0=0x%08X "
                        "R1(parms)=0x%08X LR=0x%08X\n",
                        count, c.regs[0], c.regs[1], c.regs[14]);
                }
            });

            tm.OnPc(0xEF00DF04u, [](const TraceContext& c) {
                static uint32_t count = 0;
                if (++count <= 3) {
                    LOG(Trace, "[disp] OMAPDDGPE::BltPrepare #%u R0=0x%08X "
                        "R1(parms)=0x%08X LR=0x%08X\n",
                        count, c.regs[0], c.regs[1], c.regs[14]);
                }
            });
        });
    }
};

REGISTER_SERVICE(TraceCe7DisplayInitProbe);

}  /* namespace */
