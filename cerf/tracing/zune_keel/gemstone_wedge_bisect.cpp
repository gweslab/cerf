#include "../trace_manager.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_cpu.h"
#include "../../jit/arm_mmu.h"
#include "../../jit/cpu_state.h"
#include "../../cpu/emulated_memory.h"
#include "../../socs/imx31/imx31_ipu.h"
#include "bundle.h"

#include <atomic>
#include <cstdint>

#if CERF_DEV_MODE

namespace {

constexpr uint32_t kGemstonePid = 0x0C000000u;  /* slot 0x0C = gemstone.exe */

/* gemstone reaches DDraw surface creation but never paints (content latch
   never fires). Sample its user-mode PC + capture its blocking waits to find
   where init wedges before first paint. */
class ZuneKeelGemstoneWedgeBisect : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kZuneKeelBundleCrc32, [&] {
            /* Latched on gemstone's first present; FB-DUMP only scans the SDC
               scanout buffer after presents begin (the EBA page-flips then). */
            auto present_seen = std::make_shared<std::atomic<uint32_t>>(0);
            /* gemstone user-mode PC sampler (skip kernel idle running in its
               FCSE context). Last cluster before silence = the wedge site. */
            tm.OnRunLoopIter([](const TraceContext& c) {
                if (c.pc >= 0x80000000u) return;
                if (c.emu.Get<ArmMmu>().State()->process_id != kGemstonePid) return;
                static std::atomic<uint32_t> n{0};
                const uint32_t i = n.fetch_add(1);
                if (i < 48 || (i & 0xFFu) == 0)
                    LOG(Trace, "[GEMPC] pc=0x%08X lr=0x%08X sp=0x%08X\n",
                        c.pc, c.regs[14], c.regs[13]);
            });

            const auto gem = [](const TraceContext& c) {
                return c.emu.Get<ArmMmu>().State()->process_id == kGemstonePid;
            };

            /* HAL CreateSurface (DDHAL callback). UNFILTERED on purpose: the
               gem-filtered GEM-CS never fired, so the creator is another process —
               re-adding a gemstone filter silences it again. a7&1 = DISPLAYABLE ->
               video heap (sub_3191CA8), else system; logged pid attributes the fire. */
            tm.OnPc(0x318ECB4u, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                const uint32_t i = n.fetch_add(1);
                if (i >= 48) return;
                auto& mmu = c.emu.Get<ArmMmu>();
                auto rd = [&](uint32_t va) -> uint32_t {
                    const uint8_t* p = mmu.PeekVaToHost(va);
                    return p ? *reinterpret_cast<const uint32_t*>(p) : 0xDEADu;
                };
                const uint32_t a1 = c.regs[0], sp = c.regs[13];
                const uint32_t a3 = c.regs[2], a4 = c.regs[3];
                const uint32_t a5 = rd(sp), a6 = rd(sp + 4), a7 = rd(sp + 8);
                const uint32_t expfmt = rd(rd(a1 + 16) + 20);
                LOG(Trace, "[GEM-CS] #%u pid=%08X a1=%08X w=%u h=%u fmt=%08X "
                           "expFmt=%08X a6=%08X caps=%08X %s%s lr=%08X\n",
                    i, mmu.State()->process_id, a1, a3, a4, a5, expfmt, a6, a7,
                    (a7 & 1u) ? "DISPLAYABLE" : "offscreen",
                    ((a7 & 1u) && a5 != expfmt) ? " FMT-MISMATCH->DDERR" : "",
                    c.regs[14]);
                /* HAL CreateSurface reached only via the DDHAL callback ptr
                   (no static xref to its caller); walk the stack to name the
                   server-runtime caller that drives the complex chain. */
                char sb[200]; int q = 0;
                for (uint32_t d = 0; d < 0x100u && q < 180; d += 4) {
                    const uint32_t rv = rd(sp + d);
                    if (rv != 0xDEADu && rv >= 0x02000000u && rv < 0x0C000000u)
                        q += snprintf(sb + q, sizeof(sb) - q, "%08X ", rv);
                }
                LOG(Trace, "[GEM-CS-STK] #%u %s\n", i, sb);
            });
            /* DISPLAYABLE-path outcome: video-heap alloc result (R0 at 0x318ED44,
               just after BL sub_3191CA8). 0 => OUTOFVIDEOMEMORY -> the ddraw runtime
               falls back to a system surface (the blank-screen suspect). */
            tm.OnPc(0x318ED44u, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                if (n.fetch_add(1) >= 48) return;
                LOG(Trace, "[GEM-CSVID] vidAlloc=%08X %s pid=%08X\n",
                    c.regs[0], c.regs[0] ? "ok" : "OUTOFVIDEOMEMORY",
                    c.emu.Get<ArmMmu>().State()->process_id);
            });
            /* Built video surface object (R0 at 0x318ED94 STR R0,[R5]); correlate to
               the present's dev=0x000B448C / srcsurf=0x000B44AC. */
            tm.OnPc(0x318ED94u, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                if (n.fetch_add(1) >= 48) return;
                LOG(Trace, "[GEM-CSOBJ] video surf obj=%08X pid=%08X\n",
                    c.regs[0], c.emu.Get<ArmMmu>().State()->process_id);
            });
            /* System/offscreen surface path taken (loc_318EDC8). */
            tm.OnPc(0x318EDC8u, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                if (n.fetch_add(1) >= 48) return;
                LOG(Trace, "[GEM-CSSYS] system/offscreen surface path pid=%08X\n",
                    c.emu.Get<ArmMmu>().State()->process_id);
            });
            /* sub_3192DB0 post-loop, after the back-buffer video CreateSurface:
               R0=result, R10=back-buffer obj, R11=ctx(R11[3]=count), R9[4]=desc
               (+0x68 ddsCaps). Confirms gemstone's COMPLEX chain + video back. */
            tm.OnPc(0x3193194u, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                if (n.fetch_add(1) >= 8) return;
                auto& mmu = c.emu.Get<ArmMmu>();
                auto rd = [&](uint32_t va) -> uint32_t {
                    const uint8_t* p = mmu.PeekVaToHost(va);
                    return p ? *reinterpret_cast<const uint32_t*>(p) : 0xDEADu;
                };
                const uint32_t v11 = c.regs[10], desc = c.regs[9];
                LOG(Trace, "[GEM-BBREAL] result=%08X v11=%08X v11vt=%08X "
                           "v11sub=%08X v11caps=%08X ddsCaps=%08X pid=%08X\n",
                    c.regs[0], v11, rd(v11), rd(v11 + 4), rd(v11 + 0x20),
                    rd(rd(desc + 4) + 0x68), mmu.State()->process_id);
                /* Any dword in the DDraw object heap equal to v11 references the
                   video back buffer; a referrer in the primary cluster => attach
                   intact. None => the COMPLEX attach link was never written. */
                static std::atomic<uint32_t> hits{0};
                for (uint32_t a = 0x00611000u; a < 0x00613000u; a += 4) {
                    if (rd(a) != v11) continue;
                    if (hits.fetch_add(1) >= 24) break;
                    LOG(Trace, "[GEM-ATTACH] [%08X] -> v11(back %08X)\n", a, v11);
                }
            });
            /* 0x31931B8: R2=v11[1], R3=realized video buffer addr written in.
               Cross-process discriminator vs gemstone srcsurf's system buffer
               (host 0x0B): equal => connected, differ => video back buffer
               never reaches the surface gemstone enumerates. */
            tm.OnPc(0x31931B8u, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                if (n.fetch_add(1) >= 8) return;
                LOG(Trace, "[GEM-BBADDR] v11sub=%08X vidBufAddr=%08X pid=%08X\n",
                    c.regs[2], c.regs[3],
                    c.emu.Get<ArmMmu>().State()->process_id);
            });
            /* gemstone EnumAttachedSurfaces callback: R0=enumerated surface iface;
               its underPSL(iface-8)=server handle delivered. 0x00612310 => video
               back delivered (loss is downstream); 0 => handle-0 surface delivered. */
            tm.OnPcFiltered(0x34E89E4u, gem, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                if (n.fetch_add(1) >= 8) return;
                const uint32_t lp = c.regs[0];
                const uint32_t f = lp < 0x02000000u
                    ? ((lp & 0x01FFFFFFu) | kGemstonePid) : lp;
                LOG(Trace, "[GEM-ENUMCB] lpSurf=%08X vt=%08X underPSL=%08X\n",
                    lp, c.ReadVa32(f).value_or(0xDEADu),
                    c.ReadVa32(f - 8u).value_or(0xDEADu));
            });
            /* Surface QI sub_37A7C28: R0=object base, [R0+4]=input server handle
               (0x00612520 primary / 0x00612480 back). Confirms which surface is
               QI'd and with what handle. */
            tm.OnPcFiltered(0x37A7C28u, gem, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                if (n.fetch_add(1) >= 12) return;
                const uint32_t obj = c.regs[0];
                const uint32_t f = obj < 0x02000000u
                    ? ((obj & 0x01FFFFFFu) | kGemstonePid) : obj;
                LOG(Trace, "[GEM-QI] obj=%08X inHandle=%08X iid=%08X lr=%08X\n",
                    obj, c.ReadVa32(f + 4u).value_or(0xDEADu),
                    c.ReadVa32(c.regs[1]).value_or(0xDEADu), c.regs[14]);
            });
            /* sub_37A7AC0(v13,IID,ppv): R0=v13 = server-QI result handle. 0 here
               => the server QI (PSL 0x1F6C200) returned 0 for this surface, so
               the built proxy binds to nothing (underPSL=0). */
            tm.OnPcFiltered(0x37A7AC0u, gem, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                if (n.fetch_add(1) >= 12) return;
                LOG(Trace, "[GEM-QIRES] v13(resultHandle)=%08X iid=%08X lr=%08X\n",
                    c.regs[0], c.ReadVa32(c.regs[1]).value_or(0xDEADu), c.regs[14]);
            });
            /* sub_34E8A2C = XUI render-target clear: R0=render-target surface,
               [R0+80]=its CPU pixel buffer, [R0+52]/[R0+56]=w/h. Resolve the
               buffer's host vs the video buffers (0x812AA000/0x81491800) to see
               whether XUI renders into video or system memory. */
            tm.OnPcFiltered(0x34E8A2Cu, gem, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                if (n.fetch_add(1) >= 8) return;
                const uint32_t a1 = c.regs[0];
                const uint32_t f = a1 < 0x02000000u
                    ? ((a1 & 0x01FFFFFFu) | kGemstonePid) : a1;
                const uint32_t buf = c.ReadVa32(f + 80u).value_or(0xDEADu);
                const uint32_t bf = (buf && buf < 0x02000000u)
                    ? ((buf & 0x01FFFFFFu) | kGemstonePid) : buf;
                auto& mmu = c.emu.Get<ArmMmu>();
                auto& mem = c.emu.Get<EmulatedMemory>();
                const uint8_t* h = mmu.PeekVaToHost(bf);
                const uint8_t* v0 = mem.TryTranslate(0x812AA000u);
                const uint8_t* v1 = mem.TryTranslate(0x81491800u);
                const bool vid = h && ((v0 && h >= v0 && h < v0 + 0x96000u) ||
                                       (v1 && h >= v1 && h < v1 + 0x96000u));
                LOG(Trace, "[GEM-RTBUF] rt=%08X buf=%08X w=%u h=%u host=%p%s\n",
                    a1, buf, c.ReadVa32(f + 52u).value_or(0),
                    c.ReadVa32(f + 56u).value_or(0), (const void*)h,
                    vid ? " VIDEO" : " system");
            });
            /* sub_34E9160 clear router: PS+11600(=PS[2900]) sw-surface ptr selects
               the sw-clear path; if 0, srcsurf=PS+10840 gets a COLORFILL Blt (traps). */
            tm.OnPcFiltered(0x34E9160u, gem, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                if (n.fetch_add(1) >= 8) return;
                auto fold = [](uint32_t p) {
                    return p < 0x02000000u ? ((p & 0x01FFFFFFu) | kGemstonePid) : p;
                };
                const uint32_t ps = fold(c.regs[0]);
                const uint32_t sw = c.ReadVa32(ps + 11600u).value_or(0xDEADu);
                const uint32_t srcsurf = c.ReadVa32(ps + 10840u).value_or(0xDEADu);
                LOG(Trace, "[GEM-CLEAR] ps=%08X PS[2900]=%08X srcsurf=%08X path=%s "
                           "lr=%08X\n",
                    c.regs[0], sw, srcsurf,
                    sw ? "SW-surf(34E8A2C)" : "srcsurf->Blt-COLORFILL", c.regs[14]);
            });
            /* sub_34E7AAC entry: RenderEnd worker. When PS+11600==0 it Locks
               srcsurf (slot25) and stores lpSurface at PS+11728 = the buffer XUI
               draws into. Confirm it runs + which branch (PS[2900]). */
            tm.OnPcFiltered(0x34E7AACu, gem, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                if (n.fetch_add(1) >= 8) return;
                auto fold = [](uint32_t p) {
                    return p < 0x02000000u ? ((p & 0x01FFFFFFu) | kGemstonePid) : p;
                };
                const uint32_t ps = fold(c.regs[0]);
                LOG(Trace, "[GEM-RENDEND] ps=%08X PS[2900]=%08X PS+11728=%08X "
                           "branch=%s\n",
                    c.regs[0], c.ReadVa32(ps + 11600u).value_or(0xDEADu),
                    c.ReadVa32(ps + 11728u).value_or(0xDEADu),
                    c.ReadVa32(ps + 11600u).value_or(0) ? "sw" : "srcsurf->Lock");
            });
            /* sub_34E7AAC @0x34E7BFC: post srcsurf->Lock store of lpSurface
               (desc+0x24) -> PS+11728, the buffer XUI draws the frame into. R2 holds
               lpSurface. host in 0x812AA000/0x81491800 (or mapped view 0x46300000) =
               VIDEO (Flip works); else system (frame never reaches the flip buffer). */
            tm.OnPcFiltered(0x34E7BFCu, gem, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                if (n.fetch_add(1) >= 8) return;
                auto fold = [](uint32_t p) {
                    return p < 0x02000000u ? ((p & 0x01FFFFFFu) | kGemstonePid) : p;
                };
                const uint32_t lps = c.regs[2];
                auto& mmu = c.emu.Get<ArmMmu>();
                auto& mem = c.emu.Get<EmulatedMemory>();
                const uint8_t* vh = lps ? mmu.PeekVaToHost(fold(lps)) : nullptr;
                const uint8_t* v0 = mem.TryTranslate(0x812AA000u);
                const uint8_t* v1 = mem.TryTranslate(0x81491800u);
                size_t nz = 0;
                if (vh) for (size_t i = 0; i < 0x2000u; ++i) if (vh[i]) ++nz;
                /* DDSURFACEDESC filled by srcsurf->Lock is at SP+4 (lpSurface at
                   desc+0x24 == SP+0x28 confirmed). Dump dwFlags/dwHeight/dwWidth/
                   lPitch/ddsCaps to see what XUI decides render-direct vs shadow on. */
                const uint32_t sp = fold(c.regs[13]);
                auto d = [&](uint32_t off) {
                    return c.ReadVa32(sp + off).value_or(0xDEADu);
                };
                LOG(Trace, "[GEM-LOCKSURF] lpSurface=%08X viewHost=%p "
                           "v0(812AA000)=%p v1(81491800)=%p nz/8K=%zu | "
                           "flags=%08X h=%u w=%u pitch=%d caps=%08X\n",
                    lps, (const void*)vh, (const void*)v0, (const void*)v1, nz,
                    d(8), d(0xC), d(0x10), (int32_t)d(0x14), d(0x6C));
            });
            /* sub_34EA944 rasterizer dispatch: R0=PS, R1=primtype. Gated on
               PS+11728 (locked video buffer) != 0 — else bails with no write.
               Does the scene draw run with the buffer locked? */
            tm.OnPcFiltered(0x34EA944u, gem, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                if (n.fetch_add(1) >= 16) return;
                auto fold = [](uint32_t p) {
                    return p < 0x02000000u ? ((p & 0x01FFFFFFu) | kGemstonePid) : p;
                };
                const uint32_t ps = fold(c.regs[0]);
                const uint32_t locked = c.ReadVa32(ps + 11728u).value_or(0xDEADu);
                /* Scan the locked dest's host content. Many draws hit the same
                   buffer per frame; if stores land, later draws see accumulated
                   nonzero. All-zero across draws => stores never reach this page. */
                auto& mmu = c.emu.Get<ArmMmu>();
                const uint8_t* h = (locked && locked != 0xDEADu)
                    ? mmu.PeekVaToHost(fold(locked)) : nullptr;
                size_t nz = 0;
                if (h) for (size_t i = 0; i < 0x4000u; ++i) if (h[i]) ++nz;
                LOG(Trace, "[GEM-RASTER] primtype=%u PS+11728=%08X destNz/16K=%zu "
                           "%s lr=%08X\n",
                    c.regs[1], locked, nz,
                    locked && locked != 0xDEADu ? "LOCKED" : "UNLOCKED-BAILS",
                    c.regs[14]);
            });
            /* sub_34EA324 triangle setup: R0=PS. v14=*(PS+0x2E20) is the span-fill
               callback ptr AND the enable guard — if 0, returns without filling
               (clip/disabled). R1=vert0 ptr (x,y at [0],[1]). Names the filler to
               hook next + rules out degenerate/offscreen coords. */
            tm.OnPcFiltered(0x34EA324u, gem, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                if (n.fetch_add(1) >= 12) return;
                auto fold = [](uint32_t p) {
                    return p < 0x02000000u ? ((p & 0x01FFFFFFu) | kGemstonePid) : p;
                };
                const uint32_t ps = fold(c.regs[0]);
                const uint32_t filler = c.ReadVa32(ps + 0x2E20u).value_or(0xDEADu);
                /* a2/a3/a4 = R1/R2/R3 = the 3 triangle verts; [0]=x<<16, [1]=y.
                   Dump all 3 (x,y) to see if the triangle has zero area (collapsed). */
                const uint32_t a = fold(c.regs[1]), b = fold(c.regs[2]),
                               cc = fold(c.regs[3]);
                auto rd = [&](uint32_t p) { return c.ReadVa32(p).value_or(0xDEADu); };
                LOG(Trace, "[GEM-FILL] filler=%08X A=(%d,%d) B=(%d,%d) C=(%d,%d)\n",
                    filler,
                    (int32_t)rd(a) >> 16, (int32_t)rd(a + 4u),
                    (int32_t)rd(b) >> 16, (int32_t)rd(b + 4u),
                    (int32_t)rd(cc) >> 16, (int32_t)rd(cc + 4u));
            });
            /* sub_34E9548 per-vertex transform entry: R1=input vert (float x@[0],
               y@[1]); PS+10828=matrix-active. Output Y is constant per triangle; if
               input y bits vary here, the transform flattens Y (else upstream geom). */
            tm.OnPcFiltered(0x34E9548u, gem, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                if (n.fetch_add(1) >= 18) return;
                auto fold = [](uint32_t p) {
                    return p < 0x02000000u ? ((p & 0x01FFFFFFu) | kGemstonePid) : p;
                };
                const uint32_t v = fold(c.regs[1]);
                const uint32_t ps = fold(c.regs[0]);
                LOG(Trace, "[GEM-XFORM] inX=%08X inY=%08X mtxActive=%08X\n",
                    c.ReadVa32(v).value_or(0xDEADu),
                    c.ReadVa32(v + 4u).value_or(0xDEADu),
                    c.ReadVa32(ps + 10828u).value_or(0xDEADu));
            });
            /* sub_34F5904 store-landing test: 0x34F5E08 STRH R5,[LR] captures dest=LR
               +val=R5; 0x34F5E0C (post-store) reads PeekVaToHost(dest). They fire in
               lockstep per pixel. readback!=val => guest store to the video view didn't
               land where reads resolve. */
            {
                auto shared = std::make_shared<std::atomic<uint64_t>>(0);
                tm.OnPcFiltered(0x34F5E08u, gem, [shared](const TraceContext& c) {
                    shared->store((uint64_t(c.regs[14]) << 16) |
                                  (c.regs[5] & 0xFFFFu));
                });
                tm.OnPcFiltered(0x34F5E0Cu, gem, [shared](const TraceContext& c) {
                    static std::atomic<uint32_t> n{0};
                    if (n.fetch_add(1) >= 10) return;
                    const uint64_t s = shared->load();
                    const uint32_t dest = uint32_t(s >> 16);
                    const uint32_t val = uint32_t(s & 0xFFFFu);
                    const uint8_t* h = c.emu.Get<ArmMmu>().PeekVaToHost(dest);
                    const uint32_t got = h
                        ? *reinterpret_cast<const uint16_t*>(h) : 0xDEAD;
                    LOG(Trace, "[GEM-LAND] dest=%08X wrote=%04X readback=%04X %s\n",
                        dest, val, got, (h && got == val) ? "LANDS"
                                                          : "LOST(store-alias)");
                });
            }
            /* sub_34DB6E0 = device draw-command dispatcher: (*(PS+a3+464))().
               R0=device, R2=a3 (command offset), PS=*(device+12). Capture the
               resolved leaf draw fn = *(PS+a3+464) to name the scene compositor. */
            tm.OnPcFiltered(0x34DB6E0u, gem, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                if (n.fetch_add(1) >= 24) return;
                auto fold = [](uint32_t p) {
                    return p < 0x02000000u ? ((p & 0x01FFFFFFu) | kGemstonePid) : p;
                };
                const uint32_t dev = c.regs[0], a3 = c.regs[2];
                const uint32_t ps = c.ReadVa32(fold(dev) + 12u).value_or(0);
                const uint32_t leaf = ps
                    ? c.ReadVa32(fold(ps) + a3 + 464u).value_or(0) : 0u;
                LOG(Trace, "[GEM-DRAW] dev=%08X a3=%08X ps=%08X leaffn=%08X lr=%08X\n",
                    dev, a3, ps, leaf, c.regs[14]);
            });
            /* sub_37A7AC0 @0x37A7B30: per-IID surface proxy constructor call.
               R4=matched table entry, *(R4+4)=ctor, R8=handle, R9=IID. ctor for
               iid0=0x0B0E83E4 builds srcsurf — the function to decompile next. */
            tm.OnPcFiltered(0x37A7B30u, gem, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                if (n.fetch_add(1) >= 16) return;
                const uint32_t ctor = c.ReadVa32(c.regs[4] + 4u).value_or(0);
                const uint32_t iid0 = c.ReadVa32(c.regs[9]).value_or(0);
                LOG(Trace, "[GEM-CTOR] handle=%08X iid0=%08X ctor=%08X lr=%08X\n",
                    c.regs[8], iid0, ctor, c.regs[14]);
            });
            /* GetSurfaceDesc post-trap (0x37A6390): R4=surface iface, desc ptr at
               [SP+0]; server has filled desc.lpSurface(+0x24)=pixel buffer and
               ddsCaps(+0x68). lpSurface in video view (0x46xxxxxx) => buffer is
               video; in 0x0B###### / low => system. The value XUI composites into. */
            tm.OnPcFiltered(0x37A6390u, gem, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                if (n.fetch_add(1) >= 16) return;
                auto fold = [](uint32_t p) {
                    return p < 0x02000000u ? ((p & 0x01FFFFFFu) | kGemstonePid) : p;
                };
                auto rd = [&](uint32_t va) {
                    return c.ReadVa32(fold(va)).value_or(0xDEADu);
                };
                const uint32_t surf = c.regs[4];
                const uint32_t under = rd(surf - 8u);
                const uint32_t desc = c.ReadVa32(c.regs[13]).value_or(0);
                const uint32_t lps = desc ? rd(desc + 0x24u) : 0u;
                const uint32_t caps = desc ? rd(desc + 0x68u) : 0u;
                LOG(Trace, "[GEM-GSD] surf=%08X underPSL=%08X lpSurface=%08X "
                           "ddsCaps=%08X\n", surf, under, lps, caps);
            });
            /* GetDC entry (surf vtbl slot17 sub_37A61E4): does XUI obtain srcsurf's
               drawable via GetDC instead of Lock/GetSurfaceDesc? R0=surface. */
            tm.OnPcFiltered(0x37A61E4u, gem, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                if (n.fetch_add(1) >= 16) return;
                const uint32_t surf = c.regs[0];
                const uint32_t f = surf < 0x02000000u
                    ? ((surf & 0x01FFFFFFu) | kGemstonePid) : surf;
                LOG(Trace, "[GEM-GDC] surf=%08X underPSL=%08X\n",
                    surf, c.ReadVa32(f - 8u).value_or(0xDEADu));
            });
            /* sub_318BC4C @0x318BC78: DDraw HAL one-shot vidmem init. Unfiltered
               — the HAL's loader process isn't known a priori, and the captured
               AllocPhysMem VA↔PA alias is physical / process-independent so any
               firing process is valid. R0=VA, [R5+0x48]=PA (the scanout base). */
            tm.OnPc(0x318BC78u, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                if (n.fetch_add(1) >= 4) return;
                auto& mmu = c.emu.Get<ArmMmu>();
                auto& mem = c.emu.Get<EmulatedMemory>();
                const uint32_t va = c.regs[0];
                const uint8_t* pp = mmu.PeekVaToHost(c.regs[5] + 0x48u);
                const uint32_t pa = pp ? *reinterpret_cast<const uint32_t*>(pp) : 0;
                LOG(Trace, "[GEM-APM] va=%08X pa=%08X hostVA=%p hostPA=%p\n",
                    va, pa, (const void*)mmu.PeekVaToHost(va),
                    (const void*)mem.TryTranslate(pa));
            });

            /* Past VirtualCopy(view=a1[19], PA>>8, size, PAGE_PHYSICAL) @0x318BCE4;
               unfiltered (process-independent physical alias, like GEM-APM). R5=dev:
               PA +0x48, view VA +0x4C. host(viewVA)!=host(PA) = VirtualCopy didn't
               re-point the view onto the scanout physical = the blank-screen root. */
            tm.OnPc(0x318BD14u, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                if (n.fetch_add(1) >= 4) return;
                auto& mmu = c.emu.Get<ArmMmu>();
                auto& mem = c.emu.Get<EmulatedMemory>();
                auto fld = [&](uint32_t off) -> uint32_t {
                    const uint8_t* p = mmu.PeekVaToHost(c.regs[5] + off);
                    return p ? *reinterpret_cast<const uint32_t*>(p) : 0;
                };
                const uint32_t apmVA = fld(0x40), pa = fld(0x48), viewVA = fld(0x4C);
                const uint8_t* hView = mmu.PeekVaToHost(viewVA);
                const uint8_t* hPa = mem.TryTranslate(pa);
                LOG(Trace, "[GEM-VCOPY] apmVA=%08X pa=%08X viewVA=%08X | "
                           "host(viewVA)=%p host(pa)=%p host(apmVA)=%p %s\n",
                    apmVA, pa, viewVA, (const void*)hView, (const void*)hPa,
                    (const void*)mmu.PeekVaToHost(apmVA),
                    hView == hPa ? "ALIAS-OK" : "ALIAS-MISMATCH(view!=phys)");
            });

            /* Unfiltered: the GPE GDI blit runs in the display-driver owner
               process (GWES), not gemstone, so we observe every compositing
               blit regardless of process; pid logged to attribute it. */
            tm.OnPc(0x318C4F0u, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                const uint32_t i = n.fetch_add(1);
                if (i >= 32) return;
                auto& mmu = c.emu.Get<ArmMmu>();
                auto rd = [&](uint32_t va) -> uint32_t {
                    const uint8_t* p = mmu.PeekVaToHost(va);
                    return p ? *reinterpret_cast<const uint32_t*>(p) : 0xDEADu;
                };
                const uint32_t dev = c.regs[0], parms = c.regs[1];
                const uint32_t primary = rd(dev + 4);
                const uint32_t dst = rd(parms + 4);
                const uint32_t src = rd(parms + 8);
                const uint32_t dstVA =
                    (dst && dst != 0xDEADu) ? rd(dst + 4) : 0u;
                const uint8_t* dstHost =
                    (dstVA && dstVA != 0xDEADu) ? mmu.PeekVaToHost(dstVA) : nullptr;
                LOG(Trace, "[GEM-BLT] #%u pid=%08X dev=%08X primary=%08X dst=%08X "
                           "src=%08X dstVA=%08X dstHost=%p%s\n",
                    i, c.emu.Get<ArmMmu>().State()->process_id, dev, primary,
                    dst, src, dstVA, (const void*)dstHost,
                    dst == primary ? " DST=PRIMARY" : "");
            });

            /* IDirectDrawSurface::Lock post-HAL return (ddraw.dll 0x37A6428):
               R4 = DDSurfaceDesc; lpSurface in it = gemstone's pixel write VA.
               Translate desc pointer fields; vid = video-memory host. */
            tm.OnPcFiltered(0x37A6428u, gem, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                const uint32_t i = n.fetch_add(1);
                if (i >= 16) return;
                auto& mmu = c.emu.Get<ArmMmu>();
                auto& mem = c.emu.Get<EmulatedMemory>();
                const uint8_t* vid = mem.TryTranslate(0x812AA000u);
                const uint32_t desc = c.regs[4];
                for (uint32_t o = 0; o < 0x40u; o += 4) {
                    const uint8_t* fp = mmu.PeekVaToHost(desc + o);
                    if (!fp) continue;
                    const uint32_t f = *reinterpret_cast<const uint32_t*>(fp);
                    if (!f) continue;
                    const uint8_t* h = mmu.PeekVaToHost(f);
                    if (h)
                        LOG(Trace, "[GEM-LOCK2] #%u desc[%u]=%08X host=%p vid=%p\n",
                            i, o, f, (const void*)h, (const void*)vid);
                }
            });

            /* Full (non-strided) scan of the IPU SDC scanout buffer: definitive
               answer to "do gemstone's rendered pixels land in the buffer the
               IPU displays?" vs the content-latch's strided heuristic. */
            tm.OnRunLoopIter([present_seen](const TraceContext& c) {
                if (!present_seen->load()) return;  /* only sample post-present */
                static std::atomic<uint32_t> n{0}, logged{0};
                if ((n.fetch_add(1) % 4000u) != 0u || logged.load() >= 80u) return;
                auto& ipu = c.emu.Get<Imx31Ipu>();
                const uint32_t fb_pa = ipu.GetSdcBgFbPa();
                /* skip the boot fb (0x80100000); sample gemstone's DDraw surface */
                if (fb_pa < 0x81200000u) return;
                const uint8_t* fb = c.emu.Get<EmulatedMemory>().TryTranslate(fb_pa);
                const uint32_t w = ipu.GetGuestW(), h = ipu.GetGuestH();
                if (!fb || w <= 1u || h <= 1u) return;
                const size_t bytes = (size_t)w * h * 2u;
                size_t nz = 0, first = (size_t)-1;
                for (size_t i = 0; i < bytes; ++i)
                    if (fb[i]) { ++nz; if (first == (size_t)-1) first = i; }
                logged.fetch_add(1);
                LOG(Trace, "[FB-DUMP] fb_pa=%08X w=%u h=%u bytes=%zu nonzero=%zu "
                           "first=0x%zX head=%02X%02X%02X%02X%02X%02X%02X%02X\n",
                    fb_pa, w, h, bytes, nz, first,
                    fb[0], fb[1], fb[2], fb[3], fb[4], fb[5], fb[6], fb[7]);
                /* Locate gemstone's real draw target: coarse-scan DRAM
                   0x80000000..0x82000000 per 64KB, report blocks with content. */
                if (logged.load() != 1u) return;
                auto& mem = c.emu.Get<EmulatedMemory>();
                for (uint32_t pa = 0x80000000u; pa < 0x82000000u; pa += 0x10000u) {
                    const uint8_t* p = mem.TryTranslate(pa);
                    if (!p) continue;
                    size_t blk_nz = 0;
                    for (size_t i = 0; i < 0x10000u; i += 16) if (p[i]) ++blk_nz;
                    if (blk_nz > 64)
                        LOG(Trace, "[FB-SCAN] pa=%08X nz_samples=%zu/4096\n",
                            pa, blk_nz);
                }
            });

            /* sub_34ACE38 flatten recursion: a2(R1) = curve = 4 control points
               (8 floats). Dump depth + bit patterns. NaN/Inf = bad input coords;
               normal-but-never-flat = VFP flatness compute. */
            {
                auto cn = std::make_shared<std::atomic<uint32_t>>(0);
                tm.OnPcFiltered(0x34ACE38u, gem, [cn](const TraceContext& c) {
                    const uint32_t i = cn->fetch_add(1);
                    if (i < 20 || (i & 0x7Fu) == 0) {
                        const uint32_t p = c.regs[1];
                        uint32_t f[8];
                        for (int k = 0; k < 8; ++k)
                            f[k] = c.ReadVa32(p + k * 4).value_or(0xDEADu);
                        LOG(Trace, "[GEM-CURVE] depth=%u p0=%08X,%08X "
                                   "p1=%08X,%08X p2=%08X,%08X p3=%08X,%08X\n",
                            i, f[0], f[1], f[2], f[3], f[4], f[5], f[6], f[7]);
                    }
                });
            }

            /* Flatness compare sub_34E5EF8(x,y)=(x<y) called from the flatness
               test sub_34ACB78 [0x34ACB78,0x34ACC60). x=lenSq, y=tolerance.
               x==0 => the compare mis-evaluates 0<0.5; x!=0 => upstream
               FSUB/FMUL/FADD on zeros is wrong. */
            {
                auto cn = std::make_shared<std::atomic<uint32_t>>(0);
                tm.OnPcFiltered(0x34E5EF8u,
                    [](const TraceContext& c) {
                        return c.emu.Get<ArmMmu>().State()->process_id
                                   == kGemstonePid
                            && c.regs[14] >= 0x34ACB78u
                            && c.regs[14] < 0x34ACC60u;
                    },
                    [cn](const TraceContext& c) {
                        const uint32_t i = cn->fetch_add(1);
                        if (i < 20 || (i & 0x7Fu) == 0)
                            LOG(Trace, "[GEM-FCMP] #%u x=%08X y=%08X lr=0x%08X\n",
                                i, c.regs[0], c.regs[1], c.regs[14]);
                    });
            }

            /* Pin the broken step of the flatness compare sub_34E5EF8:
               0x34E5F04 = after FCMPS (FPSCR), 0x34E5F08 = after VMRS (CPSR).
               FPSCR N wrong => FCMPS; CPSR N wrong => VMRS transfer; both
               right => conditional eval. */
            tm.OnPcFiltered(0x34E5F04u, gem, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                const uint32_t i = n.fetch_add(1);
                const uint32_t fp = c.emu.Get<ArmCpu>().State()->fpscr;
                if (i < 12 || (i & 0x7Fu) == 0)
                    LOG(Trace, "[GEM-VFPST] postFCMPS fpscr=0x%08X "
                               "N=%u Z=%u C=%u V=%u\n",
                        fp, (fp>>31)&1, (fp>>30)&1, (fp>>29)&1, (fp>>28)&1);
            });
            tm.OnPcFiltered(0x34E5F08u, gem, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                const uint32_t i = n.fetch_add(1);
                if (i < 12 || (i & 0x7Fu) == 0)
                    LOG(Trace, "[GEM-VFPST] postVMRS cpsr=0x%08X "
                               "N=%u Z=%u C=%u V=%u\n",
                        c.cpsr, (c.cpsr>>31)&1, (c.cpsr>>30)&1,
                        (c.cpsr>>29)&1, (c.cpsr>>28)&1);
            });

            /* Content/async/texture load entries; last to fire before the
               Background.xur delayed-init wedge names the blocking op. */
            struct Lx { uint32_t ea; const char* nm; };
            static const Lx kLoad[] = {
                {0x34C1F98u, "XuiElementTreeDelayedInitialization"},
                {0x349ED80u, "XuiSendMessage"},
                {0x34C1D6Cu, "XuiImageElementSetImagePath"},
                {0x34D4710u, "XuiCreateTextureBrushAsync"},
                {0x34D4674u, "XuiCreateTextureBrush"},
                {0x34D2254u, "XuiBrushAsyncComplete"},
                {0x34D2218u, "XuiBrushIsLoaded"},
                {0x34D2414u, "XuiAddTexture"},
                {0x34C82E4u, "XuiResourceLoadAll"},
                {0x34C755Cu, "XuiResourceRead"},
                {0x34C8E0Cu, "XuiSoundSetFile"},
            };
            for (const auto& l : kLoad) {
                const char* nm = l.nm;
                auto cn = std::make_shared<std::atomic<uint32_t>>(0);
                tm.OnPcFiltered(l.ea, gem, [nm, cn](const TraceContext& c) {
                    const uint32_t i = cn->fetch_add(1);
                    if (i < 12 || (i & 0x3Fu) == 0)
                        LOG(Trace, "[GEM-LOAD] %s #%u r0=0x%08X r1=0x%08X "
                                   "r2=0x%08X lr=0x%08X\n",
                            nm, i, c.regs[0], c.regs[1], c.regs[2], c.regs[14]);
                });
            }

            /* inside sub_1E834: navigate#1 -> sub_29308 -> sub_1E080 ->
               navigate#2 -> XuiCreateObject -> sub_1CD80 x6. Block is between
               navigate#1 and navigate#2; narrow it. */
            struct Ix { uint32_t ea; const char* nm; };
            static const Ix kSc2[] = {
                {0x29308u, "sub_29308"},
                {0x1E080u, "sub_1E080"},
                {0x1CD80u, "sub_1CD80 (page-load)"},
            };
            for (const auto& s : kSc2) {
                const char* nm = s.nm;
                auto cn = std::make_shared<std::atomic<uint32_t>>(0);
                tm.OnPcFiltered(s.ea, gem, [nm, cn](const TraceContext& c) {
                    const uint32_t i = cn->fetch_add(1);
                    if (i < 8 || (i & 0x3Fu) == 0)
                        LOG(Trace, "[GEM-SC2] %s #%u r0=0x%08X r1=0x%08X lr=0x%08X\n",
                            nm, i, c.regs[0], c.regs[1], c.regs[14]);
                });
            }

            /* sub_203F0 init tail after scene-load (sub_1E834): sub_1F4E0 ->
               sub_1CBD0 -> ZMediaQueue_Resync -> return. gemstone blocks here
               (never reaches main loop). Last to fire + first silent = blocker. */
            static const Ix kIx[] = {
                {0x1F4E0u, "sub_1F4E0 (post scene-load)"},
                {0x1CBD0u, "sub_1CBD0"},
                {0x3404218u, "ZMediaQueue_Resync"},
            };
            for (const auto& ix : kIx) {
                const char* nm = ix.nm;
                auto cn = std::make_shared<std::atomic<uint32_t>>(0);
                tm.OnPcFiltered(ix.ea, gem, [nm, cn](const TraceContext& c) {
                    const uint32_t i = cn->fetch_add(1);
                    if (i < 6 || (i & 0xFFu) == 0)
                        LOG(Trace, "[GEM-INIT] %s #%u r0=0x%08X lr=0x%08X\n",
                            nm, i, c.regs[0], c.regs[14]);
                });
            }

            /* coredll WaitForMultipleObjects/WaitForSingleObject entries: lr =
               the clean xuidll/gemstone caller one frame above the kernel
               wrapper. Last caller before silence = the wedge wait's caller. */
            struct Wc { uint32_t ea; const char* nm; };
            static const Wc kWaitC[] = {
                {0x3F8F5B8u, "WaitForMultipleObjects"},
                {0x3F8F61Cu, "WaitForSingleObject"},
            };
            for (const auto& w : kWaitC) {
                const char* nm = w.nm;
                auto cn = std::make_shared<std::atomic<uint32_t>>(0);
                tm.OnPcFiltered(w.ea, gem, [nm, cn](const TraceContext& c) {
                    const uint32_t i = cn->fetch_add(1);
                    if (i < 24 || (i & 0xFu) == 0)
                        LOG(Trace, "[GEM-WAITC] %s #%u r0=0x%08X r1=0x%08X "
                                   "r3=0x%08X lr=0x%08X\n",
                            nm, i, c.regs[0], c.regs[1], c.regs[3], c.regs[14]);
                });
            }

            /* Abort/undef vectors (banked LR = fault PC + mode offset) +
               ThreadExceptionExit entry; last GEM-FAULT before GEM-XEXIT crash
               teardown = the crashing instruction. */
            struct Vx { uint32_t ea; const char* nm; };
            static const Vx kVec[] = {
                {0xFFFF0004u, "UNDEF"},
                {0xFFFF000Cu, "PREFETCH_ABORT"},
                {0xFFFF0010u, "DATA_ABORT"},
            };
            for (const auto& v : kVec) {
                const char* nm = v.nm;
                auto cn = std::make_shared<std::atomic<uint32_t>>(0);
                tm.OnPcFiltered(v.ea, gem, [nm, cn](const TraceContext& c) {
                    const uint32_t i = cn->fetch_add(1);
                    if (i < 40 || (i & 0xFu) == 0)
                        LOG(Trace, "[GEM-FAULT] %s #%u bankedLR=0x%08X sp=0x%08X\n",
                            nm, i, c.regs[14], c.regs[13]);
                });
            }
            {
                auto cn = std::make_shared<std::atomic<uint32_t>>(0);
                tm.OnPcFiltered(0x3F96118u, gem, [cn](const TraceContext& c) {
                    const uint32_t i = cn->fetch_add(1);
                    LOG(Trace, "[GEM-XEXIT] #%u r0=0x%08X r1=0x%08X r2=0x%08X "
                               "r3=0x%08X lr=0x%08X\n",
                        i, c.regs[0], c.regs[1], c.regs[2], c.regs[3],
                        c.regs[14]);
                });
            }

            /* sub_349E81C = XUI message dispatcher, calls class handler obj[7]
               (obj+0x1C). Track [0x0C20D6B8] + each call's (obj,handler); when
               the word flips to the corrupt value, the prior call's handler
               is the writer. */
            tm.OnPcFiltered(0x349E81Cu, gem, [](const TraceContext& c) {
                static std::atomic<uint32_t> prevHeap{0}, prevObj{0},
                    prevHandler{0}, logged{0};
                const uint32_t obj = c.regs[0];
                const uint32_t cur = c.ReadVa32(0x0C20D6B8u).value_or(0);
                const uint32_t handler = c.ReadVa32(obj + 0x1Cu).value_or(0);
                const uint32_t ph = prevHeap.exchange(cur);
                const uint32_t po = prevObj.exchange(obj);
                const uint32_t pH = prevHandler.exchange(handler);
                if (cur == 0x12FFFFFFu && ph != 0x12FFFFFFu &&
                    logged.fetch_add(1) < 4)
                    LOG(Trace, "[GEM-MSGH] corrupt after obj=0x%08X "
                               "handler=0x%08X prevHeap=0x%08X\n", po, pH, ph);
            });

            /* sub_34E7660 = ARGB->RGB565 texture upload (writer of the heap
               overrun). a1=r0. Dest buf a1[20] sized a1[13]*a1[14]; first loop
               writes rect a1[16..19] at stride a1[13]. Capture dims vs rect to
               see which input exceeds the buffer. */
            tm.OnPcFiltered(0x34E7660u, gem, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                const uint32_t i = n.fetch_add(1);
                if (i >= 24) return;
                /* r0 is a raw low VA (<32MB); the data TLB is keyed on the
                   FCSE-folded address (raw | gemstone slot). Fold before peek. */
                const uint32_t a = (c.regs[0] & 0x01FFFFFFu) | kGemstonePid;
                const uint32_t w   = c.ReadVa32(a + 13 * 4).value_or(0xDEAD);
                const uint32_t h   = c.ReadVa32(a + 14 * 4).value_or(0xDEAD);
                const uint32_t x0  = c.ReadVa32(a + 16 * 4).value_or(0xDEAD);
                const uint32_t y0  = c.ReadVa32(a + 17 * 4).value_or(0xDEAD);
                const uint32_t x1  = c.ReadVa32(a + 18 * 4).value_or(0xDEAD);
                const uint32_t y1  = c.ReadVa32(a + 19 * 4).value_or(0xDEAD);
                const uint32_t dst = c.ReadVa32(a + 20 * 4).value_or(0xDEAD);
                const uint32_t src = c.ReadVa32(a + 22 * 4).value_or(0xDEAD);
                /* Read the contiguous-heap block-size word that prefixes each
                   user buffer (sub_3F983AC steps by *blockstart). Fold the
                   raw low pointer to the gemstone slot first. */
                const auto hdr = [&](uint32_t p) -> uint32_t {
                    if (p >= 0x02000000u) return 0xDEAD;
                    const uint32_t f = (p & 0x01FFFFFFu) | kGemstonePid;
                    return c.ReadVa32(f - 4).value_or(0xDEAD);
                };
                LOG(Trace, "[GEM-TEX] #%u obj=%08X w=%u h=%u rect=[%u,%u..%u,%u] "
                           "rectW=%d rectH=%d dst=%08X dstHdr=%08X src=%08X "
                           "srcHdr=%08X needRGB=%u needSrc=%u\n",
                    i, a, w, h, x0, y0, x1, y1, (int)(x1 - x0), (int)(y1 - y0),
                    dst, hdr(dst), src, hdr(src), w * h * 2u, w * h * 4u);
                auto& mmu = c.emu.Get<ArmMmu>();
                auto& mem = c.emu.Get<EmulatedMemory>();
                const uint8_t* h_surf = mmu.PeekVaToHost(dst);
                const uint8_t* h_eba0 = mem.TryTranslate(0x812AA000u);
                const uint8_t* h_eba1 = mem.TryTranslate(0x81491800u);
                LOG(Trace, "[GEM-PA] #%u surfVA=%08X hostSurf=%p hostEBA0=%p "
                           "hostEBA1=%p\n",
                    i, dst, (const void*)h_surf, (const void*)h_eba0,
                    (const void*)h_eba1);
            });

            /* sub_34E77DC = texture Lock: allocs src a1[22]=4*rectW*rectH for
               the sub-rect a2, returns ptr+pitch via a4=r3; its caller (LR)
               then fills src and overruns. Capture caller LR + rect + dims to
               find the filler and the dim it uses. */
            tm.OnPcFiltered(0x34E77DCu, gem, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                const uint32_t i = n.fetch_add(1);
                if (i >= 24) return;
                const uint32_t obj = c.regs[0];
                const uint32_t a1f = (obj & 0x01FFFFFFu) | kGemstonePid;
                const uint32_t r2  = c.regs[1];  /* rect ptr (may be 0) */
                uint32_t rx0 = 0, ry0 = 0, rx1 = 0, ry1 = 0;
                if (r2 && r2 < 0x02000000u) {
                    const uint32_t rf = (r2 & 0x01FFFFFFu) | kGemstonePid;
                    rx0 = c.ReadVa32(rf).value_or(0xDEAD);
                    ry0 = c.ReadVa32(rf + 4).value_or(0xDEAD);
                    rx1 = c.ReadVa32(rf + 8).value_or(0xDEAD);
                    ry1 = c.ReadVa32(rf + 12).value_or(0xDEAD);
                }
                const uint32_t w = c.ReadVa32(a1f + 13 * 4).value_or(0xDEAD);
                const uint32_t h = c.ReadVa32(a1f + 14 * 4).value_or(0xDEAD);
                LOG(Trace, "[GEM-LOCK] #%u obj=%08X texW=%u texH=%u rectPtr=%08X "
                           "rect=[%u,%u..%u,%u] flags=%08X caller_lr=%08X\n",
                    i, obj, w, h, r2, rx0, ry0, rx1, ry1, c.regs[2], c.regs[14]);
            });

            /* sub_34D66A0 gradient fill row loop: R10=v11(start), R11=v14(end),
               pitch at [SP+0x18], src base at [SP+0x1C]. */
            tm.OnPcFiltered(0x34D67B0u, gem, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                const uint32_t i = n.fetch_add(1);
                if (i >= 24) return;
                const uint32_t sp = c.regs[13];
                const uint32_t pitch = c.ReadVa32(sp + 0x18u).value_or(0xDEAD);
                const uint32_t base  = c.ReadVa32(sp + 0x1Cu).value_or(0xDEAD);
                LOG(Trace, "[GEM-GRAD] #%u v11=%u v14=%u rows=%d pitch=%u "
                           "base=%08X\n",
                    i, c.regs[10], c.regs[11], (int)(c.regs[11] - c.regs[10]),
                    pitch, base);
            });

            /* sub_34E5CD0 = FTOUIZD (double->uint), R0:R1 = input double bits.
               Filtered to the gradient caller sub_34D66A0; log the double bits
               so the value can be hand-decoded vs the known output 78. */
            tm.OnPcFiltered(0x34E5CD0u,
                [](const TraceContext& c) {
                    return c.emu.Get<ArmMmu>().State()->process_id == kGemstonePid
                        && c.regs[14] >= 0x34D66A0u && c.regs[14] < 0x34D68A4u;
                },
                [](const TraceContext& c) {
                    static std::atomic<uint32_t> n{0};
                    const uint32_t i = n.fetch_add(1);
                    if (i >= 12) return;
                    LOG(Trace, "[GEM-FTOUI] #%u dblLo=%08X dblHi=%08X lr=%08X\n",
                        i, c.regs[0], c.regs[1], c.regs[14]);
                });

            /* sub_34E5D08 = FCVTDS (float->double), R0 = input float bits.
               Filtered to the gradient caller; capture a2[3] (the gradient
               param) to see if the garbage 469762126.0 comes from a bad input
               or from the coredll math op 0x1F220AC downstream. */
            tm.OnPcFiltered(0x34E5D08u,
                [](const TraceContext& c) {
                    return c.emu.Get<ArmMmu>().State()->process_id == kGemstonePid
                        && c.regs[14] >= 0x34D66A0u && c.regs[14] < 0x34D68A4u;
                },
                [](const TraceContext& c) {
                    static std::atomic<uint32_t> n{0};
                    const uint32_t i = n.fetch_add(1);
                    if (i >= 12) return;
                    LOG(Trace, "[GEM-FCVT] #%u floatBits=%08X lr=%08X\n",
                        i, c.regs[0], c.regs[14]);
                });

            /* sub_34E5D08 exit (0x34E5D18, after FMRDL R0/FMRDH R1): R0:R1 =
               the FCVTDS output double. If high word == raw float bits, FCVTDS
               (or FMRDH) is wrong; if it's the correct double, the garbage
               enters downstream (math op / FMDLR/FMDHR rebuild). */
            tm.OnPcFiltered(0x34E5D18u,
                [](const TraceContext& c) {
                    return c.emu.Get<ArmMmu>().State()->process_id == kGemstonePid
                        && c.regs[14] >= 0x34D66A0u && c.regs[14] < 0x34D68A4u;
                },
                [](const TraceContext& c) {
                    static std::atomic<uint32_t> n{0};
                    const uint32_t i = n.fetch_add(1);
                    if (i >= 12) return;
                    LOG(Trace, "[GEM-FCVTO] #%u outLo=%08X outHi=%08X lr=%08X\n",
                        i, c.regs[0], c.regs[1], c.regs[14]);
                });

            /* sub_34D0B20 present: at 0x34D0B78 (just after the vtable+0x44
               present-method call) R0=result, R4=method addr, R5=a1. Tells us
               whether present succeeds or errors (surface-lost 0x88760868) and
               the method to decompile next. */
            tm.OnPcFiltered(0x34D0B78u, gem, [present_seen](const TraceContext& c) {
                present_seen->store(1);  /* gate FB-DUMP on post-present window */
                static std::atomic<uint32_t> n{0};
                const uint32_t i = n.fetch_add(1);
                if (i < 8 || (i & 0x3Fu) == 0)
                    LOG(Trace, "[GEM-PRESENT] #%u result=0x%08X method=0x%08X "
                               "a1=0x%08X\n", i, c.regs[0], c.regs[4], c.regs[5]);
            });

            /* XUI render device dump (render ctx 0x000B5DD0, *ctx=device). Find the
               render-target surface field — system (host 0x0B) vs the video back
               buffer (host of 0x812AA000). PeekVaToHost in OnRunLoopIter (ReadVa32
               missed); vt = each field's [0] to spot surface vtables (0x37A1AB0). */
            tm.OnRunLoopIter([](const TraceContext& c) {
                if (c.emu.Get<ArmMmu>().State()->process_id != kGemstonePid) return;
                static std::atomic<uint32_t> done{0};
                if (done.load()) return;
                auto& mmu = c.emu.Get<ArmMmu>();
                auto& mem = c.emu.Get<EmulatedMemory>();
                auto rd = [&](uint32_t va, uint32_t* out) -> bool {
                    const uint32_t f = va < 0x02000000u
                        ? ((va & 0x01FFFFFFu) | kGemstonePid) : va;
                    const uint8_t* p = mmu.PeekVaToHost(f);
                    if (!p) return false;
                    *out = *reinterpret_cast<const uint32_t*>(p);
                    return true;
                };
                uint32_t dev = 0;
                if (!rd(0x0C0B5DD0u, &dev) || !dev) return;
                if (done.fetch_add(1)) return;
                const uint8_t* hv = mem.TryTranslate(0x812AA000u);
                LOG(Trace, "[GEM-XRT] ctx=000B5DD0 dev=%08X hv=%p\n",
                    dev, (const void*)hv);
                for (uint32_t o = 0; o < 0x80u; o += 4) {
                    uint32_t f = 0;
                    if (!rd(dev + o, &f) || !f) continue;
                    const uint32_t ff = f < 0x02000000u
                        ? ((f & 0x01FFFFFFu) | kGemstonePid) : f;
                    const uint8_t* h = mmu.PeekVaToHost(ff);
                    const bool vid = h && hv && h >= hv && h < hv + 0x300000u;
                    uint32_t vt = 0;
                    rd(f, &vt);
                    LOG(Trace, "[GEM-XRT] dev[%02X]=%08X vt=%08X host=%p%s\n",
                        o, f, vt, (const void*)h, vid ? " <==VIDEO" : "");
                }
                /* Dump the render-target candidate dev[0x0C] to find its pixel
                   buffer (host 0x0B/system vs video) and its surface type. */
                uint32_t rt = 0;
                if (rd(dev + 0x0Cu, &rt) && rt) {
                    for (uint32_t o = 0; o < 0x40u; o += 4) {
                        uint32_t f = 0;
                        if (!rd(rt + o, &f) || !f) continue;
                        const uint32_t ff = f < 0x02000000u
                            ? ((f & 0x01FFFFFFu) | kGemstonePid) : f;
                        const uint8_t* h = mmu.PeekVaToHost(ff);
                        const bool vid = h && hv && h >= hv && h < hv + 0x300000u;
                        LOG(Trace, "[GEM-XRT] RT(%08X)[%02X]=%08X host=%p%s\n",
                            rt, o, f, (const void*)h, vid ? " <==VIDEO" : "");
                    }
                }
            });

            /* Resolve the ddraw HAL/runtime callback pointers MEMORY[0x1F6C...] the
               surface Blt/Flip/Lock forward to — the next straight hop (where the
               COLORFILL on srcsurf actually writes). Read the pointer values, don't
               assume "PSL server". slot-0 ddraw data; PeekVaToHost folds by pid. */
            tm.OnRunLoopIter([](const TraceContext& c) {
                if (c.emu.Get<ArmMmu>().State()->process_id != kGemstonePid) return;
                static std::atomic<uint32_t> done{0};
                if (done.load()) return;
                auto& mmu = c.emu.Get<ArmMmu>();
                auto rd = [&](uint32_t va) -> uint32_t {
                    const uint8_t* p = mmu.PeekVaToHost(va);
                    return p ? *reinterpret_cast<const uint32_t*>(p) : 0;
                };
                const uint32_t blt = rd(0x01F6C180u);
                if (!blt) return;
                if (done.fetch_add(1)) return;
                LOG(Trace, "[GEM-CB] Blt(180)=%08X Flip(1A4)=%08X Lock(1F4)=%08X "
                           "op(22C)=%08X ddc(288)=%08X\n",
                    blt, rd(0x01F6C1A4u), rd(0x01F6C1F4u),
                    rd(0x01F6C22Cu), rd(0x01F6C288u));
            });

            /* Prefetch-abort vector: CERF raises it for a PSL-trap call (0xF000xxxx).
               In abort mode R14 = LR_abt = trap+4, so the trap addr is R14-4; filter
               to the DDraw api-set range (0xF0008xxx) to capture which op traps. */
            tm.OnPc(0xFFFF000Cu, [](const TraceContext& c) {
                const uint32_t trap = c.regs[14] - 4u;  /* LR_abt = trap+4 */
                /* DDraw Blt (0xF00082F8) / Flip (0xF00082D4) only — 0xF0008400 is a
                   hot unrelated PSL call that floods the broad range. */
                if (trap != 0xF00082F8u && trap != 0xF00082D4u) return;
                static std::atomic<uint32_t> dumped{0};
                if (dumped.fetch_add(1) == 0) {
                    /* prefetch-abort high-vector literal pool: kernel dispatch entry */
                    for (uint32_t a = 0xFFFF0020u; a < 0xFFFF0040u; a += 4)
                        LOG(Trace, "[GEM-PSL] vec[%08X]=%08X\n", a,
                            c.ReadVa32(a).value_or(0));
                }
                static std::atomic<uint32_t> n{0};
                if (n.fetch_add(1) >= 12) return;
                LOG(Trace, "[GEM-PSL] %s trap=%08X r0=%08X r1=%08X r2=%08X pid=%08X\n",
                    trap == 0xF00082F8u ? "BLT" : "FLIP", trap,
                    c.regs[0], c.regs[1], c.regs[2],
                    c.emu.Get<ArmMmu>().State()->process_id);
            });

            /* Poll the source DDraw surface object (srcsurf=0x000B44AC, folded
               0x0C0B44AC) until its page is fast-path-resident, then dump it
               once to find the pixel-buffer pointer (compare to SDC EBA). */
            tm.OnRunLoopIter([](const TraceContext& c) {
                if (c.emu.Get<ArmMmu>().State()->process_id != kGemstonePid) return;
                static std::atomic<uint32_t> done{0};
                if (done.load()) return;
                const uint32_t sf = 0x0C0B44ACu;
                const auto w0 = c.ReadVa32(sf);
                if (!w0.has_value() || *w0 == 0u) return;
                if (done.fetch_add(1)) return;
                char b[256]; int p = 0;
                for (uint32_t o = 0; o < 0x60u && p < 240; o += 4)
                    p += snprintf(b + p, sizeof(b) - p, "%08X ",
                                  c.ReadVa32(sf + o).value_or(0xDEAD));
                LOG(Trace, "[GEM-SRCSURF] obj=0C0B44AC: %s\n", b);
                const uint32_t sub = c.ReadVa32(sf + 0x10u).value_or(0);
                auto& mmu = c.emu.Get<ArmMmu>();
                auto& mem = c.emu.Get<EmulatedMemory>();
                const uint8_t* hVid = mem.TryTranslate(0x812AA000u);
                for (uint32_t o = 0; sub && o < 0x60u; o += 4) {
                    const auto fo = c.ReadVa32(sub + o);
                    if (!fo.has_value() || *fo == 0u) continue;
                    const uint8_t* h = mmu.PeekVaToHost(*fo);
                    if (h)
                        LOG(Trace, "[GEM-RT] sub=%08X [%u]=%08X host=%p (vidHost=%p)\n",
                            sub, o, *fo, (const void*)h, (const void*)hVid);
                }
            });

            /* Resolve the present primary (dev=0x000B448C) and back/render-target
               (srcsurf=0x000B44AC) underlying surfaces via *(iface-8) (what the
               Flip/Lock forwarders hand the HAL); flag any field whose host is the
               video heap (host of PA 0x812AA000) = scanout, vs 0x0B###### = system. */
            tm.OnRunLoopIter([](const TraceContext& c) {
                if (c.emu.Get<ArmMmu>().State()->process_id != kGemstonePid) return;
                static std::atomic<uint32_t> done{0};
                if (done.load()) return;
                auto& mmu = c.emu.Get<ArmMmu>();
                /* full page-table walk (not fast-path ReadVa32 — that misses on
                   non-resident object pages and masks as 0). */
                auto rd = [&](uint32_t va, uint32_t* out) -> bool {
                    const uint32_t f = va < 0x02000000u
                        ? ((va & 0x01FFFFFFu) | kGemstonePid) : va;
                    const uint8_t* p = mmu.PeekVaToHost(f);
                    if (!p) return false;
                    *out = *reinterpret_cast<const uint32_t*>(p);
                    return true;
                };
                /* latch once the primary iface is resident (its underlying PSL
                   object is server-side, unmapped in gemstone — only the -8 pointer
                   value is readable here; resolve it in GWES context). */
                uint32_t pu = 0;
                if (!rd(0x0C0B4484u, &pu) || !pu) return;
                if (done.fetch_add(1)) return;
                struct S { uint32_t iface; const char* nm; };
                const S surfs[] = {{0x0C0B448Cu, "PRIMARY/dev"},
                                   {0x0C0B44ACu, "BACK/srcsurf"}};
                for (const auto& s : surfs) {
                    uint32_t under = 0;
                    rd(s.iface - 8u, &under);
                    LOG(Trace, "[GEM-UNDER] %s iface=%08X underPSL=%08X\n",
                        s.nm, s.iface, under);
                }
            });

            /* Does gemstone's address space contain video memory? Scan the CE
               shared region (>0x42000000, process-global VAs) for a VA whose host
               is the video heap (host of PA 0x812AA000). Found => gemstone can render
               to video (system surfaces are a binding choice); none => no video map. */
            tm.OnRunLoopIter([](const TraceContext& c) {
                if (c.emu.Get<ArmMmu>().State()->process_id != kGemstonePid) return;
                static std::atomic<uint32_t> done{0};
                if (done.load()) return;
                auto& mmu = c.emu.Get<ArmMmu>();
                auto& mem = c.emu.Get<EmulatedMemory>();
                const uint8_t* hv = mem.TryTranslate(0x812AA000u);
                if (!hv) return;
                if (done.fetch_add(1)) return;
                uint32_t hits = 0;
                for (uint32_t va = 0x42000000u; va < 0x48000000u; va += 0x100000u) {
                    const uint8_t* h = mmu.PeekVaToHost(va);
                    if (h && h >= hv && h < hv + 0x300000u) {
                        LOG(Trace, "[GEM-VIDMAP] gemstone VA=%08X -> host=%p "
                                   "(video heap, vidHost=%p)\n",
                            va, (const void*)h, (const void*)hv);
                        if (++hits >= 8) break;
                    }
                }
                if (!hits)
                    LOG(Trace, "[GEM-VIDMAP] gemstone maps NO video VA in "
                               "0x42000000..0x48000000 (vidHost=%p)\n",
                        (const void*)hv);
            });

            /* GWES-context surface buffer resolver. HAL surface buffer VA = GPE
               device view base (device[19]) + surf[11] offset; map each to a host
               and flag video (host of PA 0x812AA000) vs system. Settles whether the
               present primary/srcsurf server-side surfaces are video- or system-backed. */
            tm.OnRunLoopIter([](const TraceContext& c) {
                constexpr uint32_t kGwesPid = 0x08000000u;
                if (c.emu.Get<ArmMmu>().State()->process_id != kGwesPid) return;
                static std::atomic<uint32_t> done{0};
                if (done.load()) return;
                auto& mmu = c.emu.Get<ArmMmu>();
                auto& mem = c.emu.Get<EmulatedMemory>();
                auto rd = [&](uint32_t va, uint32_t* out) -> bool {
                    const uint32_t f = va < 0x02000000u
                        ? ((va & 0x01FFFFFFu) | kGwesPid) : va;
                    const uint8_t* p = mmu.PeekVaToHost(f);
                    if (!p) return false;
                    *out = *reinterpret_cast<const uint32_t*>(p);
                    return true;
                };
                uint32_t dvb = 0, pv = 0;
                if (!rd(0x000D1980u + 19u * 4u, &dvb) || !dvb) return;
                if (!mmu.PeekVaToHost(dvb)) return;     /* view not VirtualCopy'd yet */
                if (!rd(0x00612520u, &pv) || !pv) return; /* primary underlying absent */
                if (done.fetch_add(1)) return;
                const uint8_t* hv = mem.TryTranslate(0x812AA000u);
                LOG(Trace, "[GEM-HALSURF] devViewBase[19]=%08X host=%p vidHost=%p\n",
                    dvb, (const void*)mmu.PeekVaToHost(dvb), (const void*)hv);
                const uint32_t objs[] = {0x000D8110u, 0x000E2DA0u, 0x00612520u,
                                         0x00612480u, 0x00612310u, 0x00612540u};
                /* CE5 DDRAWI_DDRAWSURFACE_LCL: +0x04 lpGbl, +0x20 ddsCaps;
                   GBL +0x14 fpVidMem (the pixel buffer). Classify fpVidMem host
                   vs the video heap to see each surface's real backing. */
                for (uint32_t o : objs) {
                    uint32_t lpGbl = 0, caps = 0, fpVid = 0;
                    rd(o + 4u, &lpGbl);
                    rd(o + 0x20u, &caps);
                    if (lpGbl) rd(lpGbl + 0x14u, &fpVid);
                    const uint8_t* h = fpVid ? mmu.PeekVaToHost(fpVid) : nullptr;
                    const bool vid = h && h >= hv && h < hv + 0x300000u;
                    LOG(Trace, "[GEM-HALSURF] LCL=%08X lpGbl=%08X ddsCaps=%08X "
                               "fpVidMem=%08X host=%p%s\n",
                        o, lpGbl, caps, fpVid, (const void*)h,
                        vid ? " VIDEO" : " system");
                }
                /* Primary PSL surface 0x00612520 -> HAL surface (field whose [0] is
                   the HAL surface vtable 0x318AA80) -> buffer = devView + HAL off[11].
                   Resolves whether the primary's real backing is video or system. */
                for (uint32_t o = 0; o < 0x80u; o += 4) {
                    uint32_t f = 0;
                    if (!rd(0x00612520u + o, &f) || !f) continue;
                    uint32_t vt = 0;
                    if (!rd(f, &vt) || vt != 0x0318AA80u) continue;
                    uint32_t hoff = 0;
                    rd(f + 11u * 4u, &hoff);
                    const uint32_t buf = dvb + hoff;
                    const uint8_t* h = mmu.PeekVaToHost(buf);
                    const bool vid = h && h >= hv && h < hv + 0x300000u;
                    LOG(Trace, "[GEM-HALSURF] PSL[0x%02X]=%08X HAL off[11]=%08X "
                               "buf=%08X host=%p%s\n",
                        o, f, hoff, buf, (const void*)h, vid ? " VIDEO" : " system/?");
                }
            });

            /* sub_34E8788 present-blit: switch(*(a1+11740))=mode; blits via
               device *(a1+10836) vtable+20 (case3) / +44 (case2/101). Capture
               mode + device + blit-method addrs to follow the pixels to the fb. */
            tm.OnPcFiltered(0x34E8788u, gem, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                const uint32_t i = n.fetch_add(1);
                if (i >= 6) return;
                auto fold = [](uint32_t p) {
                    return p < 0x02000000u ? ((p & 0x01FFFFFFu) | kGemstonePid) : p;
                };
                const uint32_t a1 = fold(c.regs[0]);
                const uint32_t mode = c.ReadVa32(a1 + 11740u).value_or(0xDEAD);
                const uint32_t dev  = c.ReadVa32(a1 + 10836u).value_or(0);
                const uint32_t srcs = c.ReadVa32(a1 + 10840u).value_or(0);
                auto rd = [&](uint32_t off) {
                    return (int32_t)c.ReadVa32(a1 + off).value_or(0xDEAD);
                };
                LOG(Trace, "[GEM-BLIT] #%u mode=%u dev=%08X srcsurf=%08X\n",
                    i, mode, dev, srcs);
                LOG(Trace, "[GEM-RECT] #%u rA[11608..11636]=%d,%d,%d,%d,%d,%d,%d,%d "
                           "rB[11688..11700]=%d,%d,%d,%d\n",
                    i, rd(11608), rd(11612), rd(11616), rd(11620), rd(11624),
                    rd(11628), rd(11632), rd(11636),
                    rd(11688), rd(11692), rd(11696), rd(11700));
                (void)srcs;  /* surface object dumped via poll below (fast-path) */
            });

            /* sub_34E8788 case-3 blit call (0x34E8964 MOV PC,R4): R4=blit method
               (dev vtable+0x14), R0=dev, R2=source surface. Captures the blit fn
               from the register (no vtable read), to follow pixels to the fb. */
            tm.OnPcFiltered(0x34E8964u, gem, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                const uint32_t i = n.fetch_add(1);
                if (i >= 6) return;
                LOG(Trace, "[GEM-BLT3] #%u blitfn=0x%08X dev=0x%08X srcsurf=0x%08X\n",
                    i, c.regs[4], c.regs[0], c.regs[2]);
            });

            /* Device vtable at 0x037A1AB0 (module beyond xuidll). Poll across
               run-loop iters in gemstone context until the .rdata page is
               fast-path-resident, then log present(+0x2C) and blit(+0x14). */
            tm.OnRunLoopIter([](const TraceContext& c) {
                if (c.emu.Get<ArmMmu>().State()->process_id != kGemstonePid) return;
                static std::atomic<uint32_t> logged{0};
                if (logged.load()) return;
                const auto m2c = c.ReadVa32(0x037A1AB0u + 0x2Cu);
                const auto m14 = c.ReadVa32(0x037A1AB0u + 0x14u);
                if (m2c && m14 && logged.fetch_add(1) == 0) {
                    LOG(Trace, "[GEM-DEVVT] present+0x2C=%08X blit+0x14=%08X\n",
                        *m2c, *m14);
                    /* Scan the module .rdata for ASCII strings (name/symbols)
                       to identify the module owning the present/blit methods. */
                    char buf[80]; int bi = 0;
                    for (uint32_t a = 0x037A0000u; a < 0x037A2000u; a += 4) {
                        const auto w = c.ReadVa32(a);
                        if (!w) { bi = 0; continue; }
                        for (int k = 0; k < 4; ++k) {
                            const char ch = (char)((*w >> (k * 8)) & 0xFFu);
                            if (ch >= 0x20 && ch < 0x7F) {
                                if (bi < 78) buf[bi++] = ch;
                            } else {
                                if (bi >= 5) { buf[bi] = 0;
                                    LOG(Trace, "[GEM-STR] %08X %s\n", a, buf); }
                                bi = 0;
                            }
                        }
                    }
                }
            });

            /* The corrupt heap word at 0x0C20D6B8 (deterministic across runs)
               holds the bad header 0x12FFFFFF. Poll it per RunLoop iter; log the
               transition into the bad value + PC to localize the writer. */
            tm.OnRunLoopIter([](const TraceContext& c) {
                if (c.emu.Get<ArmMmu>().State()->process_id != kGemstonePid)
                    return;
                const auto v = c.ReadVa32(0x0C20D6B8u);
                if (!v.has_value()) return;
                static std::atomic<uint32_t> prev{0};
                static std::atomic<uint32_t> logged{0};
                const uint32_t cur = *v;
                const uint32_t p = prev.exchange(cur);
                if (cur != p && logged.fetch_add(1) < 12)
                    LOG(Trace, "[GEM-CORRUPTW] 0x0C20D6B8: 0x%08X -> 0x%08X "
                               "pc=0x%08X lr=0x%08X\n", p, cur, c.pc, c.regs[14]);
                /* On the corrupt transition, dump the surrounding heap to see
                   the overflow pattern + the preceding block boundary. */
                if (cur == 0x12FFFFFFu && p != 0x12FFFFFFu) {
                    static std::atomic<uint32_t> dumped{0};
                    if (dumped.fetch_add(1) == 0) {
                        for (uint32_t a = 0x0C20D388u; a <= 0x0C20D778u; a += 16) {
                            LOG(Trace, "[GEM-HEAPDUMP] %08X: %08X %08X %08X %08X\n",
                                a, c.ReadVa32(a).value_or(0xDEAD),
                                c.ReadVa32(a + 4).value_or(0xDEAD),
                                c.ReadVa32(a + 8).value_or(0xDEAD),
                                c.ReadVa32(a + 12).value_or(0xDEAD));
                        }
                        LOG(Trace, "[GEM-CW-REGS] r0=%08X r1=%08X r2=%08X r3=%08X "
                                   "r4=%08X r5=%08X r6=%08X r7=%08X r12=%08X "
                                   "sp=%08X lr=%08X pc=%08X\n",
                            c.regs[0], c.regs[1], c.regs[2], c.regs[3], c.regs[4],
                            c.regs[5], c.regs[6], c.regs[7], c.regs[12],
                            c.regs[13], c.regs[14], c.pc);
                        /* Stack return-addr scan: shared-DLL + gemstone-slot code
                           frames at the batch boundary name the filler. */
                        char sb[480]; int q = 0;
                        for (uint32_t d = 0; d < 0x400u && q < 460; d += 4) {
                            const auto w = c.ReadVa32(c.regs[13] + d);
                            if (!w.has_value()) continue;
                            const uint32_t rv = *w;
                            if ((rv >= 0x02000000u && rv < 0x0C000000u) ||
                                (rv >= 0x0C000000u && rv < 0x0C100000u))
                                q += snprintf(sb + q, sizeof(sb) - q, "%08X ", rv);
                        }
                        LOG(Trace, "[GEM-CW-STK] %s\n", sb);
                    }
                }
            });

            /* Data abort inside the coredll heap free-list walk sub_3F983AC
               [0x3F983AC,0x3F98500): banked abort LR = fault PC + 8. FAR =
               the wild pointer the walk dereferenced = the corrupted heap
               block address; capture it + GPRs to hunt the corrupting write. */
            tm.OnPcFiltered(0xFFFF0010u, gem, [](const TraceContext& c) {
                const uint32_t flr = c.regs[14];
                if (flr < 0x03F983ACu || flr >= 0x03F98500u) return;
                static std::atomic<uint32_t> n{0};
                if (n.fetch_add(1) >= 8) return;
                const uint32_t fault_addr =
                    c.emu.Get<ArmMmu>().State()->fault_address;
                LOG(Trace, "[GEM-HEAPFLT] far=0x%08X flr=0x%08X r0=%08X r3=%08X "
                           "r4=%08X r6=%08X r7=%08X r8=%08X r10=%08X sp=%08X\n",
                    fault_addr, flr, c.regs[0], c.regs[3], c.regs[4], c.regs[6],
                    c.regs[7], c.regs[8], c.regs[10], c.regs[13]);
            });

            /* sub_34C0C38 = recursive element-tree delayed-init; sends
               XuiSendMessage(element, init) per element. The LAST element whose
               entry fires before the recursion stalls is where init blocks. */
            tm.OnPcFiltered(0x34C0C38u, gem, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                const uint32_t i = n.fetch_add(1);
                if (i < 600)
                    LOG(Trace, "[GEM-ELEM] #%u elem=0x%08X parent=0x%08X "
                               "lr=0x%08X\n",
                        i, c.regs[0], c.regs[1], c.regs[14]);
            });
            /* 0x8821A9B8 = WaitForSingleObject wrapper, 0x8821A5F8 =
               WaitForMultipleObjects. Filtered to gemstone: handle + timeout +
               caller LR (the coredll site; the user caller is up the stack). */
            tm.OnPcFiltered(0x8821A9B8u, gem, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                const uint32_t i = n.fetch_add(1);
                if (i < 40 || (i & 0x3Fu) == 0)
                    LOG(Trace, "[GEM-WFSO] #%u hnd=0x%08X timeout=0x%08X "
                               "lr=0x%08X\n", i, c.regs[0], c.regs[1], c.regs[14]);
            });
            /* xuidll scene/UI load chain. gemstone never renders; check whether
               it loads a UI scene at all. Last to fire + first silent = where
               scene construction stalls. */
            struct Sx { uint32_t ea; const char* nm; };
            static const Sx kSx[] = {
                {0x34C8084u, "XuiResourceOpen"},
                {0x34C5650u, "XuiLoadVisualFromBinary"},
                {0x34C3220u, "XuiSceneCreateEx"},
                {0x34C48D8u, "XuiCreateObjectFromData"},
                {0x34A28D4u, "XuiCreateObject"},
                {0x34C4AE8u, "XuiSceneNavigateFirst"},
            };
            for (const auto& s : kSx) {
                const char* nm = s.nm;
                auto cn = std::make_shared<std::atomic<uint32_t>>(0);
                tm.OnPcFiltered(s.ea, gem, [nm, cn](const TraceContext& c) {
                    const uint32_t i = cn->fetch_add(1);
                    if (i < 8 || (i & 0x3Fu) == 0)
                        LOG(Trace, "[GEM-SCENE] %s #%u r0=0x%08X lr=0x%08X\n",
                            nm, i, c.regs[0], c.regs[14]);
                });
            }

            /* sub_20008 main loop renders only on MsgWaitForMultipleObjectsEx
               WAIT_TIMEOUT; a permanently-signaled handle starves that path. The
               handler that fires repeatedly names the stuck handle's subsystem.
               gemstone code runs at slot-0 VAs == IDA RVA while it's active. */
            struct Dx { uint32_t ea; const char* nm; };
            static const Dx kDx[] = {
                {0x1CC24u, "h@64 sub_1CC24"}, {0x1DF98u, "h@68 sub_1DF98"},
                {0x1E018u, "h@72 sub_1E018"}, {0x1FBD4u, "h@84 sub_1FBD4"},
                {0x1F878u, "h@76 sub_1F878"}, {0x1F360u, "h@88 sub_1F360"},
                {0x1CC84u, "h@92/96 sub_1CC84"}, {0x1CCF8u, "h@100 sub_1CCF8"},
            };
            for (const auto& dx : kDx) {
                const char* nm = dx.nm;
                auto cn = std::make_shared<std::atomic<uint32_t>>(0);
                tm.OnPcFiltered(dx.ea, gem, [nm, cn](const TraceContext&) {
                    const uint32_t i = cn->fetch_add(1);
                    if (i < 6 || (i & 0x3FFu) == 0)
                        LOG(Trace, "[GEM-DISP] %s #%u\n", nm, i);
                });
            }

            /* per-frame XUI calls. gemstone's render callback is registered but
               never invoked. Does gemstone run a per-frame loop at all, and does
               it ever see the scene as dirty (needing a render)? */
            struct Fx { uint32_t ea; const char* nm; };
            static const Fx kFx[] = {
                {0x34996A8u, "XuiGetSleepInterval"},
                {0x34C6D6Cu, "XuiTimersRun"},
                {0x3497A98u, "XuiAnimRun"},
                {0x34C111Cu, "XuiProcessInput"},
                {0x34BE58Cu, "XuiElementTreeGetDirtyExtents"},
            };
            for (const auto& f : kFx) {
                const char* nm = f.nm;
                auto cn = std::make_shared<std::atomic<uint32_t>>(0);
                tm.OnPcFiltered(f.ea, gem, [nm, cn](const TraceContext& c) {
                    const uint32_t i = cn->fetch_add(1);
                    if (i < 6 || (i & 0xFFu) == 0)
                        LOG(Trace, "[GEM-FRAME] %s #%u r0=0x%08X lr=0x%08X\n",
                            nm, i, c.regs[0], c.regs[14]);
                });
            }

            /* xuidll render loop (load-aligned, VA==IDA). Does gemstone run
               XuiRenderBegin->End->Present? If Present fires but the framebuffer
               stays blank, the bug is the DDraw flip/surface path, not render. */
            struct Rx { uint32_t ea; const char* nm; };
            static const Rx kRx[] = {
                {0x34D5B84u, "XuiRenderBegin"},
                {0x34D1FCCu, "XuiRenderEnd"},
                {0x34D204Cu, "XuiRenderPresent"},
            };
            for (const auto& r : kRx) {
                const char* nm = r.nm;
                auto cn = std::make_shared<std::atomic<uint32_t>>(0);
                tm.OnPcFiltered(r.ea, gem, [nm, cn](const TraceContext& c) {
                    const uint32_t i = cn->fetch_add(1);
                    if (i < 12 || (i & 0x3Fu) == 0)
                        LOG(Trace, "[GEM-RENDER] %s #%u ctx=0x%08X lr=0x%08X\n",
                            nm, i, c.regs[0], c.regs[14]);
                });
            }

            tm.OnPcFiltered(0x8821A5F8u, gem, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                const uint32_t i = n.fetch_add(1);
                if (i >= 40 && (i & 0x3Fu) != 0) return;
                const auto h0 = c.ReadVa32(c.regs[1]);
                const auto h1 = c.ReadVa32(c.regs[1] + 4);
                /* walk the guest stack for the first user-range (shared-DLL or
                   gemstone-slot) return addresses = the XUI/gemstone callers. */
                char sb[200]; int p = 0;
                for (uint32_t d = 0; d < 0x300u && p < 180; d += 4) {
                    const auto w = c.ReadVa32(c.regs[13] + d);
                    if (!w.has_value()) continue;
                    const uint32_t v = *w;
                    /* shared-DLL code region only (xuidll/coredll/zmedia/...),
                       excludes the gemstone process slot's stack+heap+code. */
                    if (v >= 0x02000000u && v < 0x0C000000u)
                        p += snprintf(sb + p, sizeof(sb) - p, "%08X ", v);
                }
                LOG(Trace, "[GEM-WFMO] #%u count=%u to=0x%08X h0=0x%08X h1=0x%08X "
                           "stk:%s\n",
                    i, c.regs[0], c.regs[3], h0.value_or(0), h1.value_or(0), sb);
            });
        });
    }
};

REGISTER_SERVICE(ZuneKeelGemstoneWedgeBisect);

}  /* namespace */

#endif  /* CERF_DEV_MODE */
