#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../jit/arm_mmu.h"
#include "../../jit/arm_mmu_state.h"
#include "ce7_bundle.h"
#include "ce7_process_resolver.h"

#include <cstring>
#include <string>
#include <unordered_set>

namespace {

class TraceCe7FbWriterProbe : public Service {
public:
    using Service::Service;
    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kCe7BundleCrc32, [&] {
            tm.OnRunLoopIter([poll_count = uint32_t{0},
                              last_thread = uint32_t{0xFFFFFFFFu}](
                                       const TraceContext& c) mutable {
                ++poll_count;
                if ((poll_count & 0xFFu) != 0) return;  /* every 256 iters */
                auto cur = c.ReadVa32(0xFFFFC824u);
                uint32_t v = cur.value_or(0);
                if (v != last_thread) {
                    LOG(Trace, "[sched] PCURTHD changed: 0x%08X -> 0x%08X "
                        "(poll #%u)\n", last_thread, v, poll_count);
                    last_thread = v;
                }
            });
            tm.OnPc(0xEFF7F35Cu, [](const TraceContext& c) {
                LOG(Trace, "[sched] kmode-ThreadBaseFunc "
                    "R0(entry)=0x%08X SP=0x%08X CPSR=0x%08X\n",
                    c.regs[0], c.regs[13], c.cpsr);
            });
            tm.OnPc(0x8C03B344u, [seen = std::unordered_set<uint32_t>{}](
                                       const TraceContext& c) mutable {
                const uint32_t pth = c.regs[0];
                if (seen.insert(pth).second) {
                    LOG(Trace, "[sched] MakeRun first-fire pth=0x%08X "
                        "fAtTail=%u LR=0x%08X (total unique=%zu)\n",
                        pth, c.regs[1], c.regs[14], seen.size());
                }
            });
            tm.OnPc(0x8C041700u, [](const TraceContext& c) {
                LOG(Trace, "[sched] SetupThread pprc=0x%08X lpStack=0x%08X "
                    "cbStack=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[14]);
            });
            tm.OnPc(0x8C04C364u, [](const TraceContext& c) {
                LOG(Trace, "[loader] LoadUserCoreDll R0(pprc)=0x%08X "
                    "R1=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[14]);
            });
            tm.OnPc(0x8C048AD0u, [](const TraceContext& c) {
                LOG(Trace, "[loader] LoadE32 R0=0x%08X R1=0x%08X "
                    "R2=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[14]);
            });
            tm.OnPc(0x8C049F34u, [](const TraceContext& c) {
                LOG(Trace, "[loader] LoadO32 R0=0x%08X R1=0x%08X "
                    "R2=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[14]);
            });
            tm.OnPc(0x8C0396B0u, [](const TraceContext& c) {
                LOG(Trace, "[loader] PROCLoadModule R0(pprc)=0x%08X "
                    "R1=0x%08X R2=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[14]);
            });
            tm.OnPc(0xEFE809D4u, [](const TraceContext& c) {
                LOG(Trace, "[signal] FS_SignalStarted dw=%u LR=0x%08X\n",
                    c.regs[0], c.regs[14]);
            });
            tm.OnPc(0x8C03D08Cu, [](const TraceContext& c) {
                LOG(Trace, "[susp] SCHL_SuspendSelfIfNeeded LR=0x%08X\n",
                    c.regs[14]);
            });
            tm.OnPc(0x8C04E988u, [](const TraceContext& c) {
                auto& mmu = c.emu.Get<ArmMmu>();
                uint32_t ttbr = mmu.State()->translation_table_base.word
                                & 0xFFFFC000u;
                LOG(Trace, "[crit] EXTCRITCreate ENTRY lpcs=0x%08X "
                    "ttbr0=0x%08X LR=0x%08X\n",
                    c.regs[0], ttbr, c.regs[14]);
            });
            tm.OnPc(0x8C05E39Cu, [](const TraceContext& c) {
                /* NKCreateAPISet(name[4], cMethods, apiMethods, sigs) — capture name (4 chars) + which API set ID is allocated. */
                char tag[5] = {};
                for (int i = 0; i < 4; ++i) {
                    auto b = c.ReadVa8(c.regs[0] + i);
                    tag[i] = b.has_value() ? static_cast<char>(*b) : '?';
                }
                LOG(Trace, "[apiset] NKCreateAPISet tag='%s' cMethods=%u "
                    "apiMethods=0x%08X sigs=0x%08X LR=0x%08X\n",
                    tag, c.regs[1], c.regs[2], c.regs[3], c.regs[14]);
            });
            tm.OnPc(0xEFD73DE4u, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                const uint32_t grfExStyle   = c.regs[0];
                const uint32_t pszClassName = c.regs[1];
                const uint32_t pszName      = c.regs[2];
                const uint32_t grfStyle     = c.regs[3];
                std::string cls;
                if ((pszClassName >> 16) != 0u) {
                    for (int i = 0; i < 64; ++i) {
                        auto w = c.ReadVa16(pszClassName + i * 2);
                        if (!w.has_value() || *w == 0) break;
                        cls += (*w < 0x80) ? static_cast<char>(*w) : '?';
                    }
                } else {
                    char buf[16];
                    snprintf(buf, sizeof(buf), "ATOM:0x%04X", pszClassName & 0xFFFFu);
                    cls = buf;
                }
                std::string name;
                if (pszName != 0u) {
                    for (int i = 0; i < 64; ++i) {
                        auto w = c.ReadVa16(pszName + i * 2);
                        if (!w.has_value() || *w == 0) break;
                        name += (*w < 0x80) ? static_cast<char>(*w) : '?';
                    }
                }
                const int32_t x  = static_cast<int32_t>(
                    c.ReadVa32(c.regs[13] + 0x0u).value_or(0));
                const int32_t y  = static_cast<int32_t>(
                    c.ReadVa32(c.regs[13] + 0x4u).value_or(0));
                const int32_t cx = static_cast<int32_t>(
                    c.ReadVa32(c.regs[13] + 0x8u).value_or(0));
                const int32_t cy = static_cast<int32_t>(
                    c.ReadVa32(c.regs[13] + 0xCu).value_or(0));
                const uint32_t hwndParent =
                    c.ReadVa32(c.regs[13] + 0x10u).value_or(0);
                const uint32_t ttbr0 =
                    c.emu.Get<ArmMmu>().State()->translation_table_base.word
                    & 0xFFFFC000u;
                LOG(Trace, "[wnd] CreateWindowExW_I #%u class='%s' name='%s' "
                    "grfStyle=0x%08X grfExStyle=0x%08X x=%d y=%d cx=%d cy=%d "
                    "hwndParent=0x%08X TTBR0=0x%08X LR=0x%08X\n",
                    count, cls.c_str(), name.c_str(),
                    grfStyle, grfExStyle, x, y, cx, cy,
                    hwndParent, ttbr0, c.regs[14]);
            });
            tm.OnPc(0xEFD9F4C4u, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                LOG(Trace, "[wnd] ShowWindow_I #%u hwnd=0x%08X nCmdShow=%d LR=0x%08X\n",
                    count, c.regs[0], static_cast<int32_t>(c.regs[1]), c.regs[14]);
            });
            tm.OnRunLoopIter([
                last_pcurthd = uint32_t{0},
                last_pc_per_pth = std::unordered_map<uint32_t, uint32_t>{}
            ] (const TraceContext& c) mutable {
                const uint32_t pcurthd = c.ReadVa32(0xFFFFC824u).value_or(0u);
                last_pc_per_pth[pcurthd] = c.pc;
                if (pcurthd != last_pcurthd && last_pcurthd != 0u) {
                    auto it = last_pc_per_pth.find(last_pcurthd);
                    const uint32_t prev_pc = (it != last_pc_per_pth.end()) ? it->second : 0u;
                    const uint32_t ctx_pc  = c.ReadVa32(last_pcurthd + 0xA0u).value_or(0);
                    const uint32_t ctx_lr  = c.ReadVa32(last_pcurthd + 0x9Cu).value_or(0);
                    const uint32_t ctx_sp  = c.ReadVa32(last_pcurthd + 0x98u).value_or(0);
                    const uint32_t ctx_psr = c.ReadVa32(last_pcurthd + 0x60u).value_or(0);
                    auto& mmu = c.emu.Get<ArmMmu>();
                    const uint32_t ttbr = mmu.State()->translation_table_base.word
                                        & 0xFFFFC000u;
                    LOG(Trace, "[park-track] outgoing_pTh=0x%08X last_PC=0x%08X "
                        "ctx.Pc=0x%08X ctx.Lr=0x%08X ctx.Sp=0x%08X ctx.Psr=0x%08X "
                        "incoming_pTh=0x%08X TTBR0=0x%08X\n",
                        last_pcurthd, prev_pc,
                        ctx_pc, ctx_lr, ctx_sp, ctx_psr,
                        pcurthd, ttbr);
                }
                last_pcurthd = pcurthd;
            });
            tm.OnPc(0xEFD9E200u, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count > 30 && (count % 50u) != 0u) return;
                LOG(Trace, "[wnd] SetWindowPos_I #%u hwnd=0x%08X x=%d y=%d "
                    "cx=%d cy=%d LR=0x%08X\n",
                    count, c.regs[0],
                    static_cast<int32_t>(c.regs[2]), static_cast<int32_t>(c.regs[3]),
                    static_cast<int32_t>(c.ReadVa32(c.regs[13]).value_or(0)),
                    static_cast<int32_t>(c.ReadVa32(c.regs[13] + 4).value_or(0)),
                    c.regs[14]);
            });
            tm.OnPc(0x8C02C020u, [](const TraceContext& c) {
                LOG(Trace, "[sched] MDSetupThread pTh=0x%08X lpBase(entry)=0x%08X "
                    "lpStart=0x%08X kmode=%u LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[3], c.regs[14]);
            });
            tm.OnPc(0x8C03C16Cu, [count = uint32_t{0}](
                                       const TraceContext& c) mutable {
                ++count;
                if (count <= 20 || (count % 1000) == 0) {
                    LOG(Trace, "[sched] NextThread #%u R0=0x%08X LR=0x%08X\n",
                        count, c.regs[0], c.regs[14]);
                }
            });
            auto reg_open_hook = [](const TraceContext& c, const char* src) {
                std::string name;
                for (int i = 0; i < 96; ++i) {
                    auto w = c.ReadVa16(c.regs[1] + i * 2);
                    if (!w.has_value()) break;
                    if (*w == 0) break;
                    name += (*w < 0x80) ? static_cast<char>(*w) : '?';
                }
                if (name.find("ompositor") != std::string::npos ||
                    name.find("Gwe") != std::string::npos) {
                    LOG(Trace, "[reg] %s hKey=0x%08X subkey='%s' LR=0x%08X\n",
                        src, c.regs[0], name.c_str(), c.regs[14]);
                }
            };
            /* compositor.exe user-VA hooks. ImageBase 0x10000 aliases
               with every other EXE, so each hook is filtered by FCSE
               PID via the resolver. */
            auto compositor_only =
                ce7_resolver::PidPredicateForName("compositor.exe");
            tm.OnPcFiltered(0x00011B68u, compositor_only,
                [](const TraceContext& c) {
                    LOG(Trace, "[cmp] WinMainCRTStartup LR=0x%08X SP=0x%08X\n",
                        c.regs[14], c.regs[13]);
                });
            tm.OnPcFiltered(0x00011E10u, compositor_only,
                [](const TraceContext& c) {
                    LOG(Trace, "[cmp] _security_init_cookie LR=0x%08X\n",
                        c.regs[14]);
                });
            tm.OnPcFiltered(0x00011AE8u, compositor_only,
                [](const TraceContext& c) {
                    LOG(Trace, "[cmp] WinMainCRTStartupHelper LR=0x%08X\n",
                        c.regs[14]);
                });
            tm.OnPcFiltered(0x00011DB0u, compositor_only,
                [](const TraceContext& c) {
                    LOG(Trace, "[cmp] _cinit LR=0x%08X\n", c.regs[14]);
                });
            tm.OnPcFiltered(0x00012960u, compositor_only,
                [](const TraceContext& c) {
                    LOG(Trace, "[cmp] init_singleton LR=0x%08X\n",
                        c.regs[14]);
                });
            tm.OnPcFiltered(0x00011700u, compositor_only,
                [](const TraceContext& c) {
                    LOG(Trace, "[cmp] singleton::get_lock R0=0x%08X LR=0x%08X\n",
                        c.regs[0], c.regs[14]);
                });
            tm.OnPcFiltered(0x000119F0u, compositor_only,
                [](const TraceContext& c) {
                    LOG(Trace, "[cmp] thunk_InitializeCriticalSection R0=0x%08X "
                        "LR=0x%08X\n", c.regs[0], c.regs[14]);
                    auto slot = c.ReadVa32(0x00013004u);
                    LOG(Trace, "[cmp]   __imp_InitializeCriticalSection (at "
                        "user-VA 0x13004) = 0x%08X\n",
                        slot.value_or(0xDEADBEEFu));
                });
            tm.OnPcFiltered(0x000119F8u, compositor_only,
                [](const TraceContext& c) {
                    LOG(Trace, "[cmp] thunk BX R12 about to branch to R12=0x%08X "
                        "LR=0x%08X\n", c.regs[12], c.regs[14]);
                });
            tm.OnPcFiltered(0x00011B98u, compositor_only,
                [](const TraceContext& c) {
                    LOG(Trace, "[cmp] _onexit R0=0x%08X LR=0x%08X\n",
                        c.regs[0], c.regs[14]);
                });
            tm.OnPcFiltered(0x00011728u, compositor_only,
                [](const TraceContext& c) {
                    LOG(Trace, "[cmp] post-InitCriticalSection LR=0x%08X\n",
                        c.regs[14]);
                });
            tm.OnPcFiltered(0x00012964u, compositor_only,
                [](const TraceContext& c) {
                    LOG(Trace, "[cmp] init_CompositorPlugin LR=0x%08X\n",
                        c.regs[14]);
                });
            tm.OnPcFiltered(0x00012984u, compositor_only,
                [](const TraceContext& c) {
                    LOG(Trace, "[cmp] init_CompositorApiSetTraps LR=0x%08X\n",
                        c.regs[14]);
                });
            tm.OnPcFiltered(0x00011754u, compositor_only,
                [](const TraceContext& c) {
                    LOG(Trace, "[cmp] WinMain LR=0x%08X SP=0x%08X\n",
                        c.regs[14], c.regs[13]);
                });
            tm.OnPcFiltered(0x00011580u, compositor_only,
                [](const TraceContext& c) {
                    LOG(Trace, "[cmp] LoadConfiguration LR=0x%08X SP=0x%08X\n",
                        c.regs[14], c.regs[13]);
                });
            tm.OnPcFiltered(0x000114ACu, compositor_only,
                [](const TraceContext& c) {
                    LOG(Trace, "[cmp] InitializeCompositor LR=0x%08X SP=0x%08X\n",
                        c.regs[14], c.regs[13]);
                });
            /* kernel-mode k.coredll xxx_RegOpenKeyExW — captures kernel-side reads */
            tm.OnPc(0xEFF73CE8u, [reg_open_hook](const TraceContext& c) {
                reg_open_hook(c, "kmode_RegOpenKeyExW");
            });
            tm.OnPc(0xEF0199F0u, [](const TraceContext& c) {
                /* PC just after LDR R0, [R5, #4] in DrvEnableSurface:
                   R0 = dhpdev[1] = driver primary GPE surface pointer.
                   Read primary.m_pVirtAddr at +0x04 to confirm it maps
                   to the FB at PA 0x84800000. */
                auto prim_va = c.ReadVa32(c.regs[0] + 0x04);
                LOG(Trace, "[fb] DrvEnableSurface: primary_surf=0x%08X "
                    "primary.m_pVirtAddr=0x%08X\n",
                    c.regs[0], prim_va.value_or(0xDEADBEEF));
            });
            tm.OnPc(0xEF019C8Cu, [](const TraceContext& c) {
                LOG(Trace, "[fb] DrvFillPath pso=0x%08X path=0x%08X "
                    "clip=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[14]);
            });
            tm.OnPc(0xEF01A6FCu, [](const TraceContext& c) {
                LOG(Trace, "[fb] DrvCopyBits psoTrg=0x%08X psoSrc=0x%08X "
                    "LR=0x%08X\n", c.regs[0], c.regs[1], c.regs[14]);
            });
            tm.OnPc(0xEF01B328u, [](const TraceContext& c) {
                /* SURFOBJ dhsurf @ +0x0; OMAPDDGPESurface m_pVirtAddr @ +0x04. */
                auto dst_dhsurf = c.ReadVa32(c.regs[0] + 0x0);
                uint32_t dst_va = 0;
                if (dst_dhsurf && *dst_dhsurf) {
                    auto va = c.ReadVa32(*dst_dhsurf + 0x04);
                    dst_va = va.value_or(0);
                }
                auto src_dhsurf = c.ReadVa32(c.regs[1] + 0x0);
                uint32_t src_va = 0;
                if (src_dhsurf && *src_dhsurf) {
                    auto va = c.ReadVa32(*src_dhsurf + 0x04);
                    src_va = va.value_or(0);
                }
                /* Direct PA reads: VA 0xD18F0000 = PA 0x84800000 (primary FB);
                   VA 0xD1986000 = PA 0x84896000 (compositor backbuffer). */
                auto& mem = c.emu.Get<EmulatedMemory>();
                uint32_t pri_w0 = 0xDEAD0003u, pri_w1 = 0xDEAD0003u;
                uint32_t bb_w0 = 0xDEAD0003u, bb_w1 = 0xDEAD0003u;
                if (const uint8_t* h = mem.TryTranslate(0x84800000u)) {
                    std::memcpy(&pri_w0, h, 4);
                    std::memcpy(&pri_w1, h + 4, 4);
                }
                if (const uint8_t* h = mem.TryTranslate(0x84896000u)) {
                    std::memcpy(&bb_w0, h, 4);
                    std::memcpy(&bb_w1, h + 4, 4);
                }
                LOG(Trace, "[fb] DrvAnyBlt psoTrg=0x%08X dhsurf=0x%08X dst_va=0x%08X "
                    "| psoSrc=0x%08X src_dhsurf=0x%08X src_va=0x%08X "
                    "| PA0x84800000=%08X%08X PA0x84896000=%08X%08X LR=0x%08X\n",
                    c.regs[0], dst_dhsurf.value_or(0xDEADBEEF), dst_va,
                    c.regs[1], src_dhsurf.value_or(0xDEADBEEF), src_va,
                    pri_w0, pri_w1, bb_w0, bb_w1, c.regs[14]);
            });
            tm.OnPc(0xEF025894u, [](const TraceContext& c) {
                LOG(Trace, "[fb] DrvStrokePath pso=0x%08X path=0x%08X "
                    "LR=0x%08X\n", c.regs[0], c.regs[1], c.regs[14]);
            });
            tm.OnPc(0xEF02B2C0u, [](const TraceContext& c) {
                LOG(Trace, "[fb] DrvAlphaBlend psoTrg=0x%08X psoSrc=0x%08X "
                    "LR=0x%08X\n", c.regs[0], c.regs[1], c.regs[14]);
            });
            tm.OnPc(0xEFD88C00u, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count > 50 && (count % 200u) != 0u) return;
                /* pcwnd[57] = pcwnd+0xE4 = composition flags; bit 26 (0x4000000)
                   = NeedsBackbuffer. pcwnd[7] = pcwnd+0x1C = m_hHgBackbuffer. */
                uint32_t flags = c.ReadVa32(c.regs[0] + 0xE4u).value_or(0xDEADBEEFu);
                uint32_t bb    = c.ReadVa32(c.regs[0] + 0x1Cu).value_or(0xDEADBEEFu);
                LOG(Trace, "[fb] GweHgAllocateWindowBackbufferIfNeeded(CWindow*) #%u "
                    "pcwnd=0x%08X flags=0x%08X needs=%u m_hHgBackbuffer=0x%08X LR=0x%08X\n",
                    count, c.regs[0], flags, (flags >> 26) & 1u, bb, c.regs[14]);
            });
            tm.OnPc(0xEFD88D08u, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count > 50 && (count % 200u) != 0u) return;
                LOG(Trace, "[fb] AllocateBackbuffer-SUCCESS-STR #%u "
                    "pcwnd=R8=0x%08X pSurface=R3=0x%08X (storing to pcwnd+0x1C) LR=0x%08X\n",
                    count, c.regs[8], c.regs[3], c.regs[14]);
            });
            /* DD-HAL chain bisect: SUCCESS-STR=0 + cerf HAL CreateSurface=0; v8 @0xEFDD5150 = kernel surface HRESULT. */
            tm.OnPc(0xEFDD3FB4u, [](const TraceContext& c) {
                static uint32_t n = 0;
                if (++n > 150 && (n % 50u) != 0u) return;
                uint32_t eType = c.ReadVa32(c.regs[13]).value_or(0xDEADBEEFu);
                LOG(Trace, "[fb2] AllocateSurface #%u this=0x%08X fmt=0x%08X eType=0x%08X LR=0x%08X\n",
                    n, c.regs[0], c.regs[1], eType, c.regs[14]);
            });
            tm.OnPc(0xEFDD5614u, [](const TraceContext& c) {
                static uint32_t n = 0;
                if (++n > 150 && (n % 50u) != 0u) return;
                LOG(Trace, "[fb2] CreateOffscreenSurface #%u fmt=0x%08X w=%u h=%u fInVidMem=%u LR=0x%08X\n",
                    n, c.regs[0], c.regs[1], c.regs[2], c.regs[3], c.regs[14]);
            });
            tm.OnPc(0xEFDD50B4u, [](const TraceContext& c) {
                static uint32_t n = 0;
                if (++n > 150 && (n % 50u) != 0u) return;
                uint32_t mdev = c.ReadVa32(c.regs[0] + 8u).value_or(0xDEADBEEFu);
                LOG(Trace, "[fb2] CDDSurface::Create #%u pdd=0x%08X m_Device=0x%08X pSurfDesc=0x%08X LR=0x%08X\n",
                    n, c.regs[0], mdev, c.regs[1], c.regs[14]);
            });
            tm.OnPc(0xEFDD5150u, [](const TraceContext& c) {
                static uint32_t n = 0;
                ++n;
                bool fail = (int32_t)c.regs[0] < 0;
                if (!fail && n > 150 && (n % 50u) != 0u) return;
                LOG(Trace, "[fb2] CDDSurface::Create PSL-result v8=0x%08X %s LR=0x%08X\n",
                    c.regs[0], fail ? "FAIL" : "ok", c.regs[14]);
            });
            /* CDirectDraw::Create result + g_pDirectDraw + CreateOffscreenSurface RET: chain dies before CDDSurface::Create. */
            tm.OnPc(0xEFDD55E0u, [](const TraceContext& c) {
                static uint32_t n = 0;
                if (++n > 60 && (n % 20u) != 0u) return;
                uint32_t gdd = c.ReadVa32(c.regs[5]).value_or(0xDEADBEEFu);
                LOG(Trace, "[fb3] CDirectDraw::Create result=0x%08X g_pDirectDraw=0x%08X #%u\n",
                    c.regs[0], gdd, n);
            });
            tm.OnPc(0xEFDD4124u, [](const TraceContext& c) {
                static uint32_t n = 0;
                if (++n > 60 && (n % 20u) != 0u) return;
                LOG(Trace, "[fb3] CreateOffscreenSurface RET hresult=0x%08X #%u\n", c.regs[0], n);
            });
            /* Which half of CDirectDraw::Create's early E_FAIL: WaitForAPIReady(91) not-ready vs PSL_0xF10093F8()==0. */
            tm.OnPc(0xEFDD5480u, [](const TraceContext& c) {
                static uint32_t n = 0;
                if (++n > 40 && (n % 20u) != 0u) return;
                LOG(Trace, "[fb4] WaitForAPIReady(91)=0x%08X (0=ready) #%u\n", c.regs[0], n);
            });
            tm.OnPc(0xEFDD54B0u, [](const TraceContext& c) {
                static uint32_t n = 0;
                if (++n > 40 && (n % 20u) != 0u) return;
                LOG(Trace, "[fb4] PSL_F10093F8()=0x%08X (0=fail) #%u\n", c.regs[0], n);
            });
            /* CDirectDraw::Create later returns: GetPrimaryDDrawDeviceName / device-create PSL(F4) / caps PSL(E4) — which yields 0x80004005. */
            tm.OnPc(0xEFDD54C8u, [](const TraceContext& c) {
                static uint32_t n = 0;
                if (++n > 40 && (n % 20u) != 0u) return;
                LOG(Trace, "[fb5] GetPrimaryDDrawDeviceName=0x%08X #%u\n", c.regs[0], n);
            });
            tm.OnPc(0xEFDD551Cu, [](const TraceContext& c) {
                static uint32_t n = 0;
                if (++n > 40 && (n % 20u) != 0u) return;
                LOG(Trace, "[fb5] DDrawCreateDevice-PSL(F4)=0x%08X #%u\n", c.regs[0], n);
            });
            tm.OnPc(0xEFDD5544u, [](const TraceContext& c) {
                static uint32_t n = 0;
                if (++n > 40 && (n % 20u) != 0u) return;
                LOG(Trace, "[fb5] DDrawGetCaps-PSL(E4)=0x%08X #%u\n", c.regs[0], n);
            });
            /* Capture the resolved kernel DirectDrawCreate target (R3 at the BLX) to decompile why it E_FAILs after HALInit. */
            tm.OnPc(0xEFDD5518u, [](const TraceContext& c) {
                static uint32_t n = 0;
                if (++n > 20 && (n % 20u) != 0u) return;
                LOG(Trace, "[fb6] DDrawCreate-PSL target=R3=0x%08X szDeviceName=R0=0x%08X #%u\n",
                    c.regs[3], c.regs[0], n);
            });
            tm.OnPc(0xEFD88DB0u, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count > 50 && (count % 200u) != 0u) return;
                LOG(Trace, "[fb] GweHgAllocateWindowBackbufferIfNeeded(DC*) #%u "
                    "pdc=0x%08X LR=0x%08X\n",
                    count, c.regs[0], c.regs[14]);
            });
            tm.OnPc(0xEFDD26BCu, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count > 100 && (count % 500u) != 0u) return;
                LOG(Trace, "[fb] SetNeedsBackbuffer #%u pcwnd=0x%08X fNeedBuffer=%d LR=0x%08X\n",
                    count, c.regs[0], c.regs[1], c.regs[14]);
            });
            tm.OnPc(0xEFD888F8u, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count > 100 && (count % 500u) != 0u) return;
                LOG(Trace, "[fb] GweHgOnWindowPosChange #%u pcwnd=0x%08X ir=0x%08X LR=0x%08X\n",
                    count, c.regs[0], c.regs[1], c.regs[14]);
            });
            tm.OnPc(0xEFDD1BA4u, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count > 50 && (count % 200u) != 0u) return;
                LOG(Trace, "[fb] NotifyOnShowWindow #%u this=0x%08X pcwnd=0x%08X fVisible=%d LR=0x%08X\n",
                    count, c.regs[0], c.regs[1], c.regs[2], c.regs[14]);
            });
            tm.OnPc(0xEFDD1CE4u, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count > 50 && (count % 200u) != 0u) return;
                LOG(Trace, "[fb] NotifyOnSetWindowCompFlags #%u this=0x%08X pcwnd=0x%08X dwFlags=0x%08X LR=0x%08X\n",
                    count, c.regs[0], c.regs[1], c.regs[2], c.regs[14]);
            });
            tm.OnPc(0xEFDD39ECu, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count > 100 && (count % 500u) != 0u) return;
                LOG(Trace, "[fb] ManageWindowBackbuffers #%u this=0x%08X pmwbData=0x%08X "
                    "pcwnd=0x%08X ir=0x%08X LR=0x%08X\n",
                    count, c.regs[0], c.regs[1], c.regs[2], c.regs[3], c.regs[14]);
            });
            tm.OnPc(0xEFDD2740u, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count > 50 && (count % 200u) != 0u) return;
                uint32_t bb = c.ReadVa32(c.regs[0] + 0x1Cu).value_or(0xDEADBEEFu);
                LOG(Trace, "[fb] ClearWindowBackbuffer #%u pcwnd=0x%08X "
                    "m_hHgBackbuffer(before)=0x%08X fSendDetachNotify=%u LR=0x%08X\n",
                    count, c.regs[0], bb, c.regs[1], c.regs[14]);
            });
            tm.OnPc(0xEFDD20B8u, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count > 20 && (count % 200u) != 0u) return;
                LOG(Trace, "[fb] DumpStateOfWindowHierarchy #%u this=0x%08X pcwndRef=0x%08X LR=0x%08X\n",
                    count, c.regs[0], c.regs[1], c.regs[14]);
            });
            tm.OnPc(0xEFDD4B18u, [](const TraceContext& c) {
                LOG(Trace, "[fb] gwes::ExternalApiSet::RegisterCompositor entry "
                    "hwndCompositor=0x%08X hNotifyQueue=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[14]);
            });
            tm.OnPc(0xEFDD22C8u, [](const TraceContext& c) {
                LOG(Trace, "[fb] gwes::CCompositorCore::RegisterCompositor_I entry "
                    "this=0x%08X pcwndWrap=0x%08X hNotifyQueue=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[14]);
            });
            tm.OnPc(0xEFDD1950u, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count > 50 && (count % 200u) != 0u) return;
                /* PostCompositorNotify(this, eNotify, pPayload, cbPayload). */
                auto hqueue = c.ReadVa32(c.regs[0]).value_or(0xDEADBEEFu);
                LOG(Trace, "[fb] PostCompositorNotify #%u this=0x%08X "
                    "eNotify=%u pPayload=0x%08X cbPayload=%u m_hNotifyQueue=0x%08X LR=0x%08X\n",
                    count, c.regs[0], c.regs[1], c.regs[2], c.regs[3],
                    hqueue, c.regs[14]);
            });
            tm.OnPc(0xEFE205C0u, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                if (count > 50 && (count % 200u) != 0u) return;
                /* On entry, R0 = this (CWindowWrapper*). Read this->m_pcwnd
                   at +4 and this->m_pcwnd->m_hHgBackbuffer at +0x1C. */
                auto pcwnd = c.ReadVa32(c.regs[0] + 4u);
                uint32_t bb = 0xDEADBEEFu;
                if (pcwnd) bb = c.ReadVa32(*pcwnd + 0x1Cu).value_or(0xDEADBEEFu);
                LOG(Trace, "[fb] HasBackbuffer entry #%u this=0x%08X pcwnd=0x%08X "
                    "m_hHgBackbuffer=0x%08X LR=0x%08X\n",
                    count, c.regs[0], pcwnd.value_or(0u), bb, c.regs[14]);
            });
            tm.OnPc(0xEFE205DCu, [](const TraceContext& c) {
                /* MOVNE R0,#1 → HasBackbuffer returns 1 (m_hHgBackbuffer != 0). */
                static uint32_t count = 0;
                ++count;
                if (count > 50 && (count % 200u) != 0u) return;
                LOG(Trace, "[fb] HasBackbuffer → 1 (TRUE) #%u R4(this)=0x%08X R3(m_hHgBackbuffer)=0x%08X LR=0x%08X\n",
                    count, c.regs[4], c.regs[3], c.regs[14]);
            });
            tm.OnPc(0xEFE205E0u, [](const TraceContext& c) {
                /* MOVEQ R0,#0 → HasBackbuffer returns 0 (m_hHgBackbuffer == 0). */
                static uint32_t count = 0;
                ++count;
                if (count > 20 && (count % 200u) != 0u) return;
                LOG(Trace, "[fb] HasBackbuffer → 0 (FALSE) #%u R4(this)=0x%08X LR=0x%08X\n",
                    count, c.regs[4], c.regs[14]);
            });
            tm.OnPc(0xEFDD1D9Cu, [](const TraceContext& c) {
                /* On entry to NotifyOnSetWindowSurf, read pcwnd->m_hwnd
                   at +0x78 and dump it alongside pcwnd. */
                uint32_t mhwnd = c.ReadVa32(c.regs[1] + 0x78u).value_or(0xDEAD0001u);
                LOG(Trace, "[fb] NotifyOnSetWindowSurf this=0x%08X pcwnd=0x%08X "
                    "pcwnd->m_hwnd=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], mhwnd, c.regs[14]);
            });
            tm.OnPc(0xEFDD13A4u, [](const TraceContext& c) {
                LOG(Trace, "[fb] IsValidWindowToSend → return 1 (VALID) "
                    "R4=0x%08X (cmp result) R0=0x%08X\n",
                    c.regs[4], c.regs[0]);
            });
            tm.OnPc(0xEFDD13B0u, [](const TraceContext& c) {
                LOG(Trace, "[fb] IsValidWindowToSend → return 0 (BLOCKED) "
                    "R4=0x%08X R0=0x%08X\n",
                    c.regs[4], c.regs[0]);
            });
            tm.OnPc(0xEF01E72Cu, [](const TraceContext& c) {
                LOG(Trace, "[fb] EmulatedBlt_Bilinear this=0x%08X "
                    "parms=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[14]);
            });
            tm.OnPc(0xEF01EF8Cu, [](const TraceContext& c) {
                LOG(Trace, "[fb] EmulatedBlt_Halftone this=0x%08X "
                    "parms=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[14]);
            });
            tm.OnPc(0xEF01F7E0u, [](const TraceContext& c) {
                LOG(Trace, "[fb] EmulatedBltRotate_Internal this=0x%08X "
                    "parms=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[14]);
            });
        });
    }
};

REGISTER_SERVICE(TraceCe7FbWriterProbe);

}  /* namespace */
