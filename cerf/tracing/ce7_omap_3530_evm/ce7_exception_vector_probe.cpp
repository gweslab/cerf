#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../jit/arm_cpu.h"
#include "../../jit/arm_mmu.h"
#include "../../jit/arm_mmu_state.h"
#include "ce7_bundle.h"

#include <cstring>
#include <string>

namespace {

class TraceCe7ExceptionVectorProbe : public Service {
public:
    using Service::Service;
    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kCe7BundleCrc32, [&] {
            /* Bisection: hit OEMInit / OALIntrInit / OALTimerInit /
               OEMIdle to determine where boot stops in the chain. */
            tm.OnPc(0x8C00DE38u, [](const TraceContext& c) {
                LOG(Trace, "[hit] OEMInit entry LR=0x%08X\n", c.regs[14]);
            });
            tm.OnPc(0x8C00DC70u, [](const TraceContext& c) {
                LOG(Trace, "[hit] OALTimerInit entry R0=%u LR=0x%08X\n",
                    c.regs[0], c.regs[14]);
            });
            tm.OnPc(0x8C035068u, [](const TraceContext& c) {
                LOG(Trace, "[hit] KernelStart entry R0=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[14]);
            });
            tm.OnPc(0x8C04B668u, [](const TraceContext& c) {
                std::string name;
                for (int i = 0; i < 96; ++i) {
                    auto w = c.ReadVa16(c.regs[2] + i * 2);
                    if (!w.has_value()) break;
                    if (*w == 0) break;
                    name += (*w < 0x80) ? static_cast<char>(*w) : '?';
                }
                LOG(Trace, "[hit] InitModule entry pprc=0x%08X pMod=0x%08X "
                    "lpszFileName='%s' LR=0x%08X\n",
                    c.regs[0], c.regs[1], name.c_str(), c.regs[14]);
            });
            /* InitModule return — fires on every successful return.
               Pair against InitModule entry to find which module's
               init entered but never returned. */
            tm.OnPc(0x8C04BE90u, [](const TraceContext& c) {
                LOG(Trace, "[hit] InitModule return R0=0x%08X\n", c.regs[0]);
            });
            tm.OnPc(0x8C04B528u, [](const TraceContext& c) {
                LOG(Trace, "[hit] CreateNewProc entry R0=0x%08X R1=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[14]);
            });
            tm.OnPc(0x8C051784u, [](const TraceContext& c) {
                LOG(Trace, "[hit] RunApps entry R0=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[14]);
            });
            /* RunApps internal hooks - prove if/where it stalls */
            tm.OnPc(0x8C05178Cu, [](const TraceContext& c) {
                LOG(Trace, "[hit] RunApps after-CELOG R0=0x%08X\n", c.regs[0]);
            });
            tm.OnPc(0x8C0517A0u, [](const TraceContext& c) {
                LOG(Trace, "[hit] RunApps body R0=0x%08X (NULL->exit)\n", c.regs[0]);
            });
            tm.OnPc(0x8C0550F8u, [](const TraceContext& c) {
                (void)c;
                LOG(Trace, "[hit] CELOG_LaunchingFilesys entry\n");
            });
            /* DM_ActivateDeviceEx — first arg is lpszDevKey wchar_t*
               (e.g. L"Drivers\\BuiltIn\\SPI1"). Logs which device key
               the device manager is activating; if no matching exit
               trace fires, that's the device whose Init is stuck. */
            tm.OnPc(0xEFD3274Cu, [](const TraceContext& c) {
                wchar_t key[64] = {};
                for (int i = 0; i < 63; ++i) {
                    auto v = c.ReadVa16(c.regs[0] + i * 2);
                    if (!v || *v == 0) break;
                    key[i] = static_cast<wchar_t>(*v);
                }
                LOG(Trace, "[hit] DM_ActivateDeviceEx entry R0=0x%08X key='%ls' LR=0x%08X\n",
                    c.regs[0], key, c.regs[14]);
            });
            /* Spin-loop probe: the boot stalls cycling through these
               5 PCs at 0xEFE6xxxx (~83 instructions / 5 blocks).
               Fires once, captures LR + 8 stack words to identify the
               caller. */
            /* ROM_GetFileAttributesW entry — count invocations + log
               the filename being searched. R1 is the wchar_t* path. */
            tm.OnPc(0xEFE611B4u, [count = uint32_t{0}](const TraceContext& c) mutable {
                ++count;
                if (count <= 5 || (count % 100) == 0) {
                    wchar_t name[64] = {};
                    for (int i = 0; i < 63; ++i) {
                        auto v = c.ReadVa16(c.regs[1] + i * 2);
                        if (!v || *v == 0) break;
                        name[i] = static_cast<wchar_t>(*v);
                    }
                    LOG(Trace, "[romgfa] count=%u R1=0x%08X name='%ls' LR=0x%08X\n",
                        count, c.regs[1], name, c.regs[14]);
                }
            });
            /* Inner-loop iteration probe — after the BL to GetRomFileInfo
               returns. Captures R5/R6 (the iterator state) on each hit. */
            tm.OnPc(0xEFE611FCu, [count = uint32_t{0}](const TraceContext& c) mutable {
                ++count;
                if (count <= 5 || (count % 100) == 0) {
                    LOG(Trace, "[romgfa_iter] count=%u R4=0x%08X R5=0x%08X R6=0x%08X R8=0x%08X\n",
                        count, c.regs[4], c.regs[5], c.regs[6], c.regs[8]);
                }
            });
            tm.OnPc(0xEFE6128Cu, [fired = false](const TraceContext& c) mutable {
                if (fired) return;
                fired = true;
                LOG(Trace, "[spin] PC=0x%08X R0=0x%08X R1=0x%08X R2=0x%08X "
                           "R3=0x%08X R4=0x%08X R5=0x%08X R6=0x%08X R7=0x%08X "
                           "LR=0x%08X SP=0x%08X CPSR=0x%08X\n",
                    c.pc, c.regs[0], c.regs[1], c.regs[2], c.regs[3],
                    c.regs[4], c.regs[5], c.regs[6], c.regs[7],
                    c.regs[14], c.regs[13], c.cpsr);
                /* Walk page tables for PC + LR to find their PAs.
                   Uses TTBR1 since bit[31]=1 with TTBCR.N=1. */
                {
                    auto& mmu = c.emu.Get<ArmMmu>();
                    const auto& m = *mmu.State();
                    auto& mem = c.emu.Get<EmulatedMemory>();
                    const uint32_t ttbr1 = m.ttbr1 & 0xFFFFC000u;
                    for (uint32_t which = 0; which < 2; ++which) {
                        const uint32_t va = (which == 0) ? c.pc : c.regs[14];
                        const char* tag = (which == 0) ? "pc" : "lr";
                        const uint32_t l1_pa = ttbr1 | ((va >> 20) << 2);
                        uint32_t l1 = 0;
                        if (uint8_t* h = mem.TryTranslate(l1_pa))
                            std::memcpy(&l1, h, 4);
                        uint32_t pa = 0;
                        if ((l1 & 3u) == 1u) {
                            const uint32_t l2_pa = (l1 & 0xFFFFFC00u) |
                                                   (((va >> 12) & 0xFFu) << 2);
                            uint32_t l2 = 0;
                            if (uint8_t* h2 = mem.TryTranslate(l2_pa))
                                std::memcpy(&l2, h2, 4);
                            if ((l2 & 2u) != 0u) {
                                pa = (l2 & 0xFFFFF000u) | (va & 0xFFFu);
                            }
                            LOG(Trace, "[spin] %s_walk va=0x%08X L1=0x%08X "
                                       "L2@0x%08X=0x%08X pa=0x%08X\n",
                                tag, va, l1, l2_pa, l2, pa);
                        } else if ((l1 & 3u) == 2u) {
                            pa = (l1 & 0xFFF00000u) | (va & 0xFFFFFu);
                            LOG(Trace, "[spin] %s_walk va=0x%08X L1=0x%08X "
                                       "(section) pa=0x%08X\n", tag, va, l1, pa);
                        } else {
                            LOG(Trace, "[spin] %s_walk va=0x%08X L1=0x%08X "
                                       "(unmapped)\n", tag, va, l1);
                        }
                    }
                }
                /* Dump 24 instructions starting from PC. */
                for (uint32_t i = 0; i < 24; ++i) {
                    auto v = c.ReadVa32(c.pc + i * 4u);
                    LOG(Trace, "[spin] insn @0x%08X = 0x%08X\n",
                        c.pc + i * 4u, v.value_or(0xDEADBEEFu));
                }
                /* Dump literal pool 0xEFE61330..0xEFE6135C — function uses
                   PC-relative LDRs to load constants from there. */
                for (uint32_t i = 0; i < 12; ++i) {
                    const uint32_t a = 0xEFE61330u + i * 4u;
                    auto v = c.ReadVa32(a);
                    LOG(Trace, "[spin] lit @0x%08X = 0x%08X\n",
                        a, v.value_or(0xDEADBEEFu));
                }
                /* Dump first BL target 0xEFE62280..0xEFE622A0. */
                for (uint32_t i = 0; i < 8; ++i) {
                    const uint32_t a = 0xEFE62280u + i * 4u;
                    auto v = c.ReadVa32(a);
                    LOG(Trace, "[spin] bl0 @0x%08X = 0x%08X\n",
                        a, v.value_or(0xDEADBEEFu));
                }
                /* Dump caller context @LR-32..LR. */
                for (uint32_t i = 0; i < 8; ++i) {
                    const uint32_t a = c.regs[14] - 32u + i * 4u;
                    auto v = c.ReadVa32(a);
                    LOG(Trace, "[spin] caller @0x%08X = 0x%08X\n",
                        a, v.value_or(0xDEADBEEFu));
                }
            });
            /* DM_ActivateDeviceEx exit (last insn before return). */
            tm.OnPc(0xEFD32794u, [](const TraceContext& c) {
                LOG(Trace, "[hit] DM_ActivateDeviceEx exit R0=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[14]);
            });
            /* NKLoadLibraryEx — first arg is the filename wchar_t*. */
            tm.OnPc(0x8C04BFB0u, [](const TraceContext& c) {
                /* Read first 16 wchars from R0. */
                wchar_t name[16] = {};
                for (int i = 0; i < 15; ++i) {
                    auto v = c.ReadVa16(c.regs[0] + i * 2);
                    if (!v || *v == 0) break;
                    name[i] = static_cast<wchar_t>(*v);
                }
                LOG(Trace, "[hit] NKLoadLibraryEx R0=0x%08X R1=0x%08X LR=0x%08X name='%ls'\n",
                    c.regs[0], c.regs[1], c.regs[14], name);
            });
            tm.OnPc(0x8C03A730u, [](const TraceContext& c) {
                LOG(Trace, "[hit] PROCInit entry R0=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[14]);
            });
            tm.OnPc(0x8C0503F0u, [](const TraceContext& c) {
                static uint32_t count = 0;
                if (++count <= 50) {
                    LOG(Trace, "[hit] ThreadSleep #%u R0=0x%08X LR=0x%08X\n",
                        count, c.regs[0], c.regs[14]);
                }
            });
            tm.OnPc(0x8C05046Cu, [](const TraceContext& c) {
                static uint32_t count = 0;
                if (++count <= 50) {
                    LOG(Trace, "[hit] NKSleep #%u R0=%u LR=0x%08X\n",
                        count, c.regs[0], c.regs[14]);
                }
            });
            tm.OnPc(0xEFE801B8u, [](const TraceContext& c) {
                uint32_t guid[4] = {};
                for (int i = 0; i < 4; ++i) {
                    auto v = c.ReadVa32(c.regs[0] + i * 4);
                    guid[i] = v ? *v : 0;
                }
                LOG(Trace, "[hit] WaitForFileSystem pGUID=0x%08X "
                    "GUID={0x%08X,0x%08X,0x%08X,0x%08X} Timeout=%u\n",
                    c.regs[0], guid[0], guid[1], guid[2], guid[3], c.regs[3]);
            });
            tm.OnPc(0xEFEB7EA4u, [](const TraceContext& c) {
                static uint32_t count = 0;
                if (++count <= 30) {
                    LOG(Trace, "[hit] filesys Sleep_0 #%u R0=%u LR=0x%08X\n",
                        count, c.regs[0], c.regs[14]);
                }
            });
            tm.OnPc(0xEFCF93E0u, [](const TraceContext& c) {
                static uint32_t count = 0;
                if (++count <= 30) {
                    LOG(Trace, "[hit] pm.dll Sleep_0 #%u R0=%u LR=0x%08X\n",
                        count, c.regs[0], c.regs[14]);
                }
            });
            tm.OnPc(0x8C050B30u, [](const TraceContext& c) {
                static uint32_t count = 0;
                ++count;
                /* Sample first 100 calls + every 5000th after. Caller's
                   user-mode LR is on xxx_WaitForSingleObject's frame at
                   SP+0x14 (saved in PUSH {R4,R5,R12,LR} per its prologue). */
                const bool sample = (count <= 100) || (count % 5000) == 0;
                if (!sample) return;
                uint32_t h0 = 0xDEADBEEFu;
                if (auto v = c.ReadVa32(c.regs[1])) h0 = *v;
                uint32_t caller_lr = 0xDEADBEEFu;
                if (auto v = c.ReadVa32(c.regs[13] + 0x14u)) caller_lr = *v;
                LOG(Trace, "[hit] NKWaitForMultipleObjects #%u "
                    "cObjs=%u pH=0x%08X h0=0x%08X fAll=%u Timeout=%u "
                    "LR=0x%08X caller_LR=0x%08X\n",
                    count, c.regs[0], c.regs[1], h0, c.regs[2], c.regs[3],
                    c.regs[14], caller_lr);
            });
            tm.OnPc(0xEFE80C10u, [](const TraceContext& c) {
                LOG(Trace, "[hit] filesys RunApps (user-VA) R0=0x%X LR=0x%08X\n",
                    c.regs[0], c.regs[14]);
            });
            tm.OnPc(0x8C28FC10u, [](const TraceContext& c) {
                LOG(Trace, "[hit] filesys RunApps (kernel-VA) R0=0x%X LR=0x%08X\n",
                    c.regs[0], c.regs[14]);
            });
            tm.OnPc(0xEFF6D264u, [](const TraceContext& c) {
                LOG(Trace, "[hit] xxx_SignalStarted dwLaunchCode=0x%X LR=0x%08X\n",
                    c.regs[0], c.regs[14]);
            });
            tm.OnPc(0xEFD3236Cu, [](const TraceContext& c) {
                LOG(Trace, "[hit] StartDeviceManager entry R0=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[14]);
            });
            tm.OnPc(0xEFD32204u, [](const TraceContext& c) {
                LOG(Trace, "[hit] SignalStartedUsingReg entry LR=0x%08X\n",
                    c.regs[14]);
            });
            tm.OnPc(0xEFD4171Cu, [](const TraceContext& c) {
                LOG(Trace, "[hit] devmgr SignalStarted_0 R0=0x%X LR=0x%08X\n",
                    c.regs[0], c.regs[14]);
            });

            tm.OnPc(0xEFD3A7E0u, [](const TraceContext& c) {
                LOG(Trace, "[hit] DeviceContent::EnableDevice this=0x%08X "
                    "dwWaitTicks=0x%X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[14]);
            });
            tm.OnPc(0xEFD3E330u, [](const TraceContext& c) {
                LOG(Trace, "[hit] CReflector::InitEx this=0x%08X dwInfo=0x%08X "
                    "lpvParam=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[14]);
            });
            tm.OnPc(0xEFD3C938u, [](const TraceContext& c) {
                LOG(Trace, "[hit] CReflector::SendIoControl this=0x%08X "
                    "code=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[14]);
            });
            tm.OnPc(0xEFD3D75Cu, [](const TraceContext& c) {
                LOG(Trace, "[hit] CreateReflector R0=0x%08X R1=0x%08X "
                    "R2=0x%08X R3=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[3], c.regs[14]);
            });

            tm.OnPc(0xEFD36704u, [](const TraceContext& c) {
                LOG(Trace, "[hit] DM_REL_UDriverProcIoControl ioctl=0x%08X "
                    "in=0x%08X inSize=%u LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[14]);
            });
            tm.OnPc(0xEFF69DE0u, [](const TraceContext& c) {
                static uint32_t spin_count = 0;
                static uint32_t total = 0;
                ++total;
                uint32_t caller = 0xDEADBEEFu;
                if (auto v = c.ReadVa32(c.regs[13] + 0x14u)) caller = *v;
                const bool is_spinner = (caller == 0xEF171D94u);
                if (is_spinner) ++spin_count;
                /* Log every spin-caller exit (capped per-iteration of 10k by
                   sample), plus the first 20 of any caller for early-boot
                   context. */
                const bool sample =
                    (is_spinner && (spin_count <= 20 || (spin_count % 5000) == 0))
                    || total <= 20;
                if (!sample) return;
                uint32_t handle = 0xDEADBEEFu;
                if (auto v = c.ReadVa32(c.regs[13] + 0x18u)) handle = *v;
                LOG(Trace, "[hit] xxx_WaitForSingleObject ret total=#%u spin=#%u "
                    "handle=0x%08X result=0x%08X caller=0x%08X\n",
                    total, spin_count, handle, c.regs[0], caller);
                static bool dumped = false;
                if (is_spinner && !dumped) {
                    dumped = true;
                    LOG(Trace, "[spinner-id] dumping 64 bytes at 0xEF171D60 "
                        "(spinner-base = 0xEF170000):\n");
                    for (uint32_t off = 0; off < 64; off += 16) {
                        uint32_t w0 = 0xDEADBEEFu, w1 = 0xDEADBEEFu;
                        uint32_t w2 = 0xDEADBEEFu, w3 = 0xDEADBEEFu;
                        if (auto v = c.ReadVa32(0xEF171D60u + off + 0))  w0 = *v;
                        if (auto v = c.ReadVa32(0xEF171D60u + off + 4))  w1 = *v;
                        if (auto v = c.ReadVa32(0xEF171D60u + off + 8))  w2 = *v;
                        if (auto v = c.ReadVa32(0xEF171D60u + off + 12)) w3 = *v;
                        LOG(Trace, "[spinner-id] 0x%08X: %08X %08X %08X %08X\n",
                            0xEF171D60u + off, w0, w1, w2, w3);
                    }
                    uint32_t mzhdr = 0xDEADBEEFu;
                    if (auto v = c.ReadVa32(0xEF170000u)) mzhdr = *v;
                    LOG(Trace, "[spinner-id] @0xEF170000 first 4 bytes: 0x%08X\n",
                        mzhdr);
                }
            });
            tm.OnPc(0x8C0517B8u, [](const TraceContext& c) {
                const uint32_t pc = c.regs[3];
                /* Walk TTBR0 manually to find PA, then read PA bytes. */
                auto& mmu = c.emu.Get<ArmMmu>();
                auto& mem = c.emu.Get<EmulatedMemory>();
                const auto& m = *mmu.State();
                const uint32_t ttbr0 = m.translation_table_base.word & 0xFFFFC000u;
                const uint32_t l1_pa = ttbr0 | ((pc >> 20) << 2);
                uint32_t insn[2] = {0xDEADBEEFu, 0xDEADBEEFu};
                uint32_t pa = 0;
                uint8_t* l1h = mem.TryTranslate(l1_pa);
                if (l1h) {
                    uint32_t l1; std::memcpy(&l1, l1h, 4);
                    uint32_t t = l1 & 3u;
                    if (t == 2u) {
                        pa = (l1 & 0xFFF00000u) | (pc & 0x000FFFFFu);
                    } else if (t == 1u) {
                        const uint32_t l2_pa = (l1 & 0xFFFFFC00u) |
                                               (((pc >> 12) & 0xFFu) << 2);
                        uint8_t* l2h = mem.TryTranslate(l2_pa);
                        uint32_t l2 = 0xDEADBEEFu;
                        if (l2h) {
                            std::memcpy(&l2, l2h, 4);
                            if ((l2 & 3u) == 2u || (l2 & 3u) == 3u) {
                                pa = (l2 & 0xFFFFF000u) | (pc & 0xFFFu);
                            } else if ((l2 & 3u) == 1u) {
                                pa = (l2 & 0xFFFF0000u) | (pc & 0xFFFFu);
                            }
                        }
                        LOG(Trace, "    L2 walk: l2_pa=0x%08X l2_val=0x%08X "
                            "l2h=%p type=%u pa=0x%08X\n",
                            l2_pa, l2, (void*)l2h, l2 & 3u, pa);
                    }
                    if (pa) {
                        uint8_t* h = mem.TryTranslate(pa);
                        if (h) std::memcpy(insn, h, 8);
                    }
                }
                /* Also try a known-good PA for sanity: 0x80000000 (bank 0 start). */
                uint8_t* sanity = mem.TryTranslate(0x80000000u);
                LOG(Trace, "[hit] kernel RunApps BLX R3=0x%08X "
                    "R0=0x%08X R1=0x%08X TTBR0=0x%08X l1_pa=0x%08X "
                    "L1=0x%08X l2_pa=0x847E89C0 pa=0x%08X "
                    "code@pa=0x%08X 0x%08X sanity_bank0=%p\n",
                    pc, c.regs[0], c.regs[1],
                    m.translation_table_base.word, l1_pa,
                    l1h ? *(uint32_t*)l1h : 0xDEADBEEFu, pa,
                    insn[0], insn[1], (void*)sanity);
            });
            /* Instruction immediately after BLX — if BLX called something
               that returned, PC reaches here. */
            tm.OnPc(0x8C0517BCu, [](const TraceContext& c) {
                LOG(Trace, "[hit] kernel RunApps post-BLX R0=0x%08X LR=0x%08X R15=0x%08X\n",
                    c.regs[0], c.regs[14], c.regs[15]);
            });
            /* Poll R15 on every iter, log when it ever equals 0xEFE70000. */
            tm.OnRunLoopIter([](const TraceContext& c) {
                static uint32_t fires = 0;
                if (c.regs[15] == 0xEFE70000u && fires < 5) {
                    LOG(Trace, "[iter R15=0xEFE70000] CPSR=0x%08X\n", c.cpsr);
                    ++fires;
                }
            });
            tm.OnPc(0xEFE70000u, [](const TraceContext& c) {
                LOG(Trace, "[hit] EXEC at 0xEFE70000 R0=0x%08X R1=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[14]);
            });
            tm.OnPc(0xFFFF000Cu, [](const TraceContext& c) {
                auto& mmu = c.emu.Get<ArmMmu>();
                const auto& m = *mmu.State();
                LOG(Trace, "[hit] PREFETCH-ABORT FSR=0x%08X FAR=0x%08X LR_abt=0x%08X\n",
                    m.fault_status.word, m.fault_address, c.regs[14]);
            });
            /* filesys.dll FileSysMain entry — this is the real entry called
               by kernel.dll RunApps (R0=FileSysMain in BLX). */
            tm.OnPc(0xEFE81208u, [](const TraceContext& c) {
                LOG(Trace, "[hit] FileSysMain entry R0=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[14]);
            });
            tm.OnPc(0x8C042BFCu, [](const TraceContext& c) {
                LOG(Trace, "[hit] CreateKernelThread Start=0x%08X Parm=0x%08X "
                    "prio=0x%X flags=0x%X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[3], c.regs[14]);
            });
            /* filesys WaitForAPIReady_0 (API 84). */
            tm.OnPc(0xEFEB7EF4u, [](const TraceContext& c) {
                LOG(Trace, "[hit] WaitForAPIReady_0 R0=%u R1=%u LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[14]);
            });
            tm.OnPc(0xEFE80314u, [](const TraceContext& c) {
                LOG(Trace, "[hit] DoGeneralInit R0=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[14]);
            });
            /* BL to RunApps inside FileSysMain. */
            tm.OnPc(0xEFE81568u, [](const TraceContext& c) {
                LOG(Trace, "[hit] FileSysMain pre-BL-RunApps R0=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[14]);
            });
            /* Bisect DoGeneralInit. */
            tm.OnPc(0xEFE828D4u, [](const TraceContext& c) {
                LOG(Trace, "[hit] FSMapMemory R0=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[14]);
            });
            tm.OnPc(0xEFEBDCECu, [](const TraceContext& c) {
                LOG(Trace, "[hit] STOREMGR_Initialize R0=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[14]);
            });
            tm.OnPc(0xEFE8C6D8u, [](const TraceContext& c) {
                LOG(Trace, "[hit] prgInitRegistry R0=%u (which) R1=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[14]);
            });
            tm.OnPc(0xEFE9638Cu, [](const TraceContext& c) {
                LOG(Trace, "[hit] prgInitHiveRegistry R0=%u R1=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[14]);
            });
            tm.OnPc(0xEFE95AC0u, [](const TraceContext& c) {
                LOG(Trace, "[hit] MountSystemHive R0=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[14]);
            });
            /* PC right after BL MountSystemHive in prgInitHiveRegistry —
               fires iff MountSystemHive actually returned. */
            tm.OnPc(0xEFE963C0u, [](const TraceContext& c) {
                LOG(Trace, "[hit] MountSystemHive returned (back in prgInitHiveRegistry)\n");
                (void)c;
            });
            /* RegMountHive entry — fires on every mount attempt
               (boot ROM hive, boot RAM hive, system ROM hive, system
               RAM hive). Surfaces R0=filename pointer + R1=guid. */
            tm.OnPc(0xEFEAFD7Cu, [](const TraceContext& c) {
                LOG(Trace, "[hit] RegMountHive R0=0x%08X R1=0x%08X R2=0x%08X R3=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[3], c.regs[14]);
            });
            /* prgNotifyBootFSReady — called once after BOOTFS is
               advertised, before mounting the system hive. */
            tm.OnPc(0xEFE949F8u, [](const TraceContext& c) {
                LOG(Trace, "[hit] prgNotifyBootFSReady R0=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[14]);
            });
            tm.OnPc(0xEFBC3EC8u, [](const TraceContext& c) {
                LOG(Trace, "[hit] PD_OpenStore hDisk=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[14]);
            });
            /* PD_OpenStore Exit_0 label at 0xEFBC4114; MOV R0, R5
               at +0x0C carries the return value, so capture R5 at
               the label itself before LocalFree clobbers R0. */
            tm.OnPc(0xEFBC4114u, [](const TraceContext& c) {
                LOG(Trace, "[hit] PD_OpenStore Exit_0 R5=%u (ret) "
                           "LR=0x%08X\n",
                    c.regs[5], c.regs[14]);
            });
            tm.OnPc(0xEFBC5A0Cu, [](const TraceContext& c) {
                uint16_t bps   = 0;
                uint16_t bsig  = 0;
                uint8_t  jmp   = 0;
                auto vj = c.ReadVa8 (c.regs[0] + 0);
                auto vb = c.ReadVa16(c.regs[0] + 11);
                auto vs = c.ReadVa16(c.regs[0] + 510);
                if (vj) jmp  = *vj;
                if (vb) bps  = *vb;
                if (vs) bsig = *vs;
                LOG(Trace, "[hit] DetectFatBootSector buf=0x%08X "
                           "SectorSize=%u jmp=0x%02X BytsPerSec=%u "
                           "sig=0x%04X LR=0x%08X\n",
                    c.regs[0], c.regs[1], jmp, bps, bsig, c.regs[14]);
            });
            /* mspart!GetDOSPartitions return-value site
               (return path at 0xEFBC2590 = label exit_getdospartitions). */
            tm.OnPc(0xEFBC2590u, [](const TraceContext& c) {
                LOG(Trace, "[hit] GetDOSPartitions exit R4=%u (ret) "
                           "LR=0x%08X\n",
                    c.regs[4], c.regs[14]);
            });
            tm.OnPc(0xEFBC2184u, [](const TraceContext& c) {
                const uint32_t pSector = c.regs[2];
                const uint32_t state   = c.regs[0];
                /* DriverState +0x28 = diskInfo.di_total_sectors per
                   IDA decomp + 0xEFBC2230 LDR R3,[R7,#0x28]. */
                auto dits = c.ReadVa32(state + 0x28);
                auto b454 = c.ReadVa8(pSector + 454);
                auto b458 = c.ReadVa8(pSector + 458);
                LOG(Trace, "[hit] GetDOSPartitions entry state=0x%08X "
                           "di_total_sectors=%u pSector=0x%08X "
                           "PE0.Start[0]=0x%02X PE0.Total[0]=0x%02X\n",
                    state, dits.value_or(0xDEADBEEFu), pSector,
                    b454.value_or(0xCC), b458.value_or(0xCC));
            });
            /* nand!Fal::ReadFromMedia entry — fires for every FAL read. */
            tm.OnPc(0xEF1F305Cu, [](const TraceContext& c) {
                LOG(Trace, "[hit] Fal::ReadFromMedia this=0x%08X "
                           "pSG=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[14]);
            });
            tm.OnPc(0xEF1F3C4Cu, [](const TraceContext& c) {
                LOG(Trace, "[hit] FileSysFal::BuildupMappingInfo "
                           "this=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[14]);
            });
            tm.OnPc(0xEF1F55DCu, [](const TraceContext& c) {
                LOG(Trace, "[hit] MappingTable::MapLogicalSector "
                           "this=0x%08X logical=%u physical=%u LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[14]);
            });
            tm.OnPc(0xEF1F53F0u, [](const TraceContext& c) {
                LOG(Trace, "[hit] MappingTable::GetPhysicalSectorAddr "
                           "this=0x%08X logical=%u LR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[14]);
            });
            tm.OnPc(0xEF1F4540u, [](const TraceContext& c) {
                LOG(Trace, "[hit] FMD_ReadSector phys=%u pBuf=0x%08X "
                           "pSI=0x%08X n=%u\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[3]);
            });
            /* CELOG_FSMsg(wchar_t* msg) — surfaces every CELog
               filesys breadcrumb so we can see exactly which
               MountSystemHive milestone is reached. */
            tm.OnPc(0xEFE7E848u, [](const TraceContext& c) {
                wchar_t msg[64] = {};
                for (int i = 0; i < 63; ++i) {
                    auto v = c.ReadVa16(c.regs[0] + i * 2);
                    if (!v || *v == 0) break;
                    msg[i] = static_cast<wchar_t>(*v);
                }
                LOG(Trace, "[hit] CELOG_FSMsg '%ls'\n", msg);
            });
            tm.OnPc(0xEFD38218u, [](const TraceContext& c) {
                LOG(Trace, "[hit] DevloadInit R0=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[14]);
            });
            /* InitDevices / ActivateDeviceEx — driver chain entry. */
            tm.OnPc(0xEFD38054u, [](const TraceContext& c) {
                wchar_t name[32] = {};
                for (int i = 0; i < 31; ++i) {
                    auto v = c.ReadVa16(c.regs[0] + i * 2);
                    if (!v || *v == 0) break;
                    name[i] = static_cast<wchar_t>(*v);
                }
                LOG(Trace, "[hit] InitDevices BusName='%ls' LR=0x%08X\n",
                    name, c.regs[14]);
            });
            tm.OnPc(0xEFD3B5ECu, [](const TraceContext& c) {
                wchar_t path[64] = {};
                for (int i = 0; i < 63; ++i) {
                    auto v = c.ReadVa16(c.regs[0] + i * 2);
                    if (!v || *v == 0) break;
                    path[i] = static_cast<wchar_t>(*v);
                }
                LOG(Trace, "[hit] I_ActivateDeviceEx path='%ls' LR=0x%08X\n",
                    path, c.regs[14]);
            });
            tm.OnPc(0xEFE81120u, [](const TraceContext& c) {
                wchar_t name[64] = {};
                for (int i = 0; i < 63; ++i) {
                    auto v = c.ReadVa16(c.regs[0] + i * 2);
                    if (!v || *v == 0) break;
                    name[i] = static_cast<wchar_t>(*v);
                }
                LOG(Trace, "[hit] filesys CreateProcessW user-VA name='%ls'\n", name);
            });
            tm.OnPc(0x8C290120u, [](const TraceContext& c) {
                wchar_t name[64] = {};
                for (int i = 0; i < 63; ++i) {
                    auto v = c.ReadVa16(c.regs[0] + i * 2);
                    if (!v || *v == 0) break;
                    name[i] = static_cast<wchar_t>(*v);
                }
                LOG(Trace, "[hit] filesys CreateProcessW kernel-VA name='%ls'\n", name);
            });
            tm.OnPc(0x8C00D5E0u, [](const TraceContext& c) {
                static uint32_t calls = 0;
                if (++calls % 1000 == 1) {
                    LOG(Trace, "[hit] OEMIdle call #%u LR=0x%08X\n",
                        calls, c.regs[14]);
                }
            });

            tm.OnPc(0x8C05785Cu, [](const TraceContext& c) {
                LOG(Trace,
                    "[NKTicksToSystemTime entry] R0=0x%08X R1=0x%08X "
                    "R2=0x%08X R3=0x%08X LR=0x%08X SP=0x%08X mode=0x%X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[3],
                    c.regs[14], c.regs[13], c.cpsr & 0x1Fu);
            });

            /* Hook the faulting STRH at PC=0x8C0579D8.
               At that PC: R2=lpst, R3=value to store. */
            tm.OnPc(0x8C0579D8u, [](const TraceContext& c) {
                LOG(Trace,
                    "[STRH-fault site] R2(lpst)=0x%08X R3(val)=0x%08X "
                    "LR=0x%08X SP=0x%08X mode=0x%X\n",
                    c.regs[2], c.regs[3], c.regs[14],
                    c.regs[13], c.cpsr & 0x1Fu);
            });

            /* Hook the UND vector entry. LR_und = faulting_pc + 4
               (ARM) or + 2 (Thumb). Dump 16 bytes at faulting PC
               via TTBR0 walk so we see what insn the kernel really
               executed (vs what IDA sees in the kernel.dll image). */
            tm.OnPc(0xFFFF0004u, [](const TraceContext& c) {
                const uint32_t fpc  = c.regs[14] - 4u;
                auto& mmu = c.emu.Get<ArmMmu>();
                auto& mem = c.emu.Get<EmulatedMemory>();
                const auto& m = *mmu.State();
                const uint32_t ttbr0 = m.translation_table_base.word & 0xFFFFC000u;
                const uint32_t l1_pa = ttbr0 | ((fpc >> 20) << 2);
                uint32_t l1 = 0xDEADBEEFu, l2 = 0xDEADBEEFu;
                uint32_t insn = 0xDEADBEEFu;
                uint8_t* l1h = mem.TryTranslate(l1_pa);
                uint32_t pa = 0;
                bool ok = false;
                if (l1h) {
                    std::memcpy(&l1, l1h, 4);
                    uint32_t type = l1 & 3u;
                    if (type == 2u) {
                        pa = (l1 & 0xFFF00000u) | (fpc & 0x000FFFFFu);
                        ok = true;
                    } else if (type == 1u) {
                        const uint32_t l2_pa = (l1 & 0xFFFFFC00u) |
                                               (((fpc >> 12) & 0xFFu) << 2);
                        uint8_t* l2h = mem.TryTranslate(l2_pa);
                        if (l2h) {
                            std::memcpy(&l2, l2h, 4);
                            uint32_t lt = l2 & 3u;
                            if (lt == 2u || lt == 3u) {
                                pa = (l2 & 0xFFFFF000u) | (fpc & 0xFFFu);
                                ok = true;
                            }
                        }
                    }
                }
                if (ok) {
                    uint8_t* h = mem.TryTranslate(pa);
                    if (h) std::memcpy(&insn, h, 4);
                }
                LOG(Trace,
                    "[und-vector] fpc=0x%08X insn@fpc=0x%08X "
                    "L1=0x%08X L2=0x%08X pa=0x%08X CPSR=0x%08X\n",
                    fpc, insn, l1, l2, pa, c.cpsr);
            });

            /* Hook k.coredll memcpy entry — log only when dst is in
               the 0xCE9xxxxx region that's been re-faulting. R14 at
               entry = caller's return PC (memcpy is leaf, no LR push). */
            tm.OnPc(0xEFFA4400u, [last_caller = uint32_t{0xDEADBEEFu}]
                                 (const TraceContext& c) mutable {
                if ((c.regs[0] & 0xFFF00000u) != 0xCE900000u) return;
                if (c.regs[14] == last_caller) return;
                last_caller = c.regs[14];
                LOG(Trace, "[memcpy-cap] dst=0x%08X src=0x%08X n=0x%X "
                           "caller_LR=0x%08X CPSR=0x%08X\n",
                    c.regs[0], c.regs[1], c.regs[2], c.regs[14], c.cpsr);
            });

            tm.OnRunLoopIter([last = uint32_t{0xDEADBEEFu}]
                             (const TraceContext& c) mutable {
                auto& mmu = c.emu.Get<ArmMmu>();
                auto& m = *mmu.State();
                uint32_t dacr = m.domain_access_control;
                if (dacr == last) return;
                last = dacr;
                LOG(Trace, "[dacr-change] DACR=0x%08X (dom0=%u dom1=%u "
                           "dom2=%u dom3=%u)\n",
                    dacr, dacr & 3u, (dacr >> 2) & 3u,
                    (dacr >> 4) & 3u, (dacr >> 6) & 3u);
            });

            /* Hook the data-abort vector entry. */
            tm.OnPc(0xFFFF0010u, [last_far = uint32_t{0xDEADBEEFu},
                                  last_fsr = uint32_t{0xDEADBEEFu}]
                                 (const TraceContext& c) mutable {
                auto& mmu = c.emu.Get<ArmMmu>();
                const auto& m = *mmu.State();
                LOG(Trace,
                    "[abort-vector] FSR=0x%08X FAR=0x%08X TTBR0=0x%08X "
                    "LR_abt=0x%08X SP=0x%08X CPSR=0x%08X pid=0x%08X "
                    "CTXIDR=0x%08X\n",
                    m.fault_status.word, m.fault_address,
                    m.translation_table_base.word,
                    c.regs[14], c.regs[13], c.cpsr, m.process_id,
                    m.contextidr);

                /* Walk PTE once per unique (FAR, FSR) — a fault that
                   transitions Translation→Permission on the same FAR
                   re-walks so we can see what the kernel just wrote. */
                if (m.fault_address == last_far &&
                    m.fault_status.word == last_fsr) return;
                last_far = m.fault_address;
                last_fsr = m.fault_status.word;

                /* Dump SVC-banked R13/R14 — leaf-call memcpy didn't
                   push LR, so R14_svc = caller's return PC. */
                auto& cpu = c.emu.Get<ArmCpu>();
                auto* cs = cpu.State();
                LOG(Trace, "[abort-svc-bank] R13_svc=0x%08X "
                           "R14_svc=0x%08X SPSR_svc=0x%08X\n",
                    cs->gprs_svc[0], cs->gprs_svc[1], cs->spsr_svc);

                auto& mem = c.emu.Get<EmulatedMemory>();
                const uint32_t far_va = m.fault_address;
                const uint32_t l1_base = m.translation_table_base.word
                                       & 0xFFFFC000u;
                const uint32_t l1_idx  = far_va >> 20;
                const uint32_t l1_ent_pa = l1_base + l1_idx * 4u;

                uint32_t l1 = 0xDEADBEEFu;
                if (uint8_t* h = mem.TryTranslate(l1_ent_pa))
                    std::memcpy(&l1, h, 4);

                uint32_t l2 = 0xDEADBEEFu;
                uint32_t l2_ent_pa = 0;
                uint32_t pa = 0;
                bool resolved = false;
                const uint32_t l1_type = l1 & 0x3u;
                if (l1_type == 2u) {  /* Section */
                    pa = (l1 & 0xFFF00000u) | (far_va & 0x000FFFFFu);
                    resolved = true;
                } else if (l1_type == 1u) {  /* Coarse → L2 */
                    const uint32_t l2_base = l1 & 0xFFFFFC00u;
                    const uint32_t l2_idx  = (far_va >> 12) & 0xFFu;
                    l2_ent_pa = l2_base + l2_idx * 4u;
                    if (uint8_t* h = mem.TryTranslate(l2_ent_pa))
                        std::memcpy(&l2, h, 4);
                    const uint32_t l2_type = l2 & 0x3u;
                    if (l2_type == 2u || l2_type == 3u) {
                        pa = (l2 & 0xFFFFF000u) | (far_va & 0xFFFu);
                        resolved = true;
                    }
                }
                uint32_t ap = 0xFFu;
                if ((l2 & 0x2u) != 0u) {
                    ap = ((l2 >> 4) & 3u) | (((l2 >> 9) & 1u) << 2);
                }

                const uint32_t faulting_pc = c.regs[14] - 8u;
                uint32_t faulting_insn = 0xDEADBEEFu;
                {
                    const uint32_t l1i = faulting_pc >> 20;
                    const uint32_t l1ep = l1_base + l1i * 4u;
                    uint32_t l1v = 0;
                    if (uint8_t* h = mem.TryTranslate(l1ep))
                        std::memcpy(&l1v, h, 4);
                    const uint32_t ty = l1v & 0x3u;
                    uint32_t pc_pa = 0;
                    if (ty == 2u) {
                        pc_pa = (l1v & 0xFFF00000u) |
                                (faulting_pc & 0x000FFFFFu);
                    } else if (ty == 1u) {
                        const uint32_t l2b = l1v & 0xFFFFFC00u;
                        const uint32_t l2i = (faulting_pc >> 12) & 0xFFu;
                        uint32_t l2v = 0;
                        if (uint8_t* h2 = mem.TryTranslate(l2b + l2i * 4u))
                            std::memcpy(&l2v, h2, 4);
                        if ((l2v & 0x2u) != 0u) {
                            pc_pa = (l2v & 0xFFFFF000u) |
                                    (faulting_pc & 0xFFFu);
                        }
                    }
                    if (pc_pa) {
                        if (uint8_t* h = mem.TryTranslate(pc_pa))
                            std::memcpy(&faulting_insn, h, 4);
                    }
                    LOG(Trace, "[abort-faulting-insn] PC=0x%08X "
                               "PA=0x%08X insn=0x%08X\n",
                        faulting_pc, pc_pa, faulting_insn);
                }
                const uint32_t wnr = (m.fault_status.word >> 11) & 1u;
                LOG(Trace,
                    "[abort-pte-walk] FAR=0x%08X L1@0x%08X=0x%08X "
                    "L2@0x%08X=0x%08X resolved_pa=0x%08X (%s) "
                    "AP=0x%X WnR=%u xn=%u nG=%u\n",
                    far_va, l1_ent_pa, l1, l2_ent_pa, l2,
                    pa, resolved ? "ok" : "FAIL",
                    ap, wnr, (l2 >> 0) & 1u, (l2 >> 11) & 1u);
            });

            /* Watch every change to KData.pVMPrc — read BOTH via TLB
               (ReadVa32) AND via PA-direct walk (Section + Coarse-L2).
               Dump L1/L2 PTE words so we can see what the kernel
               actually mapped at this VA. */
            tm.OnRunLoopIter([last_tlb  = uint32_t{0xDEADBEEFu},
                              last_pa   = uint32_t{0xDEADBEEFu},
                              last_l1   = uint32_t{0xDEADBEEFu},
                              last_l2   = uint32_t{0xDEADBEEFu}]
                             (const TraceContext& c) mutable {
                constexpr uint32_t kVa = 0xFFFFC81Cu;
                auto& mmu = c.emu.Get<ArmMmu>();
                auto& mem = c.emu.Get<EmulatedMemory>();
                auto v_tlb = c.ReadVa32(kVa);
                const auto& m = *mmu.State();
                const uint32_t ttbr0_base = m.translation_table_base.word & 0xFFFFC000u;
                const uint32_t l1_pa = ttbr0_base | ((kVa >> 20) << 2);
                uint32_t v_pa = 0xDEADBEEFu;
                uint32_t l1_val = 0xDEADBEEFu;
                uint32_t l2_val = 0xDEADBEEFu;
                uint8_t* l1_host = mem.TryTranslate(l1_pa);
                if (l1_host) {
                    std::memcpy(&l1_val, l1_host, 4);
                    const uint32_t type = l1_val & 3u;
                    uint32_t pa = 0;
                    bool has_pa = false;
                    if (type == 2u) {
                        /* Section 1MB. */
                        pa = (l1_val & 0xFFF00000u) | (kVa & 0x000FFFFFu);
                        has_pa = true;
                    } else if (type == 1u) {
                        /* Coarse — fetch L2 entry. */
                        const uint32_t l2_pa = (l1_val & 0xFFFFFC00u) |
                                               (((kVa >> 12) & 0xFFu) << 2);
                        uint8_t* l2_host = mem.TryTranslate(l2_pa);
                        if (l2_host) {
                            std::memcpy(&l2_val, l2_host, 4);
                            const uint32_t l2_type = l2_val & 3u;
                            if (l2_type == 2u || l2_type == 3u) {
                                /* Small page 4KB (v6+ XN=type3). */
                                pa = (l2_val & 0xFFFFF000u) | (kVa & 0xFFFu);
                                has_pa = true;
                            } else if (l2_type == 1u) {
                                /* Large page 64KB. */
                                pa = (l2_val & 0xFFFF0000u) | (kVa & 0xFFFFu);
                                has_pa = true;
                            }
                        }
                    }
                    if (has_pa) {
                        uint8_t* h = mem.TryTranslate(pa);
                        if (h) std::memcpy(&v_pa, h, 4);
                    }
                }
                const uint32_t tlb_v = v_tlb ? *v_tlb : 0xDEADBEEFu;
                if (tlb_v != last_tlb || v_pa != last_pa ||
                    l1_val != last_l1 || l2_val != last_l2) {
                    LOG(Trace,
                        "[pVMPrc] tlb=0x%08X pa=0x%08X L1=0x%08X L2=0x%08X "
                        "TTBR0=0x%08X SCTLR.M=%u pid=0x%08X "
                        "(pc=0x%08X mode=0x%X)\n",
                        tlb_v, v_pa, l1_val, l2_val,
                        m.translation_table_base.word,
                        m.control_register.bits.m, m.process_id,
                        c.pc, c.cpsr & 0x1Fu);
                    last_tlb = tlb_v;
                    last_pa  = v_pa;
                    last_l1  = l1_val;
                    last_l2  = l2_val;
                }
            });
        });
    }
};

REGISTER_SERVICE(TraceCe7ExceptionVectorProbe);

}  /* namespace */
