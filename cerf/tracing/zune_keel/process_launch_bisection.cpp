#include "../trace_manager.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "bundle.h"
#include "zune_process_resolver.h"

#include <atomic>
#include <cstdint>

#if CERF_DEV_MODE

namespace {

/* Addresses from zune_keel nk.exe / devmgr.dll; each hook's meaning is at its
   site. Process creation -> TTBR0 mapping is owned by zune_process_resolver;
   device.exe probes filter through PidPredicateForName("device.exe"). */
class ZuneKeelProcessLaunchBisection : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kZuneKeelBundleCrc32, [&] {
            const TracePredicate device_exe =
                zune_resolver::PidPredicateForName("device.exe");

            /* devmgr VAs are ImageBase (0x3F7xxxx), NOT the XIP load addr
               0x8841xxxx — the latter never fires. StartDeviceManager early-init
               milestones (post-BL return PCs). Last one that fires = the wedged
               call. The real BuiltIn activation is sub_3F7550C @ 0x3F72264. */
            struct Milestone { uint32_t pc; const char* label; };
            static const Milestone kInit[] = {
                {0x3F720D4u, "StartDeviceManager ENTRY"},
                {0x3F72100u, "after sub_3F71CA0"},
                {0x3F72144u, "after API-event create (sub_3F78384)"},
                {0x3F721A0u, "after sub_3F76750"},
                {0x3F721CCu, "after sub_3F758D4"},
                {0x3F721E0u, "after DevMgrApiSetReady create"},
                {0x3F72204u, "after LoadLibrary(ceddk.dll)"},
                {0x3F72218u, "after GetProcAddr(CalibrateStallCounter)"},
                {0x3F72234u, "after CalibrateStallCounter()"},
                {0x3F72248u, "after sub_3F77E00"},
                {0x3F7225Cu, "after BootPhase1 create"},
                {0x3F72264u, "BL sub_3F7550C (BuiltIn ACTIVATION)"},
                {0x3F72268u, "BuiltIn activation RETURNED"},
                {0x3F72300u, "while(1) service-loop wait"},
            };
            for (const auto& m : kInit) {
                tm.OnPcFiltered(m.pc, device_exe,
                    [label = m.label](const TraceContext& c) {
                        LOG(Trace, "[DEVMGR-INIT] %s lr=0x%08X\n",
                            label, c.regs[14]);
                    });
            }

            /* device.exe USER-range PC sampler (pc < 0x80000000 to skip the
               kernel idle thread running in device.exe's FCSE context). */
            tm.OnRunLoopIter([device_exe](const TraceContext& c) {
                if (c.pc >= 0x80000000u || !device_exe(c)) return;
                static std::atomic<uint32_t> n{0};
                const uint32_t i = n.fetch_add(1);
                if (i < 16 || (i & 0xFFu) == 0) {
                    LOG(Trace, "[DEVPC] device.exe pc=0x%08X lr=0x%08X sp=0x%08X\n",
                        c.pc, c.regs[14], c.regs[13]);
                }
            });

            /* Wedge-loop body (device.exe spins here ~forever, no MMIO). Dump
               regs + an instruction-byte window for IDA byte-signature module
               ID, and the loop's memory condition. */
            tm.OnPcFiltered(0x0306B5F0u, device_exe, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                const uint32_t i = n.fetch_add(1);
                if (i >= 6 && (i & 0x1FFu) != 0) return;
                char b[120]; int p = 0;
                for (uint32_t d = 0; d <= 0x1Cu; d += 4) {  /* polled kernel obj @ r1 */
                    auto w = c.ReadVa32(c.regs[1] + d);
                    p += snprintf(b + p, sizeof(b) - p, "%08X ",
                                  w.has_value() ? *w : 0xDEADBEEFu);
                }
                /* CE object name often hangs off a pointer field; try +0x18
                   and +0x0 as candidate name pointers, read as wide string. */
                char nm[48]; int q = 0;
                for (uint32_t fld : {0x18u, 0x00u}) {
                    auto p2 = c.ReadVa32(c.regs[1] + fld);
                    q += snprintf(nm + q, sizeof(nm) - q, "[+%X->", fld);
                    if (p2) for (int k = 0; k < 16 && q < (int)sizeof(nm) - 4; ++k) {
                        auto w = c.ReadVa16(*p2 + k * 2);
                        if (!w.has_value() || *w == 0) break;
                        nm[q++] = (*w >= 0x20 && *w < 0x7F) ? (char)*w : '.';
                    }
                    q += snprintf(nm + q, sizeof(nm) - q, "] ");
                }
                LOG(Trace, "[WEDGE] #%u objAddr=%08X lr=%08X | [obj+0..1C]: %s | "
                           "name?: %s\n",
                    i, c.regs[1], c.regs[14], b, nm);
            });

            /* The USB host-controller bring-up poll: pc=0x03E924E8 reads
               USBSTS (PA 0x43F88144) ~40/sec forever. Capture its register
               context + the live USBSTS value to see the exact spin condition. */
            tm.OnPcFiltered(0x03E924E8u, device_exe, [](const TraceContext& c) {
                static std::atomic<uint32_t> n{0};
                const uint32_t i = n.fetch_add(1);
                if (i >= 8 && (i & 0x3Fu) != 0) return;
                auto sts = c.ReadVa32(0x43F88144u);
                LOG(Trace, "[USBPOLL] #%u r0=%08X r1=%08X r2=%08X r3=%08X r4=%08X "
                           "r5=%08X r6=%08X lr=%08X usbsts=%08X\n",
                    i, c.regs[0], c.regs[1], c.regs[2], c.regs[3], c.regs[4],
                    c.regs[5], c.regs[6], c.regs[14],
                    sts.has_value() ? *sts : 0xDEADBEEFu);
            });

            /* device.exe infinite waits (sub_8821A5F8 = kernel
               WaitForMultipleObjects; R3==INFINITE). Filtered to device.exe so
               only its blocking waits show — the steady one is its wedge. */
            tm.OnPcFiltered(0x8821A5F8u, device_exe, [](const TraceContext& c) {
                if (c.regs[3] != 0xFFFFFFFFu) return;
                static std::atomic<uint32_t> n{0};
                const uint32_t i = n.fetch_add(1);
                auto h = c.ReadVa32(c.regs[1]);
                if (i < 16 || (i & 0x3Fu) == 0) {
                    LOG(Trace, "[WAIT-INF] #%u count=%u hnd0=0x%08X lr=0x%08X\n",
                        i, c.regs[0], h.has_value() ? *h : 0xFFFFFFFFu,
                        c.regs[14]);
                }
            });

            /* Kernel startup (process-agnostic): filesys.exe create result +
               the SYSTEM/FSReady handshake. */
            tm.OnPc(0x88222F9Cu, [](const TraceContext& c) {
                LOG(Trace, "[PROC-FILESYS] CreateProcess(filesys.exe) result="
                           "0x%08X (%s)\n",
                    c.regs[0], c.regs[0] ? "CREATED" : "FAILED");
            });
            tm.OnPc(0x88222FC0u, [](const TraceContext& /*c*/) {
                LOG(Trace, "[PROC-FSREADY] kernel about to "
                           "WaitForSingleObject(SYSTEM/FSReady, INFINITE)\n");
            });
            tm.OnPc(0x88222FC4u, [](const TraceContext& c) {
                LOG(Trace, "[PROC-FSREADY] FSReady wait RETURNED; filesys "
                           "signaled ready. r0=0x%08X\n", c.regs[0]);
            });
        });
    }
};

}  /* namespace */

REGISTER_SERVICE(ZuneKeelProcessLaunchBisection);

#endif  /* CERF_DEV_MODE */
