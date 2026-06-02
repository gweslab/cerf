#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "ce7_bundle.h"

namespace {

class TraceCe7ExplorerAliveProbe : public Service {
public:
    using Service::Service;
    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kCe7BundleCrc32, [&] {
            /* Explorer.exe ROM loadVA=0x8EAFE000, PE ImageBase=0x10000.
               Hook entry points at BOTH user-mode VA (PE) and kernel-
               cached VA (ROM XIP) — whichever the kernel uses, one
               will fire. */
            tm.OnPc(0x8EB016F4u, [](const TraceContext& c) {
                LOG(Trace, "[expl] WinMainCRTStartup (rom-VA) LR=0x%08X\n",
                    c.regs[14]);
            });
            tm.OnPc(0x8EB021F0u, [](const TraceContext& c) {
                LOG(Trace, "[expl] WinMain (rom-VA) R0(hInst)=0x%08X "
                    "R2(cmd)=0x%08X LR=0x%08X\n",
                    c.regs[0], c.regs[2], c.regs[14]);
            });
            /* EXTLoadLibraryEx — user-mode SVC wrapper for LoadLibrary.
               Catches every LoadLibrary call from user-mode processes
               that NKLoadLibraryEx (kernel-internal entry) misses. */
            tm.OnPc(0x8C04CB6Cu, [](const TraceContext& c) {
                wchar_t name[32] = {};
                for (int i = 0; i < 31; ++i) {
                    auto v = c.ReadVa16(c.regs[0] + i * 2);
                    if (!v || *v == 0) break;
                    name[i] = static_cast<wchar_t>(*v);
                }
                static uint32_t count = 0;
                if (++count <= 200) {
                    LOG(Trace, "[expl] EXTLoadLibraryEx #%u name='%ls' "
                        "flags=0x%08X LR=0x%08X\n",
                        count, name, c.regs[1], c.regs[14]);
                }
            });
        });
    }
};

REGISTER_SERVICE(TraceCe7ExplorerAliveProbe);

}  /* namespace */
