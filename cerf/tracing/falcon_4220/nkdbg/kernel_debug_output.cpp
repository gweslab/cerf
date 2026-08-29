#include "../../kernel_debug_sink.h"
#include "../../trace_manager.h"
#include "../../../core/cerf_emulator.h"
#include "bundle.h"

namespace {

/* nk.exe OEMWriteDebugString sub_800E7770 (R0 = wide string): this OAL wires no
   writer into its output sink (0x82296020) and discards every string inside the
   function, so only a hook on the ENTRY captures the text. */
class Falcon4220KernelDebugOutput : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kFalcon4220BundleCrc32, [this] {
            emu_.Get<TraceManager>().OnPc(0x800E7770u, [this](const TraceContext& c) {
                emu_.Get<KernelDebugSink>().EmitWideStringAt(c, c.regs[0]);
            });
        });
    }
};

}  // namespace

REGISTER_SERVICE(Falcon4220KernelDebugOutput);
