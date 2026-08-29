#include "../../kernel_debug_sink.h"
#include "../../trace_manager.h"
#include "../../../core/cerf_emulator.h"
#include "bundle.h"

namespace {

/* SL4 nk.exe nulls OEMWriteDebugString (final emit is nullsub_3), so no serial
   debug text exists. 0x800835BC is the wide-string sink (R0 = formatted string)
   every debug print passes through before the dead emit. */
class SimpadSl4OemDebugPrint : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kSimpadSl4Ce4BundleCrc32, [this] {
            emu_.Get<TraceManager>().OnPc(0x800835BCu, [this](const TraceContext& c) {
                emu_.Get<KernelDebugSink>().EmitWideStringAt(c, c.regs[0]);
            });
        });
    }
};

}  // namespace

REGISTER_SERVICE(SimpadSl4OemDebugPrint);
