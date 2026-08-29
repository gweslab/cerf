#include "../../kernel_debug_sink.h"
#include "../../trace_manager.h"
#include "../../../core/cerf_emulator.h"
#include "../../../jit/mips/mips_cpu_state.h"
#include "bundle.h"

namespace {

/* nk.exe sub_9F41C790 is NKDbgPrintfW. It formats into a stack buffer and only then
   gates the output call on OEM global 0x80015130, which this retail ROM leaves null,
   so the kernel's exception and halt text is built and dropped. The hook fires at the
   instruction the formatting call returns to, where the finished string is readable. */
constexpr uint32_t kNkDbgPrintfFormatted = 0x9F41C7C0u;

/* addiu $sp, -0x220 ... addiu $a0, $sp, 0x1C: the formatted wide string. */
constexpr uint32_t kBufOffFromSp = 0x1Cu;

class VeloKernelDbgOutput : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kBundleCrc32, [this] {
            emu_.Get<TraceManager>().OnPc(
                kNkDbgPrintfFormatted, [this](const TraceContext& c) {
                    if (!c.mips) return;
                    const uint32_t sp = static_cast<uint32_t>(c.mips->gpr[29]);
                    emu_.Get<KernelDebugSink>().EmitWideStringAt(c, sp + kBufOffFromSp,
                                                                 "NK");
                });
        });
    }
};

}  // namespace

REGISTER_SERVICE(VeloKernelDbgOutput);
