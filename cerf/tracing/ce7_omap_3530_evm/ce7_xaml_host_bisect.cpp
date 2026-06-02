#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "../../jit/arm_mmu_state.h"
#include "ce7_bundle.h"

#include <cstdint>

#if CERF_DEV_MODE

namespace {

/* xamlruntime.dll @ ImageBase 0x40130000.
   XRApplication::CreateHostFromXaml @ 0x4015B81C.
   Each post-BL site captures R0 = return value of the preceding call.
   The last one to fire with R0 < 0 names the failing sub-call. */
constexpr uint32_t kPcXrEntry                = 0x4015B81Cu;
constexpr uint32_t kPcXrPostLoadCore         = 0x4015B8B8u;
constexpr uint32_t kPcXrPostXamlContainerCreate = 0x4015B8CCu;
constexpr uint32_t kPcXrPostLoadXaml         = 0x4015B940u;
constexpr uint32_t kPcXrPostCheckParser      = 0x4015B964u;
constexpr uint32_t kPcXrPostCreateHostInt    = 0x4015B984u;
constexpr uint32_t kPcXrFinalMovR0R4         = 0x4015B9FCu;

constexpr uint32_t kVaPCurThd = 0xFFFFC824u;

class TraceCe7XamlHostBisect : public Service {
public:
    using Service::Service;
    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kCe7BundleCrc32, [&] {
            auto user_proc_only = [](const TraceContext& c) -> bool {
                return (c.emu.Get<ArmMmu>()
                            .State()
                            ->translation_table_base.word
                        & 0xFFFFC000u) != 0u;
            };

            auto hook = [&tm, &user_proc_only]
                        (uint32_t pc, const char* tag) {
                tm.OnPcFiltered(pc, user_proc_only,
                    [tag](const TraceContext& c) {
                        static uint32_t n = 0;
                        ++n;
                        const uint32_t pcurthd =
                            c.ReadVa32(kVaPCurThd).value_or(0u);
                        LOG(Trace,
                            "[xhb] %s #%u pTh=0x%08X R0=0x%08X R4=0x%08X LR=0x%08X\n",
                            tag, n, pcurthd,
                            c.regs[0], c.regs[4], c.regs[14]);
                    });
            };

            hook(kPcXrEntry,                "CreateHostFromXaml ENTRY");
            hook(kPcXrPostLoadCore,         "post-LoadNewSilverlightCore");
            hook(kPcXrPostXamlContainerCreate, "post-XamlContainer::Create");
            hook(kPcXrPostLoadXaml,         "post-pCore->LoadXaml");
            hook(kPcXrPostCheckParser,      "post-CheckParserError");
            hook(kPcXrPostCreateHostInt,    "post-CreateHostInternal");
            hook(kPcXrFinalMovR0R4,         "FINAL R4->R0");
        });
    }
};

REGISTER_SERVICE(TraceCe7XamlHostBisect);

}  /* namespace */

#endif  /* CERF_DEV_MODE */
