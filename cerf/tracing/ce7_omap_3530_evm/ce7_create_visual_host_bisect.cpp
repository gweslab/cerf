#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "../../jit/arm_mmu_state.h"
#include "ce7_bundle.h"

#include <cstdint>

#if CERF_DEV_MODE

namespace {

/* FingerKB.dll KeyBoard::CreateVisualHost — split into post-BL probes
   for each major XAML init call. The last one that fires + the next
   one that doesn't names the broken XAML primitive. */
constexpr uint32_t kPcCvhEntry             = 0x407C598Cu;
constexpr uint32_t kPcCvhPostXamlInit      = 0x407C59C4u;
constexpr uint32_t kPcCvhPostGetXRApp      = 0x407C59F4u;
constexpr uint32_t kPcCvhPostAddResMod     = 0x407C5A10u;
constexpr uint32_t kPcCvhPostCreateHostXml = 0x407C5AE4u;
constexpr uint32_t kPcCvhPreEvntModify     = 0x407C5B98u;
constexpr uint32_t kPcCvhExit              = 0x407C5BA4u;

/* KeyBoard::ThreadProc — outer thread entry. */
constexpr uint32_t kPcKbThreadProc         = 0x407C5BB4u;

constexpr uint32_t kVaPCurThd = 0xFFFFC824u;

class TraceCe7CreateVisualHostBisect : public Service {
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
                            "[cvh] %s #%u pTh=0x%08X R0=0x%08X LR=0x%08X\n",
                            tag, n, pcurthd, c.regs[0], c.regs[14]);
                    });
            };

            hook(kPcKbThreadProc,        "KeyBoard::ThreadProc");
            hook(kPcCvhEntry,            "CreateVisualHost ENTRY");
            hook(kPcCvhPostXamlInit,     "post-XamlRuntimeInitialize");
            hook(kPcCvhPostGetXRApp,     "post-GetXRApplicationInstance");
            hook(kPcCvhPostAddResMod,    "post-AddResourceModule");
            hook(kPcCvhPostCreateHostXml,"post-CreateHostFromXaml");
            hook(kPcCvhPreEvntModify,    "pre-EventModify(m_hEventReady)");
            hook(kPcCvhExit,             "CreateVisualHost EXIT");
        });
    }
};

REGISTER_SERVICE(TraceCe7CreateVisualHostBisect);

}  /* namespace */

#endif  /* CERF_DEV_MODE */
