#include "../trace_manager.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "ce7_bundle.h"

#include <cstdint>

#if CERF_DEV_MODE

namespace {

/* At each GetElementByName<T> return PC (start+0x34) the prolog's
   PUSH {R0-R3} then PUSH {R12,LR} leaves SP+12=pName, SP+16=pDO. */
constexpr uint32_t kPcKbGetElementsEntry         = 0x407C3914u;
constexpr uint32_t kPcGetElementByNameBtnRet     = 0x407C334Cu;
constexpr uint32_t kPcGetElementByNameGridRet    = 0x407C3384u;
constexpr uint32_t kPcGetElementByNameBorderRet  = 0x407C33BCu;
constexpr uint32_t kPcGetElementByNameTbRet      = 0x407C33F4u;

static void HookElementReturn(TraceManager& tm, uint32_t pc, const char* T) {
    tm.OnPc(pc, [T](const TraceContext& c) {
        const uint32_t sp        = c.regs[13];
        const uint32_t pName     = c.ReadVa32(sp + 12).value_or(0);
        const uint32_t pDO       = c.ReadVa32(sp + 16).value_or(0);
        const uint32_t pInterface =
            pDO ? c.ReadVa32(pDO).value_or(0xDEADBEEFu) : 0u;
        const int32_t  hr        = static_cast<int32_t>(c.regs[0]);

        wchar_t name[64] = {};
        if (pName) {
            for (int i = 0; i < 63; ++i) {
                auto v = c.ReadVa16(pName + i * 2);
                if (!v || *v == 0) break;
                name[i] = static_cast<wchar_t>(*v);
            }
        }

        LOG(Trace, "[fkb-xaml] GetElementByName<%s> name='%ls' hr=0x%08X "
                   "pDO=0x%08X *pDO=0x%08X\n",
            T, name, hr, pDO, pInterface);
    });
}

class TraceCe7FingerKbXamlProbe : public Service {
public:
    using Service::Service;
    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kCe7BundleCrc32, [&] {
            tm.OnPc(kPcKbGetElementsEntry, [](const TraceContext& c) {
                LOG(Trace, "[fkb-xaml] === KeyBoard::GetElements ENTRY "
                           "this=0x%08X m_pRoot.m_pInterface=0x%08X ===\n",
                    c.regs[0],
                    c.ReadVa32(c.regs[0] + 0x58).value_or(0xDEADBEEFu));
            });

            HookElementReturn(tm, kPcGetElementByNameBtnRet,    "IXRButton");
            HookElementReturn(tm, kPcGetElementByNameGridRet,   "IXRGrid");
            HookElementReturn(tm, kPcGetElementByNameBorderRet, "IXRBorder");
            HookElementReturn(tm, kPcGetElementByNameTbRet,     "IXRTextBlock");
        });
    }
};

REGISTER_SERVICE(TraceCe7FingerKbXamlProbe);

}  /* namespace */

#endif  /* CERF_DEV_MODE */
