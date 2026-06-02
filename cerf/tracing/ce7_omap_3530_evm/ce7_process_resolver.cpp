#include "ce7_process_resolver.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "../../jit/arm_mmu_state.h"
#include "ce7_bundle.h"

#include <mutex>
#include <string>
#include <unordered_map>

#if CERF_DEV_MODE

namespace {

std::mutex                                                g_mu;
std::unordered_map<std::string, uint32_t>                 g_name_to_ttbr0;
std::unordered_map<std::string, uint32_t>                 g_name_to_entry;
/* Names captured from NKCreateProcess in order; consumed by
   MDSwitchToUserCode in spawn-order. Multiple in-flight names is
   handled by a FIFO instead of a single g_pending_name slot. */
std::vector<std::string>                                  g_pending_names;

uint32_t CurrentTtbr0(const TraceContext& c) {
    return c.emu.Get<ArmMmu>().State()->translation_table_base.word
           & 0xFFFFC000u;
}

constexpr uint32_t kNKCreateProcessVa     = 0x8C03AA70u;
constexpr uint32_t kMDSwitchToUserCodeVa  = 0x8C0351D0u;

std::string ReadWcStr(const TraceContext& c, uint32_t va, int max_chars) {
    std::string out;
    if (va == 0) return out;
    for (int i = 0; i < max_chars; ++i) {
        auto w = c.ReadVa16(va + i * 2);
        if (!w.has_value()) break;
        if (*w == 0) break;
        out += (*w < 0x80) ? static_cast<char>(*w) : '?';
    }
    return out;
}

class Ce7ProcessResolverProbe : public Service {
public:
    using Service::Service;
    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kCe7BundleCrc32, [&] {
            tm.OnPc(kNKCreateProcessVa, [](const TraceContext& c) {
                std::string image = ReadWcStr(c, c.regs[0], 64);
                std::string cmd   = ReadWcStr(c, c.regs[1], 96);
                LOG(Trace, "[hit] NKCreateProcess entry image='%s' cmdline='%s' "
                    "R0=0x%08X R1=0x%08X LR=0x%08X\n",
                    image.c_str(), cmd.c_str(),
                    c.regs[0], c.regs[1], c.regs[14]);
                std::lock_guard<std::mutex> lk(g_mu);
                g_pending_names.push_back(image);
            });
            /* MDSwitchToUserCode fires exactly once per new process. R0 is
               passed to MTBFf, which then dispatches to args[0] (the EXE's
               WinMainCRTStartup). We pop the FIFO front. */
            tm.OnPc(kMDSwitchToUserCodeVa, [](const TraceContext& c) {
                uint32_t ttbr = CurrentTtbr0(c);
                /* Read args[0] (the EXE entry) from the args block at R1. */
                uint32_t entry = c.ReadVa32(c.regs[1]).value_or(0);
                std::lock_guard<std::mutex> lk(g_mu);
                if (g_pending_names.empty()) return;
                std::string name = g_pending_names.front();
                g_pending_names.erase(g_pending_names.begin());
                g_name_to_ttbr0[name] = ttbr;
                g_name_to_entry[name] = entry;
                LOG(Trace, "[resolver] '%s' -> ttbr0=0x%08X entry=0x%08X\n",
                    name.c_str(), ttbr, entry);
            });
        });
    }
};
REGISTER_SERVICE(Ce7ProcessResolverProbe);

}  /* namespace */

namespace ce7_resolver {

uint8_t CurrentFcsePid(const TraceContext& c) {
    auto& mmu = c.emu.Get<ArmMmu>();
    return static_cast<uint8_t>(mmu.State()->process_id & 0x7Fu);
}

TracePredicate PidPredicateForName(std::string image_name) {
    return [name = std::move(image_name)](const TraceContext& c) -> bool {
        uint32_t cur = CurrentTtbr0(c);
        std::lock_guard<std::mutex> lk(g_mu);
        auto it = g_name_to_ttbr0.find(name);
        if (it == g_name_to_ttbr0.end()) return false;
        return it->second == cur;
    };
}

}  /* namespace ce7_resolver */

#endif  /* CERF_DEV_MODE */
