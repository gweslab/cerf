#include "zune_process_resolver.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"
#include "../../jit/arm_mmu_state.h"
#include "bundle.h"

#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#if CERF_DEV_MODE

namespace {

std::mutex                                g_mu;
std::unordered_map<std::string, uint32_t> g_name_to_pid;
std::vector<std::string>                  g_pending_names;

/* CE5 uses FCSE: one shared TTBR0, per-process isolation via the FCSE PID
   (process_id). So the address-space key is process_id, not TTBR0. */
uint32_t CurrentFcsePid(const TraceContext& c) {
    return c.emu.Get<ArmMmu>().State()->process_id;
}

constexpr uint32_t kCreateProcessVa          = 0x8821CF38u;  /* R0 = image name */
constexpr uint32_t kPrimaryThreadBootstrapVa = 0x8820E13Cu;  /* once per new proc */

/* sub_8821CF38 folds a low (<32 MB) name pointer with the caller's slot base
   v70 = *(*(0xFFFFC890)+12) | a1; read through the same fold or hit unmapped. */
std::string ReadFoldedWcStr(const TraceContext& c, uint32_t va, int max_chars) {
    std::string out;
    if (va == 0) return out;
    if ((va & 0xFE000000u) == 0) {
        auto pcur = c.ReadVa32(0xFFFFC890u);
        auto base = pcur ? c.ReadVa32(*pcur + 12u) : std::nullopt;
        if (base) va |= *base;
    }
    for (int i = 0; i < max_chars; ++i) {
        auto w = c.ReadVa16(va + i * 2);
        if (!w.has_value() || *w == 0) break;
        out += (*w < 0x80) ? static_cast<char>(*w) : '?';
    }
    return out;
}

class ZuneProcessResolverProbe : public Service {
public:
    using Service::Service;
    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kZuneKeelBundleCrc32, [&] {
            tm.OnPc(kCreateProcessVa, [](const TraceContext& c) {
                std::string image = ReadFoldedWcStr(c, c.regs[0], 64);
                /* callerPid identifies the launcher process (RunApps);
                   lr is its user-mode CreateProcess call site. */
                LOG(Trace, "[CREATEPROC] image='%s' callerPid=0x%08X lr=0x%08X\n",
                    image.c_str(), CurrentFcsePid(c), c.regs[14]);
                std::lock_guard<std::mutex> lk(g_mu);
                g_pending_names.push_back(image);
            });
            /* sub_8820C86C = kernel module loader; a3 (r2) = module name.
               Logs every driver DLL as it loads, in order — the last before
               device.exe wedges is the driver whose Init is stuck. */
            tm.OnPc(0x8820C86Cu, [](const TraceContext& c) {
                std::string name = ReadFoldedWcStr(c, c.regs[2], 64);
                const uint32_t pid = CurrentFcsePid(c);
                LOG(Trace, "[MODLOAD] '%s' loaderPid=0x%08X lr=0x%08X\n",
                    name.c_str(), pid, c.regs[14]);
            });
            tm.OnPc(kPrimaryThreadBootstrapVa, [](const TraceContext& c) {
                const uint32_t pid = CurrentFcsePid(c);
                std::lock_guard<std::mutex> lk(g_mu);
                if (g_pending_names.empty()) return;
                std::string name = g_pending_names.front();
                g_pending_names.erase(g_pending_names.begin());
                g_name_to_pid[name] = pid;
                LOG(Trace, "[zresolver] '%s' -> fcsePid=0x%08X\n",
                    name.c_str(), pid);
            });
        });
    }
};
REGISTER_SERVICE(ZuneProcessResolverProbe);

}  /* namespace */

namespace zune_resolver {

TracePredicate PidPredicateForName(std::string image_name) {
    return [name = std::move(image_name)](const TraceContext& c) -> bool {
        const uint32_t cur = CurrentFcsePid(c);
        std::lock_guard<std::mutex> lk(g_mu);
        auto it = g_name_to_pid.find(name);
        if (it == g_name_to_pid.end()) return false;
        return it->second == cur;
    };
}

}  /* namespace zune_resolver */

#endif  /* CERF_DEV_MODE */
