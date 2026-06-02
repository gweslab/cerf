#include "../trace_manager.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "bundle.h"

#if CERF_DEV_MODE

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <unordered_map>
#include <vector>

namespace {

/* Block-exit PC histogram for the iPAQ boot-hang investigation: the freeze
   spins in a non-MMIO RAM loop the mmio_pc histogram cannot see, so sample
   guest PC at every Run() return and dump the hottest buckets ~1/sec. */
class IpaqSpinPcHistogram : public Service {
public:
    using Service::Service;

    void OnReady() override {
        auto& tm = emu_.Get<TraceManager>();
        tm.RegisterForBundle(kIpaq3650BundleCrc32, [this, &tm] {
            tm.OnRunLoopIter([this](const TraceContext& c) {
                ++hist_[c.pc];
                if (++samples_ >= 4000000u) {
                    DumpTop();
                    hist_.clear();
                    samples_ = 0;
                }
            });
        });
    }

private:
    void DumpTop() {
        std::vector<std::pair<uint32_t, uint64_t>> v(hist_.begin(), hist_.end());
        const size_t k = std::min<size_t>(8, v.size());
        std::partial_sort(v.begin(), v.begin() + k, v.end(),
            [](const auto& a, const auto& b) { return a.second > b.second; });
        char line[320];
        int o = std::snprintf(line, sizeof line, "[SPIN-PC]");
        for (size_t i = 0; i < k; ++i) {
            o += std::snprintf(line + o, sizeof line - o, " %08X:%llu",
                               v[i].first,
                               static_cast<unsigned long long>(v[i].second));
        }
        LOG(Periph, "%s\n", line);
    }

    std::unordered_map<uint32_t, uint64_t> hist_;
    uint32_t samples_ = 0;
};

REGISTER_SERVICE(IpaqSpinPcHistogram);

}  // namespace

#endif  // CERF_DEV_MODE
