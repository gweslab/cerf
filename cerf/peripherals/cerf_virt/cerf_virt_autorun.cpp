#include "cerf_virt_addr_map.h"
#include "cerf_virt_autorun_regs.h"
#include "cerf_virt_utf16_window.h"

#include "../peripheral_base.h"
#include "../peripheral_dispatcher.h"
#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../core/log.h"
#include "../../core/string_utils.h"

#include <string>
#include <vector>

namespace {

class CerfVirtAutorun : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        return emu_.Get<DeviceConfig>().guest_additions;
    }

    void OnReady() override {
        const auto& list = emu_.Get<DeviceConfig>().guest_additions_autorun;
        if (list.size() > CerfVirt::kArMaxEntries) {
            LOG(Caution, "FATAL: guest_additions.autorun has %u entries, max %u",
                (unsigned)list.size(), CerfVirt::kArMaxEntries);
            CerfFatalExit(CERF_FATAL_USER_ERROR);
        }
        for (const std::string& s : list) {
            std::wstring w = Utf8ToWide(s.c_str());
            if (w.size() >= CerfVirt::kArEntryWchars) {
                LOG(Caution, "FATAL: guest_additions.autorun entry '%s' exceeds %u characters",
                    s.c_str(), CerfVirt::kArEntryWchars - 1);
                CerfFatalExit(CERF_FATAL_USER_ERROR);
            }
            LOG(GuestAdditions, "autorun[%u] = '%s'", (unsigned)entries_.size(), s.c_str());
            entries_.push_back(std::move(w));
        }
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override {
        return emu_.Get<BoardContext>().GuestAdditionsWindowBase() + CerfVirt::kAutorunOffset;
    }
    uint32_t MmioSize() const override { return CerfVirt::kAutorunSize; }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        if (off == CerfVirt::kArPresent) return entries_.empty() ? 0u : CerfVirt::kArMagic;
        if (off == CerfVirt::kArCount)   return (uint32_t)entries_.size();
        if (off >= CerfVirt::kArEntries && off + 4u <= CerfVirt::kAutorunSize) {
            const uint32_t rel = off - CerfVirt::kArEntries;
            const uint32_t idx = rel / CerfVirt::kArEntryStride;
            const uint32_t ch  = (rel % CerfVirt::kArEntryStride) / 2u;
            if (idx >= entries_.size()) return 0u;
            return CerfVirt::Utf16WindowWord(entries_[idx], ch);
        }
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        HaltUnsupportedAccess("WriteWord", addr, value);
    }

private:
    std::vector<std::wstring> entries_;
};

}

REGISTER_SERVICE(CerfVirtAutorun);
