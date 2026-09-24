#include "../../socs/iop13xx/iop13xx_pci_config.h"

#include "../../peripherals/siemens_ertec400/siemens_mp377_ertec400.h"
#include "../../peripherals/silicon_motion_sm501/siemens_mp377_sm501.h"
#include "../board_context.h"
#include "siemens_mp377_id.h"
#include "../../core/cerf_emulator.h"
#include "../../state/state_stream.h"
#include "../../socs/guest_cpu_reset.h"

#include <array>
#include <cstdint>

namespace {

class SiemensMp377PciConfig final : public Iop13xxPciConfig {
public:
    using Iop13xxPciConfig::Iop13xxPciConfig;

    bool ShouldRegister() override {
        auto* board = emu_.TryGet<BoardContext>();
        return board && board->GetBoardId() == BoardId::SiemensMp377;
    }

    void OnReady() override {
        Reset();
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
            if (!emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) Reset();
        });
    }

    void Reset() {
        BuildSm501Config();
        BuildErtec400Config();
        fb_bar_probe_ = false;
        regs_bar_probe_ = false;
        ertec_bar_probe_.fill(false);
    }

    uint32_t ReadPrimary(uint32_t occar) override {
        const uint32_t reg = (occar & 0xFFu) >> 2;
        const uint32_t select = DeviceSelect(occar);
        if (select == kSm501Select) return Sm501ConfigRead(reg);
        if (select == kErtec400Select) return Ertec400ConfigRead(reg);
        return 0xFFFFFFFFu;
    }

    bool WritePrimary(uint32_t occar, uint32_t value) override {
        const uint32_t reg = (occar & 0xFFu) >> 2;
        const uint32_t select = DeviceSelect(occar);
        if (select == kErtec400Select) return WriteErtec400Config(reg, value);
        if (select != kSm501Select) return true;
        return WriteSm501Config(reg, value);
    }

    uint32_t ReadSecondary(uint32_t occar) override {
        const uint32_t reg = (occar & 0xFFu) >> 2;
        if (DeviceSelect(occar) != kSecondarySm501Select) return 0xFFFFFFFFu;
        return Sm501ConfigRead(reg);
    }
    bool WriteSecondary(uint32_t occar, uint32_t value) override {
        const uint32_t reg = (occar & 0xFFu) >> 2;
        if (DeviceSelect(occar) != kSecondarySm501Select) return true;
        return WriteSm501Config(reg, value);
    }

    /* PCI Local Bus Specification Revision 3.0, section 6.2.5.1;
       SM501 Databook v1.02, PCI Configuration Space Header. */
    Iop13xxPciMemoryMapResult MapMemoryBar(uint32_t pci_address, uint32_t size,
                                           uint32_t& model_address) const override {
        if ((sm501_cfg_[0x01] & 0x00000002u) != 0u) {
            if (!fb_bar_probe_ && MapBar(pci_address, size, sm501_cfg_[0x04],
                                        siemens_mp377::kSm501FbBytes,
                                        siemens_mp377::kSm501FbBarPa, model_address))
                return Iop13xxPciMemoryMapResult::kMapped;
            if (!regs_bar_probe_ && MapBar(pci_address, size, sm501_cfg_[0x05],
                                          siemens_mp377::kSm501RegsBytes,
                                          siemens_mp377::kSm501RegsBarPa, model_address))
                return Iop13xxPciMemoryMapResult::kMapped;
        }
        if ((ertec_cfg_[0x01] & 0x00000002u) != 0u) {
            for (uint32_t reg = 0x04u; reg <= 0x09u; ++reg) {
                if (ertec_bar_probe_[reg - 0x04u]) continue;
                if (MapBar(pci_address, size, ertec_cfg_[reg], Ertec400BarSize(reg),
                           Ertec400ModelBase(reg), model_address))
                    return Iop13xxPciMemoryMapResult::kMapped;
            }
        }
        if (InModelAperture(pci_address, size)) return Iop13xxPciMemoryMapResult::kUnmapped;
        return Iop13xxPciMemoryMapResult::kNotBar;
    }

    void SaveState(StateWriter& writer) override {
        writer.WriteBytes("sm501_cfg", sm501_cfg_.data(), sm501_cfg_.size() * sizeof(sm501_cfg_[0]));
        writer.WriteBytes("ertec_cfg", ertec_cfg_.data(), ertec_cfg_.size() * sizeof(ertec_cfg_[0]));
        writer.Write("fb_bar_probe", fb_bar_probe_);
        writer.Write("regs_bar_probe", regs_bar_probe_);
        for (bool probe : ertec_bar_probe_)
            writer.Write("probe", probe);
    }

    void RestoreState(StateReader& reader) override {
        reader.ReadBytes("sm501_cfg", sm501_cfg_.data(), sm501_cfg_.size() * sizeof(sm501_cfg_[0]));
        reader.ReadBytes("ertec_cfg", ertec_cfg_.data(), ertec_cfg_.size() * sizeof(ertec_cfg_[0]));
        reader.Read("fb_bar_probe", fb_bar_probe_);
        reader.Read("regs_bar_probe", regs_bar_probe_);
        for (bool& probe : ertec_bar_probe_)
            reader.Read("probe", probe);
    }

private:
    static uint32_t DeviceSelect(uint32_t occar) { return occar & 0x7FFFFF00u; }

    /* PCI Local Bus Specification Revision 3.0, section 6.2.5.1. */
    uint32_t Sm501ConfigRead(uint32_t reg) {
        if (reg == 0x04 && fb_bar_probe_)
            return siemens_mp377::kSm501PciFbBarSizeMask | siemens_mp377::kSm501PciFbBarFlags;
        if (reg == 0x05 && regs_bar_probe_)
            return siemens_mp377::kSm501PciRegsBarSizeMask | siemens_mp377::kSm501PciRegsBarFlags;
        return sm501_cfg_[reg];
    }

    uint32_t Ertec400ConfigRead(uint32_t reg) {
        if (reg >= 0x04u && reg <= 0x09u && ertec_bar_probe_[reg - 0x04u]) {
            return Ertec400BarMask(reg);
        }
        return ertec_cfg_[reg];
    }

    static constexpr uint32_t Ertec400BarMask(uint32_t reg) {
        return reg == 0x07u ? 0xFF800000u : 0xFFFF0000u;
    }

    static constexpr uint32_t Ertec400BarSize(uint32_t reg) {
        return reg == 0x07u ? 0x00800000u : 0x00010000u;
    }

    static constexpr uint32_t Ertec400ModelBase(uint32_t reg) {
        switch (reg) {
        case 0x04u: return siemens_mp377::kErtecBar0Base;
        case 0x05u: return siemens_mp377::kErtecBar1Base;
        case 0x06u: return siemens_mp377::kErtecBar2Base;
        case 0x07u: return siemens_mp377::kErtecBar3Base;
        case 0x08u: return siemens_mp377::kErtecBar4Base;
        case 0x09u: return siemens_mp377::kErtecBar5Base;
        default: return 0u;
        }
    }

    static bool MapBar(uint32_t address, uint32_t access_size, uint32_t configured_bar,
                       uint32_t bar_size, uint32_t model_base, uint32_t& model_address) {
        if (access_size == 0u) return false;
        const uint32_t base = configured_bar & ~(bar_size - 1u);
        if (address < base) return false;
        const uint64_t offset = static_cast<uint64_t>(address) - base;
        if (offset + access_size > bar_size) return false;
        model_address = model_base + static_cast<uint32_t>(offset);
        return true;
    }

    static bool InModelAperture(uint32_t address, uint32_t access_size) {
        uint32_t ignored = 0u;
        if (MapBar(address, access_size, siemens_mp377::kSm501FbBarPa,
                   siemens_mp377::kSm501FbBytes, 0u, ignored)) return true;
        if (MapBar(address, access_size, siemens_mp377::kSm501RegsBarPa,
                   siemens_mp377::kSm501RegsBytes, 0u, ignored)) return true;
        for (uint32_t reg = 0x04u; reg <= 0x09u; ++reg) {
            if (MapBar(address, access_size, Ertec400ModelBase(reg),
                       Ertec400BarSize(reg), 0u, ignored)) return true;
        }
        return false;
    }

    bool fb_bar_probe_ = false;
    bool regs_bar_probe_ = false;
    std::array<bool, 6> ertec_bar_probe_{};

    void BuildSm501Config() {
        sm501_cfg_.fill(0u);
        sm501_cfg_[0x00] = siemens_mp377::kSm501PciDeviceVendorDword;
        sm501_cfg_[0x01] = siemens_mp377::kSm501PciCommandStatusDword;
        sm501_cfg_[0x02] = siemens_mp377::kSm501PciClassDisplayDword;
        sm501_cfg_[0x03] = siemens_mp377::kSm501PciHeaderTypeDword;
        sm501_cfg_[0x04] = siemens_mp377::kSm501PciFbBarDword;
        sm501_cfg_[0x05] = siemens_mp377::kSm501PciRegsBarDword;
        sm501_cfg_[0x0B] = siemens_mp377::kSm501PciSubsystemDword;
        sm501_cfg_[0x0D] = siemens_mp377::kSm501PciCapabilityPointerDword;
        sm501_cfg_[0x0F] = siemens_mp377::kSm501PciInterruptPinIntaLine0Dword;
    }

    void BuildErtec400Config() {
        ertec_cfg_.fill(0u);
        ertec_bar_probe_.fill(false);
        /* siemens_mp377_v1040 eddertec400.dll sub_28E1CA8. */
        ertec_cfg_[0x00] = 0x4026110Au;
        ertec_cfg_[0x01] = 0x02000007u;
        ertec_cfg_[0x02] = 0x02000000u;
        ertec_cfg_[0x03] = 0x00000000u;
        ertec_cfg_[0x04] = siemens_mp377::kErtecBar0Base;
        ertec_cfg_[0x05] = siemens_mp377::kErtecBar1Base;
        ertec_cfg_[0x06] = siemens_mp377::kErtecBar2Base;
        ertec_cfg_[0x07] = siemens_mp377::kErtecBar3Base;
        ertec_cfg_[0x08] = siemens_mp377::kErtecBar4Base;
        ertec_cfg_[0x09] = siemens_mp377::kErtecBar5Base;
        ertec_cfg_[0x0B] = 0x4026110Au;
        ertec_cfg_[0x0F] = 0x00000100u;
    }

    bool WriteErtec400Config(uint32_t reg, uint32_t value) {
        switch (reg) {
        case 0x00:
        case 0x02:
        case 0x0A:
        case 0x0B:
        case 0x0E: return true;
        case 0x04:
        case 0x05:
        case 0x06:
        case 0x07:
        case 0x08:
        case 0x09:
            ertec_bar_probe_[reg - 0x04u] = value == 0xFFFFFFFFu;
            if (!ertec_bar_probe_[reg - 0x04u]) ertec_cfg_[reg] = value & Ertec400BarMask(reg);
            return true;
        case 0x01:
        case 0x03: ertec_cfg_[reg] = (ertec_cfg_[reg] & 0xFFFF0000u) | (value & 0x0000FFFFu); return true;
        case 0x0C:
        case 0x0D: ertec_cfg_[reg] = 0u; return true;
        case 0x0F: ertec_cfg_[reg] = (ertec_cfg_[reg] & 0xFFFFFF00u) | (value & 0x000000FFu); return true;
        default: return false;
        }
    }

    bool WriteSm501Config(uint32_t reg, uint32_t value) {
        switch (reg) {
        case 0x00:
        case 0x02:
        case 0x0A:
        case 0x0B:
        case 0x0D:
        case 0x0E: return true;
        case 0x01: sm501_cfg_[reg] = (sm501_cfg_[reg] & 0xFFFF0000u) | (value & 0x0000FFFFu); return true;
        case 0x03: sm501_cfg_[reg] = (sm501_cfg_[reg] & 0xFFFF0000u) | (value & 0x0000FFFFu); return true;
        case 0x04:
            fb_bar_probe_ = (value == 0xFFFFFFFFu);
            if (!fb_bar_probe_)
                sm501_cfg_[reg] = (value & siemens_mp377::kSm501PciFbBarSizeMask) |
                                  siemens_mp377::kSm501PciFbBarFlags;
            return true;
        case 0x05:
            regs_bar_probe_ = (value == 0xFFFFFFFFu);
            if (!regs_bar_probe_)
                sm501_cfg_[reg] = (value & siemens_mp377::kSm501PciRegsBarSizeMask) |
                                  siemens_mp377::kSm501PciRegsBarFlags;
            return true;
        case 0x06:
        case 0x07:
        case 0x08:
        case 0x09:
        case 0x0C: sm501_cfg_[reg] = 0u; return true;
        case 0x0F: sm501_cfg_[reg] = (sm501_cfg_[reg] & 0xFFFFFF00u) | (value & 0x000000FFu); return true;
        default: return false;
        }
    }

    static constexpr uint32_t kSm501Select = 0x00007800u;
    static constexpr uint32_t kSecondarySm501Select = 0x00007800u;
    static constexpr uint32_t kErtec400Select = siemens_mp377::kErtec400PciSelect;

    std::array<uint32_t, 64> sm501_cfg_{};
    std::array<uint32_t, 64> ertec_cfg_{};
};

REGISTER_SERVICE_AS(SiemensMp377PciConfig, Iop13xxPciConfig);

} // namespace
