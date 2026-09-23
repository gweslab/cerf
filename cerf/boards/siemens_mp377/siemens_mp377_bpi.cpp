#include "../../peripherals/everspin_mr2a16a/siemens_mp377_mram.h"
#include "../../peripherals/silicon_motion_sm501/siemens_mp377_sm501.h"

#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_base.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../board_context.h"
#include "siemens_mp377_id.h"

#include <array>
#include <cstdint>

namespace {

class SiemensMp377Bpi : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::SiemensMp377;
    }

    void OnReady() override {
        BuildHwi();
        emu_.Get<siemens_mp377::SiemensMp377Mram>().SeedBspioBootState();
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return 0xF0000000u; }
    uint32_t MmioSize() const override { return 0x01000000u; }

    uint8_t ReadByte(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        if (off >= kHwiPtrOff && off < kHwiPtrOff + 4u) {
            return static_cast<uint8_t>((kHwiOff >> ((off - kHwiPtrOff) * 8u)) & 0xFFu);
        }
        if (off >= kMacPtrOff && off < kMacPtrOff + 4u) {
            return static_cast<uint8_t>((kMacOff >> ((off - kMacPtrOff) * 8u)) & 0xFFu);
        }
        if (off >= kImPtrOff && off < kImPtrOff + 4u) {
            return static_cast<uint8_t>((kImOff >> ((off - kImPtrOff) * 8u)) & 0xFFu);
        }
        if (off >= kHwiOff && off < kHwiOff + kHwiSize) return hwi_[off - kHwiOff];
        if (off >= kMacOff && off < kMacOff + kMacSize) return mac_[off - kMacOff];
        if (off >= kImOff && off < kImOff + kImSize) return im_[off - kImOff];
        if (off >= kMramAliasOff && off < kMramAliasOff + kMramAliasSize) {
            return emu_.Get<siemens_mp377::SiemensMp377Mram>().ReadAliasByte(addr);
        }
        if (off >= kBpiExtendedHwiOff && off < kBpiExtendedHwiOff + kBpiExtendedHwiSize) {
            HaltUnsupportedAccess("MP377 missing BPI extended HWI descriptor", addr, 0);
        }
        if (off >= kPartitionTableOff && off < kPartitionTableOff + kPartitionTableSize) {
            /* siemens_mp377_v1040 nk.exe sub_804467E8: PA 0xF07C0000,
               72-byte partition table, signature 0x20070514. */
            return 0xFFu;
        }
        HaltUnsupportedAccess("MP377 unsupported BPI byte read", addr, 0);
    }

    uint16_t ReadHalf(uint32_t addr) override {
        return static_cast<uint16_t>(ReadByte(addr) | (ReadByte(addr + 1u) << 8));
    }

    uint32_t ReadWord(uint32_t addr) override {
        return static_cast<uint32_t>(ReadByte(addr) | (ReadByte(addr + 1u) << 8) | (ReadByte(addr + 2u) << 16) |
                                     (ReadByte(addr + 3u) << 24));
    }

    void WriteByte(uint32_t addr, uint8_t value) override {
        const uint32_t off = addr - MmioBase();
        if (off >= kMramAliasOff && off < kMramAliasOff + kMramAliasSize) {
            emu_.Get<siemens_mp377::SiemensMp377Mram>().WriteAliasByte(addr, value);
            return;
        }
        HaltUnsupportedAccess("MP377 unsupported BPI byte write", addr, value);
    }

    void WriteHalf(uint32_t addr, uint16_t value) override {
        WriteByte(addr, static_cast<uint8_t>(value));
        WriteByte(addr + 1u, static_cast<uint8_t>(value >> 8));
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        WriteByte(addr, static_cast<uint8_t>(value));
        WriteByte(addr + 1u, static_cast<uint8_t>(value >> 8));
        WriteByte(addr + 2u, static_cast<uint8_t>(value >> 16));
        WriteByte(addr + 3u, static_cast<uint8_t>(value >> 24));
    }

private:
    static constexpr uint32_t kHwiPtrOff = 0x20u;
    static constexpr uint32_t kMacPtrOff = 0x24u;
    static constexpr uint32_t kImPtrOff = 0x28u;
    static constexpr uint32_t kHwiOff = 0x1000u;
    static constexpr uint32_t kMacOff = 0x1080u;
    static constexpr uint32_t kImOff = 0x109Cu;
    static constexpr uint32_t kHwiSize = 0x80u;
    static constexpr uint32_t kMacSize = 0x1Cu;
    static constexpr uint32_t kImSize = 0x30u;
    static constexpr uint32_t kMramAliasOff = siemens_mp377::kMp377MramAliasPa - 0xF0000000u;
    static constexpr uint32_t kMramAliasSize = siemens_mp377::kMp377MramSize;
    static constexpr uint32_t kBpiExtendedHwiOff = 0x00040000u;
    static constexpr uint32_t kBpiExtendedHwiSize = 0x40u;
    static constexpr uint32_t kPartitionTableOff = 0x007C0000u;
    static constexpr uint32_t kPartitionTableSize = 72u;
    void BuildHwi() {
        using siemens_mp377::kMp377HwiPanel;
        using siemens_mp377::kMp377MramAliasPa;

        /* siemens_mp377_v1040 nk.exe sub_80446218 HWI_Init handoff layout. */
        hwi_.fill(0);
        hwi_[0x00] = 0xA5u;
        hwi_[0x7F] = 0x5Au;
        hwi_[0x0E] = 0x20u;
        hwi_[0x10] = 0x00u;
        hwi_[0x11] = 0x80u;
        hwi_[0x28] = kMp377HwiPanel.op_type_family;
        hwi_[0x2C] = kMp377HwiPanel.op_type_variant;

        /* siemens_mp377_v1040 nk.exe sub_80446F50 HWI framebuffer defaults. */
        hwi_[0x14] = 0xFFu;
        hwi_[0x15] = 0xFFu;
        hwi_[0x16] = 0xFFu;
        hwi_[0x17] = 0xFFu;
        hwi_[0x18] = 0xFFu;
        hwi_[0x19] = 0xFFu;
        hwi_[0x1A] = 0xFFu;
        hwi_[0x1B] = 0xFFu;
        hwi_[0x1E] = 0xFFu;
        hwi_[0x1F] = 0xFFu;
        hwi_[0x20] = 0xFFu;
        hwi_[0x21] = 0xFFu;

        /* P377 nk.exe HWI_GetMRAMStart/HWI_GetMRAMSize descriptor. */
        hwi_[0x44] = 0x02u;
        hwi_[0x45] = 0x00u;
        cerf::le::Put16(hwi_.data() + 0x46, static_cast<uint16_t>(kMp377MramAliasPa >> 16));
        cerf::le::Put16(hwi_.data() + 0x48, static_cast<uint16_t>(kMramAliasSize >> 10));

        /* P377 nk.exe HWI_GetOneNandInfo descriptor. */
        hwi_[0x4A] = 0x01u;
        hwi_[0x4B] = 0x12u;
        hwi_[0x4C] = 0x20u;
        hwi_[0x4D] = 0xD0u;
        hwi_[0x4E] = 0x00u;
        hwi_[0x4F] = 0x01u;

        /* siemens_mp377_v1040 nk.exe sub_804462FC MAC handoff layout. */
        mac_.fill(0);
        mac_[0x00] = 0x55u;
        mac_[0x01] = 0xAAu;
        mac_[0x08] = 0x02u;
        mac_[0x09] = 0xCEu;
        mac_[0x0A] = 0x5Fu;
        mac_[0x0B] = 0x00u;
        mac_[0x0C] = 0x00u;
        mac_[0x0D] = 0x01u;

        /* P377 nk.exe HWI I&M handoff layout at BPI pointer offset 0x28. */
        im_.fill(0);
        im_[0x00] = 0x01u;
        im_[0x01] = 0x00u;
        im_[0x02] = 0x15u;
        im_[0x03] = 0x00u;
        im_[0x04] = 0x29u;
        im_[0x05] = 0x00u;
        im_[0x08] = 'M';
        im_[0x09] = 'P';
        im_[0x0A] = '3';
        im_[0x0B] = '7';
        im_[0x0C] = '7';
        im_[0x0D] = 0;
        im_[0x1C] = 'P';
        im_[0x1D] = '3';
        im_[0x1E] = '7';
        im_[0x1F] = '7';
        im_[0x20] = 0;
    }

    std::array<uint8_t, kHwiSize> hwi_{};
    std::array<uint8_t, kMacSize> mac_{};
    std::array<uint8_t, kImSize> im_{};
};

} // namespace

REGISTER_SERVICE(SiemensMp377Bpi);
