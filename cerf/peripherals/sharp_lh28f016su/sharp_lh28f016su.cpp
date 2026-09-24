#include "../intel_command_set_flash.h"

#include "../../boards/board_context.h"
#include "../../boards/page_table_builder.h"
#include "../../boards/philips_nino_300/philips_nino_300_id.h"
#include "../../core/cerf_emulator.h"

#include <cstdint>

namespace {

/* Sharp LH28F016SU, 16 Mbit, LH28F008SA-compatible (Intel basic command set).
   Two devices in parallel on the PR31700 32-bit CS0; the board crosses byte
   lanes so each identifier code appears in both halves, byte-swapped
   (datasheet PDF p.8-9; nk.exe 0x9F4321B0-0x9F4321C8 compares the swapped codes). */
constexpr uint32_t kIdentWordMfr = 0xB000B000u;   /* mfr 00B0h, lanes crossed */
constexpr uint32_t kIdentWordDev = 0x88668866u;   /* device 6688h, lanes crossed */
constexpr uint32_t kIdentOffMfr  = 0u;
constexpr uint32_t kIdentOffDev  = 4u;

class SharpLh28F016Su : public IntelCommandSetFlash {
public:
    using IntelCommandSetFlash::IntelCommandSetFlash;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::PhilipsNino300;
    }

    void OnReady() override {
        const DramRegion rom = emu_.Get<PageTableBuilder>().EntryXipRomRegion();
        base_ = rom.pa_base;
        size_ = rom.size;
        IntelCommandSetFlash::OnReady();
    }

    uint32_t MmioBase() const override { return base_; }
    uint32_t MmioSize() const override { return size_; }

protected:
    uint16_t Manufacturer() const override { return 0x00B0u; }
    uint16_t Device()       const override { return 0x6688u; }
    uint32_t Parallel()    const override { return 2u; }
    uint32_t DeviceWidth() const override { return 2u; }
    uint32_t ChipEraseBlockBytes() const override { return 0x10000u; }

    /* The Nino OAL only reads the array and the identifier codes
       (nk.exe 0x9F4321B0); every other command FATALs. */
    bool CommandEnabled(uint8_t cmd) const override { return cmd == 0xFFu || cmd == 0x90u; }

    /* Word-wide command with the byte lanes crossed: the command byte is the
       high byte of each identical 16-bit half (datasheet PDF p.9). */
    uint8_t DecodeCommand(uint32_t value, uint32_t width) override {
        if (width != 4u)
            HaltUnsupportedAccess("Sharp LH28F016SU non-word command", MmioBase(), value);
        const uint16_t lo = uint16_t(value);
        const uint16_t hi = uint16_t(value >> 16);
        if (lo != hi)
            HaltUnsupportedAccess("Sharp LH28F016SU per-device command", MmioBase(), value);
        return uint8_t(lo >> 8);
    }

    void PresentIdentifier(uint32_t /*addr*/) override {
        RestoreArray();
        SaveAndWriteWord(MmioBase() + kIdentOffMfr, kIdentWordMfr);
        SaveAndWriteWord(MmioBase() + kIdentOffDev, kIdentWordDev);
    }

private:
    uint32_t base_ = 0u;
    uint32_t size_ = 0u;
};

}  /* namespace */

REGISTER_SERVICE(SharpLh28F016Su);
