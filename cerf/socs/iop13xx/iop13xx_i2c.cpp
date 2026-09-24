#include "iop13xx_i2c_device.h"

#include "../../boards/board_context.h"
#include "iop13xx_id.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_base.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../irq_controller.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "iop13xx_cp6.h"

#include <cstdint>

namespace {

/* Intel 81341 and 81342 I/O Processors Developer's Manual, chapter 14 and
   Peripheral Register Summary: I2C0 occupies PMMR +0x2500 and uses the
   ICR/ISR MSTART/TBYTE interrupt-driven transfer contract. */
constexpr uint32_t kI2cBase = 0xFFD82500u;
constexpr uint32_t kI2cSize = 0x0000001Cu;
constexpr int kI2cIrqSource = 10;
constexpr uint32_t kI2cIrqContributor = 1u << 0;
constexpr uint32_t kCrOffset = 0x00u;
constexpr uint32_t kSrOffset = 0x04u;
constexpr uint32_t kSarOffset = 0x08u;
constexpr uint32_t kDbrOffset = 0x0Cu;
constexpr uint32_t kBmrOffset = 0x14u;
constexpr uint32_t kMbcrOffset = 0x18u;

constexpr uint32_t kIcrFastMode = 0x8000u;
constexpr uint32_t kIcrUnitReset = 0x4000u;
constexpr uint32_t kIcrSadIe = 0x2000u;
constexpr uint32_t kIcrAldIe = 0x1000u;
constexpr uint32_t kIcrSsdIe = 0x0800u;
constexpr uint32_t kIcrBerrIe = 0x0400u;
constexpr uint32_t kIcrRxFullIe = 0x0200u;
constexpr uint32_t kIcrTxEmptyIe = 0x0100u;
constexpr uint32_t kIcrGcd = 0x0080u;
constexpr uint32_t kIcrUe = 0x0040u;
constexpr uint32_t kIcrSclEn = 0x0020u;
constexpr uint32_t kIcrMAbort = 0x0010u;
constexpr uint32_t kIcrTByte = 0x0008u;
constexpr uint32_t kIcrNack = 0x0004u;
constexpr uint32_t kIcrMStop = 0x0002u;
constexpr uint32_t kIcrMStart = 0x0001u;
constexpr uint32_t kIcrKnownMask = kIcrFastMode | kIcrUnitReset | kIcrSadIe | kIcrAldIe | kIcrSsdIe | kIcrBerrIe |
                                   kIcrRxFullIe | kIcrTxEmptyIe | kIcrGcd | kIcrUe | kIcrSclEn | kIcrMAbort |
                                   kIcrTByte | kIcrNack | kIcrMStop | kIcrMStart;

constexpr uint32_t kIsrBerrd = 0x0400u;
constexpr uint32_t kIsrAld = 0x0020u;
constexpr uint32_t kIsrSsd = 0x0010u;
constexpr uint32_t kIsrRxFull = 0x0080u;
constexpr uint32_t kIsrTxEmpty = 0x0040u;
constexpr uint32_t kIsrRxRead = 0x0001u;
constexpr uint32_t kIsrBBusy = 0x0008u;
constexpr uint32_t kIsrUnitBusy = 0x0004u;
constexpr uint32_t kIsrNack = 0x0002u;
constexpr uint32_t kIsrClearBits = 0x07F0u;
constexpr uint32_t kIsarSaMask = 0x007Fu;
constexpr uint32_t kBmrScl = 0x0002u;
constexpr uint32_t kBmrSda = 0x0001u;
constexpr uint32_t kMbcrKnownMask = 0x0007u;

class Iop13xxI2c final : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* board = emu_.TryGet<BoardContext>();
        return board && board->GetSocId() == SocId::Iop13xx;
    }

    void OnReady() override {
        ResetUnit();
        emu_.Get<PeripheralDispatcher>().Register(this);
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
            if (emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) return;
            ResetUnit();
        });
    }

    void OnShutdown() override {
        if (auto* device = emu_.TryGet<Iop13xxI2cDevice>()) device->Stop();
    }

    uint32_t MmioBase() const override { return kI2cBase; }
    uint32_t MmioSize() const override { return kI2cSize; }

    uint32_t ReadWord(uint32_t addr) override { return ReadWordRaw(addr & ~3u); }

    uint16_t ReadHalf(uint32_t addr) override {
        const uint32_t word = ReadWordRaw(addr & ~3u);
        return static_cast<uint16_t>(word >> ((addr & 2u) * 8u));
    }

    uint8_t ReadByte(uint32_t addr) override {
        const uint32_t word = ReadWordRaw(addr & ~3u);
        return static_cast<uint8_t>(word >> ((addr & 3u) * 8u));
    }

    void WriteWord(uint32_t addr, uint32_t value) override { WriteWordRaw(addr & ~3u, value); }

    void WriteHalf(uint32_t addr, uint16_t value) override {
        const uint32_t aligned = addr & ~3u;
        const uint32_t shift = (addr & 2u) * 8u;
        const uint32_t mask = 0xFFFFu << shift;
        WriteWordRaw(aligned, (ReadWordRaw(aligned) & ~mask) | (static_cast<uint32_t>(value) << shift));
    }

    void WriteByte(uint32_t addr, uint8_t value) override {
        const uint32_t aligned = addr & ~3u;
        const uint32_t shift = (addr & 3u) * 8u;
        const uint32_t mask = 0xFFu << shift;
        WriteWordRaw(aligned, (ReadWordRaw(aligned) & ~mask) | (static_cast<uint32_t>(value) << shift));
    }

    void SaveState(StateWriter& writer) override {
        writer.Write("icr", icr_);
        writer.Write("isr", isr_);
        writer.Write("isar", isar_);
        writer.Write("idbr", idbr_);
        writer.Write("imbcr", imbcr_);
        writer.Write("device_selected", device_selected_);
        writer.Write("device_read", device_read_);
        writer.Write("i2c_irq_line_asserted", i2c_irq_line_asserted_);
        auto* device = emu_.TryGet<Iop13xxI2cDevice>();
        const bool has_device = device != nullptr;
        writer.Write("has_device", has_device);
        if (device) device->SaveState(writer);
    }

    void RestoreState(StateReader& reader) override {
        reader.Read("icr", icr_);
        reader.Read("isr", isr_);
        reader.Read("isar", isar_);
        reader.Read("idbr", idbr_);
        reader.Read("imbcr", imbcr_);
        reader.Read("device_selected", device_selected_);
        reader.Read("device_read", device_read_);
        reader.Read("i2c_irq_line_asserted", i2c_irq_line_asserted_);
        bool has_device = false;
        reader.Read("has_device", has_device);
        auto* device = emu_.TryGet<Iop13xxI2cDevice>();
        if (has_device != (device != nullptr))
            reader.Reject(has_device ? "the image has an I2C device this build does not have"
                                     : "this build has an I2C device the image does not have");
        if (device) device->RestoreState(reader);
        icr_ &= kIcrKnownMask & ~kIcrUnitReset;
        idbr_ &= 0xFFu;
        isar_ &= kIsarSaMask;
        imbcr_ &= kMbcrKnownMask;
    }

    void PostRestore() override {
        if (auto* device = emu_.TryGet<Iop13xxI2cDevice>()) device->PostRestore();
    }

private:
    uint32_t ReadWordRaw(uint32_t addr) {
        switch (addr - kI2cBase) {
        case kCrOffset: return icr_;
        case kSrOffset: return isr_;
        case kSarOffset: return isar_;
        case kDbrOffset: return idbr_;
        case kBmrOffset: return kBmrScl | kBmrSda;
        case kMbcrOffset: return imbcr_;
        default: HaltUnsupportedAccess("IOP13xx I2C register read", addr, 0);
        }
    }

    void WriteWordRaw(uint32_t addr, uint32_t value) {
        switch (addr - kI2cBase) {
        case kCrOffset: WriteControl(value); return;
        case kSrOffset:
            isr_ &= ~(value & kIsrClearBits);
            RefreshInterrupt();
            return;
        case kSarOffset: isar_ = value & kIsarSaMask; return;
        case kDbrOffset: idbr_ = value & 0xFFu; return;
        case kMbcrOffset: imbcr_ = value & kMbcrKnownMask; return;
        default: HaltUnsupportedAccess("IOP13xx I2C register write", addr, value);
        }
    }

    void ResetUnit() {
        icr_ = 0;
        isr_ = kIsrTxEmpty;
        isar_ = 0;
        idbr_ = 0;
        imbcr_ = 0;
        device_selected_ = false;
        device_read_ = false;
        if (auto* device = emu_.TryGet<Iop13xxI2cDevice>()) device->Stop();
        RefreshInterrupt();
    }

    void WriteControl(uint32_t value) {
        const uint32_t control = value & kIcrKnownMask;
        if (control & kIcrUnitReset) {
            ResetUnit();
            return;
        }
        icr_ = control & ~kIcrTByte;
        if ((control & kIcrMAbort) && !(control & kIcrTByte)) {
            StopTransaction();
            isr_ |= kIsrTxEmpty;
            RefreshInterrupt();
            return;
        }
        if (control & kIcrTByte) {
            isr_ &= ~(kIsrRxFull | kIsrTxEmpty | kIsrNack | kIsrBerrd | kIsrBBusy | kIsrUnitBusy);
            TransferByte(control);
        }
        if (control & kIcrMStop) StopTransaction();
        RefreshInterrupt();
    }

    void TransferByte(uint32_t control) {
        if (control & kIcrMStart) {
            StartAddress(static_cast<uint8_t>(idbr_ & 0xFFu));
            return;
        }
        auto* device = emu_.TryGet<Iop13xxI2cDevice>();
        if (device_selected_ && device_read_ && device) {
            uint8_t value = 0xFFu;
            const bool acknowledge = device->ReadByte(value);
            idbr_ = value;
            isr_ |= kIsrRxFull | kIsrRxRead;
            if (!acknowledge) isr_ |= kIsrNack;
            return;
        }
        if (device_selected_ && device) {
            if (!device->WriteByte(static_cast<uint8_t>(idbr_ & 0xFFu))) isr_ |= kIsrNack;
            isr_ |= kIsrTxEmpty;
            return;
        }
        isr_ |= kIsrTxEmpty | kIsrNack;
    }

    void StartAddress(uint8_t address_byte) {
        device_read_ = (address_byte & 1u) != 0;
        isr_ = (isr_ & ~(kIsrRxFull | kIsrTxEmpty | kIsrNack | kIsrRxRead)) | kIsrTxEmpty;
        if (device_read_) isr_ |= kIsrRxRead;
        auto* device = emu_.TryGet<Iop13xxI2cDevice>();
        if (device && device->Address(address_byte)) {
            device_selected_ = true;
            return;
        }
        device_selected_ = false;
        device_read_ = false;
        isr_ |= kIsrNack;
    }

    void StopTransaction() {
        device_selected_ = false;
        device_read_ = false;
        if (auto* device = emu_.TryGet<Iop13xxI2cDevice>()) device->Stop();
        isr_ &= ~(kIsrBBusy | kIsrUnitBusy);
    }

    uint32_t EnabledInterruptStatus() const {
        uint32_t pending = 0u;
        if ((icr_ & kIcrAldIe) != 0u) pending |= isr_ & kIsrAld;
        if ((icr_ & kIcrSsdIe) != 0u) pending |= isr_ & kIsrSsd;
        if ((icr_ & kIcrBerrIe) != 0u) pending |= isr_ & kIsrBerrd;
        if ((icr_ & kIcrRxFullIe) != 0u) pending |= isr_ & kIsrRxFull;
        if ((icr_ & kIcrTxEmptyIe) != 0u) pending |= isr_ & kIsrTxEmpty;
        return pending;
    }

    void RefreshInterrupt() {
        auto& irq = emu_.Get<IrqController>();
        if (EnabledInterruptStatus() != 0u) {
            if (!i2c_irq_line_asserted_) {
                i2c_irq_line_asserted_ = true;
                /* Intel 81341/81342 Developer's Manual, Figure 115 and
                   IINTSRC0 bit 10: I2C0 drives interrupt-controller source 10. */
                irq.SetSharedIrqLevel(kI2cIrqSource, kI2cIrqContributor, true);
            }
        } else if (i2c_irq_line_asserted_) {
            i2c_irq_line_asserted_ = false;
            irq.SetSharedIrqLevel(kI2cIrqSource, kI2cIrqContributor, false);
        }
    }

    uint32_t icr_ = 0;
    uint32_t isr_ = kIsrTxEmpty;
    uint32_t isar_ = 0;
    uint32_t idbr_ = 0;
    uint32_t imbcr_ = 0;
    bool device_selected_ = false;
    bool device_read_ = false;
    bool i2c_irq_line_asserted_ = false;
};

REGISTER_SERVICE(Iop13xxI2c);

} // namespace
