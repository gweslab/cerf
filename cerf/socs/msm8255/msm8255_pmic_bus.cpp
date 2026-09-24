#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "msm8255_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../peripherals/ssbi_slave.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"

#include <cstdint>

namespace {

constexpr uint32_t kBase = 0xAD900000u;
constexpr uint32_t kSize = 0x00010000u;

constexpr uint32_t kRegCmd    = 0x08u;
constexpr uint32_t kRegRd     = 0x10u;
constexpr uint32_t kRegStatus = 0x14u;
constexpr uint32_t kRegMode2  = 0x1Cu;

constexpr uint32_t kStatusReady     = 1u << 1;
constexpr uint32_t kStatusReadReady = 1u << 2;

constexpr uint32_t kCmdRead      = 1u << 24;
constexpr uint32_t kCmdAddrShift = 16u;
constexpr uint32_t kCmdAddrMask  = 0xFFu;
constexpr uint32_t kCmdDataMask  = 0xFFu;

constexpr uint32_t kMode2Ssbi2         = 1u << 0;
constexpr uint32_t kMode2AddrHighMask  = 0x7F0u;
constexpr uint32_t kMode2AddrHighShift = 4u;

constexpr uint32_t kMode2AddrBitsShift = 1u;
constexpr uint32_t kMode2AddrBitsBase  = 8u;
constexpr uint32_t kSlaveAddrBits      = 10u;
constexpr uint32_t kMode2Reset =
    kMode2Ssbi2 |
    ((kSlaveAddrBits - kMode2AddrBitsBase) << kMode2AddrBitsShift);

class Msm8255PmicBus : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Msm8255;
    }

    void OnReady() override {
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
            mode2_    = kMode2Reset;
            rd_       = 0;
            rd_valid_ = false;
        });
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint32_t ReadWord(uint32_t addr) override {
        switch (addr - kBase) {
            case kRegStatus:
                return kStatusReady | (rd_valid_ ? kStatusReadReady : 0u);
            case kRegRd:
                rd_valid_ = false;
                return rd_;
            case kRegMode2:  return mode2_;
            default:         HaltUnsupportedAccess("ReadWord", addr, 0);
        }
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        switch (addr - kBase) {
            case kRegMode2:
                mode2_ = value;
                return;
            case kRegCmd:
                StartTransfer(value);
                return;
            default:
                HaltUnsupportedAccess("WriteWord", addr, value);
        }
    }

    void SaveState(StateWriter& w) override {
        w.Write("mode2", mode2_);
        w.Write("rd", rd_);
        w.Write<uint8_t>("rd_valid", rd_valid_ ? 1u : 0u);
        if (auto* slave = emu_.TryGet<SsbiSlave>()) slave->SaveState(w);
    }

    void RestoreState(StateReader& r) override {
        r.Read("mode2", mode2_);
        r.Read("rd", rd_);
        uint8_t valid = 0;
        r.Read("rd_valid", valid);
        rd_valid_ = valid != 0u;
        if (auto* slave = emu_.TryGet<SsbiSlave>()) slave->RestoreState(r);
    }

    void PostRestore() override {
        if (auto* slave = emu_.TryGet<SsbiSlave>()) slave->PostRestore();
    }

private:
    void StartTransfer(uint32_t cmd) {
        const uint32_t reg =
            (((mode2_ & kMode2AddrHighMask) >> kMode2AddrHighShift) << 8u) |
            ((cmd >> kCmdAddrShift) & kCmdAddrMask);

        auto* slave = emu_.TryGet<SsbiSlave>();
        if (!slave) {
            emu_.Get<Fatal>().Die(
                "msm8255 pmic ssbi: no slave is modeled, and the guest asked "
                "to %s register 0x%03X (cmd 0x%08X mode2 0x%08X)",
                (cmd & kCmdRead) ? "read" : "write", reg, cmd, mode2_);
        }

        if ((cmd & kCmdRead) != 0u) {
            rd_       = slave->ReadReg((uint16_t)reg);
            rd_valid_ = true;
            return;
        }
        slave->WriteReg((uint16_t)reg, (uint8_t)(cmd & kCmdDataMask));
    }

    uint32_t mode2_    = kMode2Reset;
    uint32_t rd_       = 0;
    bool     rd_valid_ = false;
};

}  // namespace

REGISTER_SERVICE(Msm8255PmicBus);
