#include "iop13xx_gpio_input.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_base.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"

#include <cstdint>

namespace {

constexpr uint32_t kGpioBase = 0xFFD82480u;
constexpr uint32_t kGpioSize = 0x0000000Cu;

class Iop13xxGpio final : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* board = emu_.TryGet<BoardContext>();
        return board && board->GetSoc() == SocFamily::IOP13xx;
    }

    void OnReady() override {
        Reset();
        emu_.Get<PeripheralDispatcher>().Register(this);
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
            if (emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) return;
            Reset();
        });
    }

    uint32_t MmioBase() const override { return kGpioBase; }
    uint32_t MmioSize() const override { return kGpioSize; }

    uint32_t ReadWord(uint32_t addr) override {
        switch (addr - kGpioBase) {
        case 0x00u: return output_enable_;
        case 0x04u:
            if (auto* input = emu_.TryGet<Iop13xxGpioInput>()) return input->ReadPins();
            HaltUnsupportedAccess("IOP13xx GPIO input provider", addr, 0);
        case 0x08u: return output_data_;
        default: HaltUnsupportedAccess("IOP13xx GPIO register read", addr, 0);
        }
    }

    uint16_t ReadHalf(uint32_t addr) override {
        const uint32_t word = ReadWord(addr & ~3u);
        return static_cast<uint16_t>(word >> ((addr & 2u) * 8u));
    }

    uint8_t ReadByte(uint32_t addr) override {
        const uint32_t word = ReadWord(addr & ~3u);
        return static_cast<uint8_t>(word >> ((addr & 3u) * 8u));
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        switch (addr - kGpioBase) {
        case 0x00u: output_enable_ = value & kGpioOutputEnableMask; return;
        case 0x08u: output_data_ = value; return;
        default: HaltUnsupportedAccess("IOP13xx GPIO register write", addr, value);
        }
    }

    void WriteHalf(uint32_t addr, uint16_t value) override {
        const uint32_t aligned = addr & ~3u;
        const uint32_t shift = (addr & 2u) * 8u;
        const uint32_t mask = 0xFFFFu << shift;
        WriteWord(aligned, (ReadWord(aligned) & ~mask) | (static_cast<uint32_t>(value) << shift));
    }

    void WriteByte(uint32_t addr, uint8_t value) override {
        const uint32_t aligned = addr & ~3u;
        const uint32_t shift = (addr & 3u) * 8u;
        const uint32_t mask = 0xFFu << shift;
        WriteWord(aligned, (ReadWord(aligned) & ~mask) | (static_cast<uint32_t>(value) << shift));
    }

    void SaveState(StateWriter& writer) override {
        writer.Write(output_enable_);
        writer.Write(output_data_);
    }

    void RestoreState(StateReader& reader) override {
        reader.Read(output_enable_);
        reader.Read(output_data_);
    }

private:
    static constexpr uint32_t kGpioOutputEnableReset = 0x0000FFFFu;
    static constexpr uint32_t kGpioOutputEnableMask = 0x0000FFFFu;

    void Reset() {
        output_enable_ = kGpioOutputEnableReset;
        output_data_ = 0;
    }

    uint32_t output_enable_ = kGpioOutputEnableReset;
    uint32_t output_data_ = 0;
};

REGISTER_SERVICE(Iop13xxGpio);

} // namespace
