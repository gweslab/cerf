#include "siemens_mp377_sm501_power_gpio.h"
#include "siemens_mp377_sm501_internal.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"

namespace siemens_mp377 {

bool SiemensMp377Sm501PowerGpio::ShouldRegister() {
    auto* board = emu_.TryGet<BoardContext>();
    return board && board->GetBoard() == Board::SiemensMP377;
}

void SiemensMp377Sm501PowerGpio::Initialize(SiemensMp377Sm501Regs& registers) {
    auto& regs = registers.regs_;
    regs[kSm501PowerMode0GateReg / 4u] = kSm501PowerModeGateDefault;
    regs[kSm501PowerMode0ClockReg / 4u] = kSm501PowerModeClockDefault;
    regs[kSm501PowerMode1GateReg / 4u] = kSm501PowerModeGateDefault;
    regs[kSm501PowerMode1ClockReg / 4u] = kSm501PowerModeClockDefault;
    regs[kSm501SleepModeGateReg / 4u] = kSm501SleepModeGateDefault;
    regs[kSm501PowerModeControlReg / 4u] = 0u;
    regs[kSm501Gpio31_0ControlReg / 4u] = 0u;
    regs[kSm501GpioDataLowReg / 4u] = 0u;
    regs[kSm501GpioDataHighReg / 4u] = 0u;
    regs[kSm501GpioDirectionLowReg / 4u] = 0u;
    regs[kSm501GpioDirectionHighReg / 4u] = 0u;
    regs[kSm501GpioIrqSetupReg / 4u] = 0u;
    regs[kSm501GpioIrqStatusReg / 4u] = 0u;
}

uint32_t SiemensMp377Sm501PowerGpio::CurrentGateMask() const {
    const auto& regs = emu_.Get<SiemensMp377Sm501Regs>().regs_;
    const uint32_t mode = regs[kSm501PowerModeControlReg / 4u] & 3u;
    if (mode == 1u) return regs[kSm501PowerMode1GateReg / 4u];
    if (mode == 2u) return regs[kSm501SleepModeGateReg / 4u];
    return regs[kSm501PowerMode0GateReg / 4u];
}

uint32_t SiemensMp377Sm501PowerGpio::CurrentGate() const {
    return CurrentGateMask();
}

uint32_t SiemensMp377Sm501PowerGpio::CurrentClock() const {
    const auto& regs = emu_.Get<SiemensMp377Sm501Regs>().regs_;
    const uint32_t mode = regs[kSm501PowerModeControlReg / 4u] & 3u;
    if (mode == 1u) return regs[kSm501PowerMode1ClockReg / 4u];
    return regs[kSm501PowerMode0ClockReg / 4u];
}

bool SiemensMp377Sm501PowerGpio::IsGateEnabled(uint32_t gate_bit) const {
    return (CurrentGateMask() & gate_bit) != 0u;
}

void SiemensMp377Sm501PowerGpio::WritePowerModeControl(uint32_t value) {
    const uint32_t mode = value & 3u;
    if (mode == 2u)
        value |= 4u;
    else
        value &= ~4u;
    emu_.Get<SiemensMp377Sm501Regs>().regs_[kSm501PowerModeControlReg / 4u] = value;
}

uint32_t SiemensMp377Sm501PowerGpio::ActiveAc97GpioMuxMask() const {
    const auto& regs = emu_.Get<SiemensMp377Sm501Regs>().regs_;
    return regs[kSm501Gpio31_0ControlReg / 4u] & kSm501GpioAc97Mask;
}

bool SiemensMp377Sm501PowerGpio::IsAc97LinkMuxed() const {
    return (ActiveAc97GpioMuxMask() & kSm501GpioAc97Mask) == kSm501GpioAc97Mask;
}

bool SiemensMp377Sm501PowerGpio::IsCodecResetDeasserted() const {
    const auto& regs = emu_.Get<SiemensMp377Sm501Regs>().regs_;
    const uint32_t data = regs[kSm501GpioDataLowReg / 4u];
    const uint32_t direction = regs[kSm501GpioDirectionLowReg / 4u];
    if ((direction & kMp377CodecResetGpioBit) != 0u && (data & kMp377CodecResetGpioBit) != 0u) return true;
    return IsAc97LinkMuxed() && IsGateEnabled(kSm501GateAc97I2sBit);
}

uint32_t SiemensMp377Sm501PowerGpio::ReadGpioDataLow() const {
    const auto& regs = emu_.Get<SiemensMp377Sm501Regs>().regs_;
    const uint32_t value = regs[kSm501GpioDataLowReg / 4u];
    const uint32_t mux = ActiveAc97GpioMuxMask();
    if (mux == 0u) return value;
    uint32_t pins = 0u;
    if (IsGateEnabled(kSm501GateAc97I2sBit) && IsCodecResetDeasserted())
        pins = kSm501Gpio24Ac97RstBit | kSm501Gpio26Ac97BitclkBit;
    return (value & ~mux) | (pins & mux);
}

uint32_t SiemensMp377Sm501PowerGpio::ReadGpioDirectionLow() const {
    const auto& regs = emu_.Get<SiemensMp377Sm501Regs>().regs_;
    const uint32_t value = regs[kSm501GpioDirectionLowReg / 4u];
    const uint32_t mux = ActiveAc97GpioMuxMask();
    if (mux == 0u) return value;
    return (value & ~mux) | (kSm501GpioAc97OutputMask & mux);
}

void SiemensMp377Sm501PowerGpio::UpdateAc97Link() {
    emu_.Get<SiemensMp377Sm501Ac97>().UpdateStatus();
}

REGISTER_SERVICE(SiemensMp377Sm501PowerGpio);

} // namespace siemens_mp377
