#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../board_detector.h"

#include <cstdint>
#include <mutex>

namespace {

constexpr uint32_t kBase = 0x500FFFC0u;
constexpr uint32_t kSize = 0x00000001u;

constexpr uint32_t kRegSpeakerPhoneState = 0x00u;

class DevEmuSpkHeadset : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::Smdk2410DevEmu;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint8_t ReadByte (uint32_t addr) override;
    void    WriteByte(uint32_t addr, uint8_t value) override;

private:
    mutable std::mutex state_mutex_;
    uint8_t            speaker_phone_state_ = 0;
};

uint8_t DevEmuSpkHeadset::ReadByte(uint32_t addr) {
    const uint32_t off = addr - kBase;
    uint8_t value = 0;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        switch (off) {
            case kRegSpeakerPhoneState:
                value = speaker_phone_state_;
                break;
            default:
                HaltUnsupportedAccess("ReadByte", addr, 0);  /* noreturn */
        }
    }
    LOG(Periph, "[SpkHeadset] read8 SpeakerPhoneState -> 0x%02X\n", value);
    return value;
}

void DevEmuSpkHeadset::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off = addr - kBase;
    LOG(Periph, "[SpkHeadset] write8 SpeakerPhoneState = 0x%02X\n", value);
    std::lock_guard<std::mutex> lk(state_mutex_);
    switch (off) {
        case kRegSpeakerPhoneState:
            speaker_phone_state_ = value;
            break;
        default:
            HaltUnsupportedAccess("WriteByte", addr, value);  /* noreturn */
    }
}

}  /* namespace */

REGISTER_SERVICE(DevEmuSpkHeadset);
