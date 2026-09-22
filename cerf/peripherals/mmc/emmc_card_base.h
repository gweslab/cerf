#pragma once

#include "mmc_card.h"

#include "../../core/sd_card_cid.h"

#include <cstdint>

namespace cerf_mmc {

constexpr uint8_t kCmdGoIdleState      = 0u;
constexpr uint8_t kCmdSendOpCond       = 1u;
constexpr uint8_t kCmdAllSendCid       = 2u;
constexpr uint8_t kCmdSetRelativeAddr  = 3u;
constexpr uint8_t kCmdSleepAwake       = 5u;
constexpr uint8_t kCmdSwitch           = 6u;
constexpr uint8_t kCmdSelectCard       = 7u;
constexpr uint8_t kCmdSendExtCsd       = 8u;
constexpr uint8_t kCmdSendCsd          = 9u;
constexpr uint8_t kCmdSendCid          = 10u;
constexpr uint8_t kCmdStopTransmission = 12u;
constexpr uint8_t kCmdSendStatus       = 13u;
constexpr uint8_t kCmdReadSingleBlock  = 17u;
constexpr uint8_t kCmdReadMultiBlock   = 18u;
constexpr uint8_t kCmdSetWriteProt     = 28u;
constexpr uint8_t kCmdIoRwDirect       = 52u;
constexpr uint8_t kCmdAppCmd           = 55u;

constexpr uint32_t kBlockBytes = 512u;

constexpr uint32_t kGoIdleArgument = 0u;
constexpr uint32_t kStopHpi        = 1u << 0;

enum class MmcState : uint32_t {
    Idle  = 0u,
    Ready = 1u,
    Ident = 2u,
    Stby  = 3u,
    Tran  = 4u,
    Data  = 5u,
};

constexpr uint32_t kOcrBusy         = 0x80000000u;
constexpr uint32_t kOcrSectorAddr   = 0x40000000u;
constexpr uint32_t kOcrVoltage      = 0x00FF8000u;
constexpr uint32_t kOcrVoltageDual  = 0x00000080u;

constexpr uint32_t kR1ReadyForData      = 1u << 8;
constexpr uint32_t kR1StateShift        = 9u;
constexpr uint32_t kR1AddressOutOfRange = 1u << 31;

constexpr uint32_t kSwitchAccessShift = 24u;
constexpr uint32_t kSwitchAccessMask  = 3u;
constexpr uint32_t kSwitchIndexShift  = 16u;
constexpr uint32_t kSwitchValueShift  = 8u;
constexpr uint32_t kSwitchByteMask    = 0xFFu;
constexpr uint32_t kSwitchSetBits     = 1u;
constexpr uint32_t kSwitchClearBits   = 2u;
constexpr uint32_t kSwitchWriteByte   = 3u;
constexpr uint32_t kExtCsdUserWp      = 171u;
constexpr uint32_t kUserWpPwrWpEn     = 1u << 0;
constexpr uint32_t kExtCsdBusWidth    = 183u;
constexpr uint32_t kBusWidth8Bit      = 2u;
constexpr uint32_t kExtCsdHsTiming    = 185u;
constexpr uint32_t kHsTimingHighSpeed = 1u;

}  // namespace cerf_mmc

class EmmcCardBase : public MmcCard {
public:
    using MmcCard::MmcCard;

    void OnReady() override;

    MmcCommandResult Command(uint8_t index, uint32_t argument,
                             uint32_t response[4]) override;

    const std::vector<uint8_t>& ReadData() const override { return read_data_; }

    void NextBlock() override;

    void EndDataPhase() override;

    void Reset() override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

protected:
    virtual SdCardCid Cid() const = 0;
    virtual uint32_t  SectorCount() const = 0;
    virtual void      ReadBlock(uint32_t sector, uint8_t* out) = 0;

private:
    uint32_t StatusWord(cerf_mmc::MmcState before) const;
    void     BuildCsd(uint32_t out[4]) const;
    void     BuildCid(uint32_t out[4]) const;
    void     BuildExtCsd();
    void     ApplySwitch(uint32_t argument);
    void     ApplyUserWp(uint32_t access, uint32_t value);
    void     SetWriteProtect(uint32_t sector);
    uint32_t WpGroupCount() const;
    [[noreturn]] void HaltUnmodelledCommand(uint8_t index, uint32_t argument);

    cerf_mmc::MmcState   state_       = cerf_mmc::MmcState::Idle;
    uint16_t             rca_         = 0u;
    uint8_t              hs_timing_   = 0u;
    uint8_t              user_wp_     = 0u;
    bool                 multi_read_  = false;
    uint32_t             next_sector_ = 0u;
    std::vector<uint8_t> power_on_wp_;
    std::vector<uint8_t> read_data_;
};
