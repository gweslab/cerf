#pragma once

#include "dp8390.h"
#include "dp8390_receiver.h"

#include "../pcmcia/pcmcia_card.h"

#include <array>
#include <cstddef>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

class Rtl8019 : public PcmciaCard {
public:
    static constexpr const wchar_t* kDisplayName =
        L"NE2000 Ethernet (RTL8019)";

    explicit Rtl8019(CerfEmulator& emu);
    ~Rtl8019() override;

    std::wstring DisplayName() const override { return kDisplayName; }
    std::wstring TooltipDetail() const override;
    std::wstring MenuLabel() const override;
    const wchar_t* IconResource() const override { return L"ICON_PCMCIA_ETHERNET"; }

    void OnInserted() override;
    void OnShutdown() override;

    void PowerOn () override;
    void PowerOff() override;

    uint8_t  ReadAttribute8 (uint32_t offset)                override;
    void     WriteAttribute8(uint32_t offset, uint8_t value) override;

    uint8_t  ReadCommon8  (uint32_t offset)                  override;
    uint16_t ReadCommon16 (uint32_t offset)                  override;
    void     WriteCommon8 (uint32_t offset, uint8_t  value)  override;
    void     WriteCommon16(uint32_t offset, uint16_t value)  override;

    uint8_t  ReadIo8  (uint32_t offset)                      override;
    uint16_t ReadIo16 (uint32_t offset)                      override;
    void     WriteIo8 (uint32_t offset, uint8_t  value)      override;
    void     WriteIo16(uint32_t offset, uint16_t value)      override;

    std::vector<WidgetMenuItem> BuildCardMenu() override;

    const char* SaveId() const override { return "ne2000"; }
    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override;

private:
    friend class Dp8390;

    static constexpr std::size_t kMacLen = 6;

    void DetachRx();
    void OnRxFrame(const uint8_t* frame, std::size_t len);
    void WriteMacProm();
    std::string ReceiverId() const;

    void SetIrqLineLocked(bool level);

    /* PC Card Standard Vol. 2 Electrical, 4.12.2: on RESET or SRESET
       "a card shall return to the power-up state". */
    void PowerUpLocked();

    bool IoIgnoredLocked() const;
    bool MapCardIoLocked(uint32_t card_io, uint32_t* reg) const;

    std::string rx_id_;
    std::array<uint8_t, kMacLen> guest_mac_{};
    bool rx_installed_ = false;

    bool powered_  = false;
    bool irq_line_ = false;

    mutable std::mutex state_mutex_;

    /* PC Card Standard Vol. 2 Electrical, 4.15.1 Table 4-29 (COR) and
       4.15.2 Table 4-30 (CCSR). */
    uint8_t cor_  = 0u;
    uint8_t ccsr_ = 0u;

    std::array<uint8_t, Dp8390::kRomSize> card_rom_{};
    std::array<uint8_t, Dp8390::kRamSize> card_ram_{};

    Dp8390         nic_;
    Dp8390Receiver receiver_;
};
