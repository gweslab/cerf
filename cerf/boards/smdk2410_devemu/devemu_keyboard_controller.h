#pragma once

#include "../../socs/spi_slave.h"

#include <cstdint>
#include <deque>
#include <mutex>

class DevEmuKeyboardController : public SpiSlave {
public:
    using SpiSlave::SpiSlave;

    bool ShouldRegister() override;
    void OnReady() override;

    void QueueScancode(uint8_t scancode);

    uint8_t Exchange(uint8_t mosi) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

private:
    void ResetDevice();
    void DriveLineLocked(bool level);
    void PresentLocked();
    void OnGuestUnmask(uint32_t unmasked_intmsk);
    void AcceptHostByteLocked(uint8_t mosi);

    std::mutex          mutex_;
    std::deque<uint8_t> queue_;
    uint32_t            cmd_index_    = 0;
    uint32_t            cmd_pos_      = 0;
    bool                awaiting_ack_ = false;
    bool                line_active_  = false;
    bool                line_seeded_  = false;
};
