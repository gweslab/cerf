#pragma once

#include "../../peripherals/peripheral_base.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <vector>

/* Philips PR31x00 IR Module, TMPR3911/3912 ch.10. */
class Pr31x00Ir : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return 0x10C000A0u; }
    uint32_t MmioSize() const override { return 0x4u; }

    uint32_t ReadWord(uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    /* A board part drives the CARDET input pin, whose level IR Control 1 reports in
       CARDET<24> (§10.5.1). A rising edge latches POSCARINT and a falling edge
       NEGCARINT, both in Interrupt Status 5 (§8.3.5). */
    void DriveCarDetInput(bool level);

    /* TMPR3911 §10.5.1: "This bit is connected to the RXPWR pin." */
    using RxPwrObserver = std::function<void(bool level)>;
    void RegisterRxPwrObserver(RxPwrObserver cb);

    uint8_t  ReadByte(uint32_t addr) override { HaltUnsupportedAccess("PR31x00 IR ReadByte", addr, 0); }
    uint16_t ReadHalf(uint32_t addr) override { HaltUnsupportedAccess("PR31x00 IR ReadHalf", addr, 0); }
    void WriteByte(uint32_t addr, uint8_t  v) override { HaltUnsupportedAccess("PR31x00 IR WriteByte", addr, v); }
    void WriteHalf(uint32_t addr, uint16_t v) override { HaltUnsupportedAccess("PR31x00 IR WriteHalf", addr, v); }

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

private:
    uint32_t          ctl1_ = 0;
    std::atomic<bool> cardet_{false};

    std::vector<RxPwrObserver> rxpwr_observers_;
};
