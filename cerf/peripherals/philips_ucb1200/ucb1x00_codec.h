#pragma once

#include "../../core/service.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <vector>

class StateWriter;
class StateReader;

/* Register map and bit fields: Linux ucb1x00.h, NetBSD hpcmips ucb1200reg.h. */
class Ucb1x00Codec : public Service {
public:
    using Service::Service;

    void OnReady() override;

    uint16_t ReadReg(uint8_t reg);
    void     WriteReg(uint8_t reg, uint16_t value);

    void SetTouchPressed(bool pressed);
    bool PenDown();
    bool IrqAsserted();

    /* The active-low RESET input (UCB1300 datasheet p.32). */
    enum class ResetPin { Low, High, Floating };
    void DriveResetPin(ResetPin level);

    void SaveState(StateWriter& w);
    void RestoreState(StateReader& r);

protected:
    /* ID_REG. philips_nino_300 sib.dll sub_18D1768 returns its low 6 bits and
       sub_18D1A0C compares them against 4. */
    virtual uint16_t DeviceId() const = 0;
    virtual std::array<uint16_t, 16> PowerOnRegs() const = 0;
    virtual uint16_t AdcCrReadBack(uint16_t written) const { return written; }
    virtual uint16_t StubWriteBits(uint8_t) const { return 0u; }

private:
    struct State {
        std::array<uint16_t, 16> regs{};
        uint16_t adc_data = 0;
        uint16_t rise_ff  = 0;
        uint16_t fall_ff  = 0;
        bool     held     = false;
        bool operator==(const State&) const = default;
    };

    State    PowerOn(bool held) const;
    void     ForkLocked(const char* event);
    void     DedupeLocked();
    uint16_t ReadStateLocked(const State& s, uint8_t reg) const;
    void     WriteStateLocked(State& s, uint8_t reg, uint16_t value);
    uint16_t PenDetectTsCr(const State& s) const;
    void     Convert(State& s, uint16_t prev_cr, uint16_t adc_cr);
    static uint16_t IrqStatus(const State& s);
    bool     IrqLevelLocked();
    void     PublishIrqLocked();

    std::mutex         mutex_;
    std::vector<State> states_;
    const char*        fork_event_ = "";
    ResetPin           pin_        = ResetPin::High;
    bool               irq_out_    = false;
    std::atomic<bool>  pen_down_{false};
};
