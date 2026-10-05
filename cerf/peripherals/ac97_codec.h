#pragma once

#include "../core/service.h"

#include <cstdint>

class StateWriter;
class StateReader;

class Ac97FrameSource {
public:
    virtual ~Ac97FrameSource() = default;
    virtual bool FrameAt(uint64_t cycle, uint64_t& frame) const = 0;
    virtual void OnCodecStreamChange() = 0;
};

class Ac97Codec : public Service {
public:
    using Service::Service;

    void AttachFrameSource(Ac97FrameSource* source) { frames_ = source; }

    virtual uint16_t ReadReg(uint32_t reg, uint64_t frame) = 0;
    virtual void     WriteReg(uint32_t reg, uint16_t value, uint64_t frame) = 0;

    virtual void ColdReset()                  = 0;
    virtual void LinkStopped(uint64_t frame)  = 0;
    virtual bool DacPowered()                 = 0;
    virtual bool AdcPowered()                 = 0;

    virtual uint16_t GpioSlotStatus(uint64_t frame);

    virtual uint64_t SlotWordsBefore(uint64_t frames) = 0;
    virtual bool     FrameOfSlotWord(uint64_t n, uint64_t& frame) = 0;
    virtual uint16_t SlotWord(uint64_t n) = 0;
    virtual void     PruneSlotWords(uint64_t frames) = 0;

    void     WarmReset();
    bool     LinkPoweredDown();
    uint32_t DacRateHz() const { return dac_rate_; }
    uint32_t AdcRateHz() const { return adc_rate_; }

    virtual void SaveState(StateWriter&) {}
    virtual void RestoreState(StateReader&) {}
    virtual void PostRestore() {}

protected:
    virtual uint16_t Peek(uint32_t reg) = 0;
    virtual void     Poke(uint32_t reg, uint16_t value) = 0;
    virtual const uint16_t* SupportedRates(uint32_t& count) const = 0;
    virtual bool            IsRateRegister(uint32_t reg) const;
    virtual bool            RateWriteTakesEffect(uint32_t reg);

    bool     WriteRateRegister(uint32_t reg, uint16_t value);
    void     OnExtAudioCtrlWrite();
    uint16_t ReadStored(uint32_t reg);
    void     ResetRates();
    void     SaveRates(StateWriter& w) const;
    void     RestoreRates(StateReader& r);

    Ac97FrameSource* frames_ = nullptr;

    /* AC '97 Component Specification Revision 2.1 section 6.3.11 Table 19 and
       Appendix A.2 (index 2Ah, 2Ch, 32h). */
    static constexpr uint32_t kRegReset        = 0x00u;
    static constexpr uint32_t kRegPowerdown    = 0x26u;
    static constexpr uint32_t kRegExtAudioCtrl = 0x2Au;
    static constexpr uint32_t kRegDacRate      = 0x2Cu;
    static constexpr uint32_t kRegAdcRate      = 0x32u;
    static constexpr uint16_t kPr0 = 1u << 8;
    static constexpr uint16_t kPr1 = 1u << 9;
    static constexpr uint16_t kPr3 = 1u << 11;
    static constexpr uint16_t kPr4 = 1u << 12;
    static constexpr uint16_t kVra = 1u << 0;

private:
    uint16_t       NearestSupported(uint16_t value) const;
    static uint8_t RateBit(uint32_t reg) { return static_cast<uint8_t>(1u << ((reg - kRegDacRate) >> 1)); }

    uint32_t dac_rate_  = 48000u;
    uint32_t adc_rate_  = 48000u;
    uint8_t  unsettled_ = 0;
};
