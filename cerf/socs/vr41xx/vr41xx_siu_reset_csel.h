#pragma once

#include "vr41xx_siu.h"

#include "../../state/state_stream.h"

#include <cstdint>

/* VR4121 UM Table 25-1: SIU registers 0x09 SIURESET / 0x0A SIUCSEL (absent on the
   VR4102, whose Table 24-1 stops at 0x08). */
class Vr41xxSiuResetCsel : public Vr41xxSiu {
public:
    using Vr41xxSiu::Vr41xxSiu;

protected:
    uint32_t ReadChipExtReg(uint32_t idx) override {
        if (idx == 9u) return sreset_;
        if (idx == 10u) return csel_;
        return Vr41xxSiu::ReadChipExtReg(idx);
    }
    void WriteChipExtReg(uint32_t idx, uint32_t value) override {
        /* 0x09 SIURESET (VR4121 UM 25.2.14 p570): D0 R/W 1=Reset SIU / 0=Release, D7:1 RFU
           read-0. Casio serial.dll pulses it (sub_1330F14 RMW: set D0=1, Sleep(20), clear
           D0), reading it back - D0 is held; a D0=1 write resets the NS16550 core. */
        if (idx == 9u) {
            sreset_ = static_cast<uint8_t>(value & SiuResetWritable());
            ApplySiuReset(sreset_);
            return;
        }
        /* 0x0A SIUCSEL (VR4121 UM 25.2.15 p570): D0 R/W CSEL echo-back-prevention mask
           (D0=1 Mask), D7:1 RFU read-0. Casio serial.dll sub_1331128 writes D0=1. */
        if (idx == 10u) { csel_ = static_cast<uint8_t>(value & 0x01u); return; }
        Vr41xxSiu::WriteChipExtReg(idx, value);
    }
    /* VR4121 UM 25.2.14 p570: D0 SIURESET, D7:1 RFU. */
    virtual uint8_t SiuResetWritable() const { return 0x01u; }
    virtual void    ApplySiuReset(uint8_t sreset) {
        if (sreset & 0x01u) Serial16550::Reset();
    }

    void ResetChip() override                      { sreset_ = 0; csel_ = 0; }
    void SaveChipState(StateWriter& w) override    { w.Write("sreset", sreset_); w.Write("csel", csel_); }
    void RestoreChipState(StateReader& r) override { r.Read("sreset", sreset_); r.Read("csel", csel_); }

private:
    uint8_t sreset_ = 0;   /* SIU 0x09 SIURESET D0 */
    uint8_t csel_   = 0;   /* SIU 0x0A SIUCSEL D0 */
};
