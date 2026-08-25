#pragma once

#include "../../peripherals/peripheral_base.h"

#include "../../host/paced_wave_out.h"
#include "../audio_out_sink.h"

#include <cstdint>
#include <functional>

class StateReader;
class StateWriter;

class Pxa27xAc97 : public Peripheral, public AudioOutSink {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;
    void OnShutdown() override;

    /* Section 13.7 (page 13-20): "The AC '97 controller and Codec registers are
       mapped in addresses 0x4050_0000-0x405F_FFFC." */
    uint32_t MmioBase() const override { return 0x40500000u; }
    uint32_t MmioSize() const override { return 0x00001000u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;
    uint16_t ReadHalf (uint32_t addr) override;
    void     WriteHalf(uint32_t addr, uint16_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

    void BeginAudioOut(std::function<void()> on_block_done) override;
    void QueueOutput(const void* host_bytes, uint32_t length) override;
    void StopAudioOut() override;

    uint32_t PcmOutFifoAddr() const { return MmioBase() + kPCDR; }

private:
    /* Intel PXA27x Developer's Manual 280000-001 Table 13-25 (pages 13-42, 13-43)
       "AC '97 Controller Register Summary". */
    enum : uint32_t {
        kPOCR   = 0x000u, kPCMICR = 0x004u, kMCCR = 0x008u, kGCR  = 0x00Cu,
        kPOSR   = 0x010u, kPCMISR = 0x014u, kMCSR = 0x018u, kGSR  = 0x01Cu,
        kCAR    = 0x020u, kPCDR   = 0x040u, kMCDR = 0x060u,
        kMOCR   = 0x100u, kMICR   = 0x108u, kMOSR = 0x110u, kMISR = 0x118u,
        kMODR   = 0x140u,
    };

    /* Table 13-25 (page 13-43): "(0x4050_0200-0x4050_02FC) Primary Audio Codec
       registers", 0x300 Secondary Audio, 0x400 Primary Modem, 0x500 Secondary
       Modem, "0x4050_0600-0x405F_FFFC reserved". */
    enum : uint32_t {
        kCodecBase = 0x200u, kCodecEnd = 0x600u,
        kCodecWindows = 4u, kCodecRegs = 0x80u,
    };

    /* AC '97 Component Specification Revision 2.3 Table 30: "2Ah Ext'd Audio
       Stat/Ctrl ... VRA" at D0, "2Ch PCM Front DAC Rate SR15 ... SR0 ... BB80h";
       section 5.8.3: rate registers hold "16-bit unsigned values ... representing
       the rate of operation in Hz", default BB80h with VRA=0. */
    enum : uint32_t { kExtAudioStatCtrl = 0x2Au, kPcmFrontDacRate = 0x2Cu };
    static constexpr uint16_t kExtCtrlVra = 1u << 0;
    static constexpr uint16_t kRate48k = 0xBB80u;
    static constexpr uint16_t kChannels    = 2u;
    static constexpr uint16_t kBitsPerSamp = 16u;

    [[noreturn]] uint32_t Reject(const char* op, uint32_t addr, uint32_t value) {
        HaltUnsupportedAccess(op, addr, value);
    }

    static bool     InCodecWindow(uint32_t off);
    static bool     IsRegister(uint32_t off);
    bool            LinkOutOfColdReset() const;
    /* Section 13.7.17 (page 13-40): "Physical address for a Primary Audio Codec
       = 0x4050_0200 + Shift_Left_Once (Internal 7-bit Codec register address)". */
    static uint32_t CodecWindow(uint32_t off) { return (off - kCodecBase) >> 8; }
    static uint32_t CodecReg(uint32_t off) { return (off & 0xFFu) >> 1; }
    uint16_t        CodecRead(uint32_t off);
    void            CodecWrite(uint32_t off, uint16_t value);
    void            SnoopRateRegister(uint32_t reg, uint16_t value);
    uint32_t        ReadCar();
    static uint32_t ReadRxFifo(uint32_t& status);
    uint32_t        ReadModemRx();
    uint32_t        ReadGsr() const;
    void            WriteGcr(uint32_t value);

    /* Reset rows of Table 13-9 (page 13-23) and Tables 13-10 through 13-23 are
       0b0 in every defined field; the Table 13-8 (page 13-21) row is 0b0 in
       every defined field except nDMAEN, which it prints as undefined. */
    uint32_t pocr_ = 0, pcmicr_ = 0, mccr_ = 0, mocr_ = 0, micr_ = 0, gcr_ = 0;
    uint32_t posr_ = 0, pcmisr_ = 0, mcsr_ = 0, mosr_ = 0, misr_ = 0, gsr_ = 0;
    bool     car_caip_ = false;
    uint16_t codec_[kCodecWindows][kCodecRegs] = {};

    bool          vra_ = false;
    uint16_t      front_dac_rate_ = kRate48k;
    PacedWaveOut  audio_out_;
};
