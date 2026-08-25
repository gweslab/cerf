#pragma once

#include "../../peripherals/peripheral_base.h"
#include "../../host/paced_wave_out.h"
#include "../audio_out_sink.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>
#include <vector>

/* PXA255 AC'97 controller (base 0x40500000). Register side is a careful stub
   (GSR codec-ready, CAR link-free) so codec init doesn't hang. Audio output is
   real and MUST pace the DMA's per-block completion via on_block_done - without
   it the guest audio thread blocks on missing DMA completions, deadlocking the UI. */
class Pxa255Ac97 : public Peripheral, public AudioOutSink {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;
    void OnShutdown() override;

    uint32_t MmioBase() const override { return 0x40500000u; }
    uint32_t MmioSize() const override { return 0x00001000u; }

    uint16_t ReadHalf (uint32_t addr) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteHalf(uint32_t addr, uint16_t value) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    /* Register/codec-shadow state only; the host audio/touch coupling is
       transient and re-armed by the DMA after a restore (see the .cpp). */
    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

    /* Audio-output coupling driven by the Pxa255Dma AC'97 channel. A missed block
       completion hangs the guest audio DMA thread, so on_block_done fires even
       with no audio device present (silent boots still post it). */
    void BeginAudioOut(std::function<void()> on_block_done) override;
    void StopAudioOut() override;
    void QueueOutput(const void* host_bytes, uint32_t length) override;

    /* Touch RX: board TouchInput pushes WM9705 readback words (bit15 pen-down,
       [14:12] adcsel 0x1000 X/0x2000 Y/0x3000 P, [11:0] value) into the modem-in
       FIFO (MODR); the touch DMA drains them via the registered callback. */
    void     PushTouchSample(const uint16_t* words, uint32_t count);
    void     BeginTouchCapture(std::function<void()> on_sample);
    void     StopTouchCapture();
    uint32_t PopTouchWords(uint16_t* out, uint32_t max);
    uint32_t TouchFifoCount();

private:
    uint16_t CodecRead(uint32_t reg);
    void     CodecWrite(uint32_t reg, uint16_t value);

    static constexpr uint32_t kSampleRate  = 48000u;   /* AC-link PCM 48 kHz. */
    static constexpr uint16_t kChannels    = 2u;
    static constexpr uint16_t kBitsPerSamp = 16u;

    static constexpr uint32_t kPOCR = 0x00u, kPICR = 0x04u, kMCCR = 0x08u,
                              kGCR  = 0x0Cu, kGSR  = 0x1Cu, kCAR  = 0x20u,
                              kMOCR = 0x100u, kMICR = 0x108u;
    /* Modem-in path carries WM9705 touch slot-5 data (Linux pxa2xx-ac97-regs.h).
       MISR.FSR (bit2) = MODR FIFO has data; MODR = modem-in FIFO data register. */
    static constexpr uint32_t kMISR = 0x118u, kMODR = 0x140u;
    static constexpr uint32_t kMisrFsr = 1u << 2;
    static constexpr uint32_t kCodecBase = 0x200u, kCodecEnd = 0x600u;
    static bool InCodecWindow(uint32_t off) {
        return off >= kCodecBase && off < kCodecEnd;
    }
    /* §13.8.3.3 Table 13-8 GSR: PCR (bit 8) + SDONE (bit 18) + CDONE (bit 19). */
    static constexpr uint32_t kGsrReady = (1u << 8) | (1u << 18) | (1u << 19);

    uint32_t pocr_ = 0, picr_ = 0, mccr_ = 0, gcr_ = 0, mocr_ = 0, micr_ = 0;
    uint16_t codec_[(kCodecEnd - kCodecBase) / 2] = {};

    PacedWaveOut          audio_out_;

    /* Touch modem-in FIFO, drained by the touch DMA; separate lock (other threads). */
    std::mutex            touch_mutex_;
    std::vector<uint16_t> touch_fifo_;
    std::function<void()> on_touch_sample_;
};
