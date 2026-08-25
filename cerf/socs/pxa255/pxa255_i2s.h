#pragma once

#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "../../host/paced_wave_out.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../audio_out_sink.h"

#include <cstdint>

/* PXA255 I2S controller (base 0x40400000; Developer's Manual 278693 ch.14). */
class Pxa255I2s : public Peripheral, public AudioOutSink {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::PXA25x;
    }
    void OnReady() override;
    void OnShutdown() override;

    uint32_t MmioBase() const override { return 0x40400000u; }
    uint32_t MmioSize() const override { return 0x00001000u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    /* §14.8: I2S registers are word-addressable; route any narrower access onto
       the aligned word so an unexpected width can't halt boot. */
    uint8_t  ReadByte (uint32_t addr) override { return static_cast<uint8_t> (ReadWord(addr & ~0x3u)); }
    uint16_t ReadHalf (uint32_t addr) override { return static_cast<uint16_t>(ReadWord(addr & ~0x3u)); }
    void     WriteByte(uint32_t addr, uint8_t  v) override { WriteWord(addr & ~0x3u, v); }
    void     WriteHalf(uint32_t addr, uint16_t v) override { WriteWord(addr & ~0x3u, v); }

    /* AudioOutSink - the Pxa255Dma I2S-target channel drives playback through these. */
    void BeginAudioOut(std::function<void()> on_block_done) override;
    void QueueOutput(const void* host_bytes, uint32_t length) override;
    void StopAudioOut() override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

private:
    enum : uint32_t {
        kSACR0 = 0x00u, kSACR1 = 0x04u, kSASR0 = 0x0Cu,
        kSAIMR = 0x14u, kSAICR = 0x18u, kSADIV = 0x60u, kSADR = 0x80u,
    };
    static constexpr uint32_t kSacr0Enb = 1u << 0;   /* SACR0.ENB (Table 14-3). */
    static constexpr uint32_t kSasr0Tnf = 1u << 0;   /* SASR0.TNF (Table 14-7). */
    static constexpr uint32_t kSasr0Tfs = 1u << 3;   /* SASR0.TFS DMA service req. */

    /* I2S link fs = 576000 / SADIV (Table 14-8: 0x0C->48k, 0x24->16k, reset 0x1A->22.05k);
       played as 16-bit stereo. */
    uint32_t SampleRateHz() const { return sadiv_ ? (576000u / sadiv_) : 22050u; }

    uint32_t sacr0_ = 0, sacr1_ = 0, saimr_ = 0, sadiv_ = 0;
    PacedWaveOut audio_out_;
};
