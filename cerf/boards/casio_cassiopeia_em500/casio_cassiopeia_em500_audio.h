#pragma once

#include "../../host/paced_wave_out.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../socs/rated_tick_count.h"

#include <atomic>
#include <cstdint>
#include <functional>
#include <mutex>

class CerfEmulator;
class StateWriter;
class StateReader;

/* wavedev.dll audio DMA block, companion 0x0880-0x08CC (base dword_F640C0 =
   0x0A000000). */
class CasioCassiopeiaEm500Audio {
public:
    void Init(CerfEmulator& emu, std::function<void()> on_irq_change);
    void OnShutdown();

    bool TryReadHalf (uint32_t off, uint16_t& out);
    bool TryWriteHalf(uint32_t off, uint16_t  value);
    bool TryReadWord (uint32_t off, uint32_t& out);
    bool TryWriteWord(uint32_t off, uint32_t  value);

    /* Codec register 5 bit7 = the loc_F62984 rate doubler: @0xF62A20 sll $v1,$a1,7 /
       @0xF62A24 or 0xD007 / @0xF62A26 sw 0x3C0. */
    void SetRateDoubler(bool on);

    bool IrqPending() const {
        return status_8A8_.load(std::memory_order_acquire) != 0u;
    }

    void SaveState(StateWriter& w) const;
    void RestoreState(StateReader& r);
    void PostRestore();

private:
    /* dword_F622D4 @0xF622E4 lhu 0x8A8, the only instruction accessing 0x8A8 in
       wavedev.dll and nk_main_kernel.exe; bit0 selects the per-block class-0x10
       branch, bit1 the class-0x20 branch. */
    static constexpr uint16_t kStatusBlockDone = 0x1u;

    /* casio_cassiopeia_em500_ppc2000 wavedev.dll rate select bits[6:4]: loc_F62984 @0xF629CC lhu /
       @0xF629CE li 0x71 / @0xF629D0 neg / @0xF629D6 sw. Word RMW @0xF617DE lw / @0xF617E2 or 4 /
       @0xF617E4 sw, and loc_F62984 @0xF62A46 lw / @0xF62A4A or 4 / @0xF62A4C sw. */
    static constexpr uint32_t kOffCtrl880 = 0x0880u;
    /* casio_cassiopeia_em500_ppc2000 wavedev.dll bit0 enable loc_F618CC @0xF61966 lhu / @0xF61968 or
       / @0xF6196A sh, cleared loc_F62984 @0xF62A7E-@0xF62A86; bit1 set @0xF62A34-@0xF62A3E; bit2
       hardware BUSY, read sub_F614E4 @0xF614EE and spun loc_F61EAC @0xF61EC8-@0xF61ED2. */
    static constexpr uint32_t kOffEnable884 = 0x0884u;
    /* casio_cassiopeia_em500_ppc2000 wavedev.dll loc_F61EAC @0xF61EBC sw 0 -> 0x8A0 / @0xF61EC4
       addiu $s0,2180 / @0xF61EC8 lw / @0xF61ECA li $a0,4 / @0xF61ECC and / @0xF61ECE beqz 0xF61ED4
       / @0xF61ED2 b: the teardown spins until bit2 clears. No ROM site ever sets it. */
    static constexpr uint32_t kEnableBusyBit = 0x4u;
    /* casio_cassiopeia_em500_ppc2000 wavedev.dll bit1 MONO: loc_F618CC @0xF61910 lhu / @0xF61914 or
       2 / @0xF61926 sh (stereo @0xF6191E lhu / @0xF61924 and 0xFFFD); sub_F616F4 @0xF6171A sh 3. */
    static constexpr uint32_t kOffFormat888 = 0x0888u;
    /* casio_cassiopeia_em500_ppc2000 wavedev.dll bit1 playback enable loc_F618CC @0xF6194E (|=2),
       cleared loc_F61EAC @0xF61F0C li 3 / @0xF61F0E neg / @0xF61F10 and; bit0 capture @0xF6277E. */
    static constexpr uint32_t kOffChan890 = 0x0890u;
    static constexpr uint32_t kChanCapture = 0x1u;
    static constexpr uint32_t kChanPlay    = 0x2u;
    /* casio_cassiopeia_em500_ppc2000 wavedev.dll bit0 transfer strobe: loc_F618CC @0xF6196E sw 1;
       cleared loc_F61EAC @0xF61EF8 lw / @0xF61EFA li 2 / @0xF61EFC neg / @0xF61F00 sw; re-strobed
       by the IST decode dword_F622D4 @0xF6238E. */
    static constexpr uint32_t kOffStrobe898 = 0x0898u;
    /* casio_cassiopeia_em500_ppc2000 wavedev.dll bit0 set loc_F62984 @0xF62A94 li 1 / @0xF62A98 sw,
       cleared sub_F614E4 @0xF614F8, loc_F61EAC @0xF61EBC, sub_F62520 @0xF6252E; read by
       nk_main_kernel.exe @0x9F0388CC lw / @0x9F0388D0 andi 1. */
    static constexpr uint32_t kOffLatch8A0 = 0x08A0u;
    /* casio_cassiopeia_em500_ppc2000 wavedev.dll dword_F622D4 @0xF622E4 lhu (IST decode). */
    static constexpr uint32_t kOffStatus8A8 = 0x08A8u;
    /* casio_cassiopeia_em500_ppc2000 wavedev.dll CURRENT start/end + NEXT start/end, end inclusive:
       sub_F615D8 @0xF615E4/@0xF615EE/@0xF615F8/@0xF61602 programs all four, sub_F61614
       @0xF61624/@0xF6162E only 0x8B8/0x8BC. */
    static constexpr uint32_t kOffDescLo = 0x08B0u;
    static constexpr uint32_t kOffDescHi = 0x08BCu;
    /* casio_cassiopeia_em500_ppc2000 wavedev.dll service gate, sub_F614E4 @0xF61512 sw 1; read by
       the IST decode dword_F622D4 @0xF622E0. */
    static constexpr uint32_t kOffGate8C4 = 0x08C4u;
    /* casio_cassiopeia_em500_ppc2000 wavedev.dll interrupt ack pair: sub_F614E4 @0xF61520 sw 0x11 /
       @0xF6151A sh 0x11, dword_F622D4 @0xF622EC/@0xF622F4 sh 0x11, sub_F62520 @0xF6259E/@0xF625A6
       sh 0x10 then @0xF625B0/@0xF625B8 sh 0x11. */
    static constexpr uint32_t kOffAckL8C8 = 0x08C8u;
    static constexpr uint32_t kOffAckR8CC = 0x08CCu;

    /* casio_cassiopeia_em500_ppc2000 wavedev.dll loc_F62984 @0xF629CE li $a2, 0x71 / neg ->
       0xFFFFFF8F, so the select is bits[6:4]. */
    static constexpr uint32_t kRateSelectMask = 0x70u;

    /* casio_cassiopeia_em500_ppc2000 wavedev.dll: every loc_F61998 converter stores with sh:
       @0xF61D3A (case 0, lbu source), @0xF61C92 (case 1, lh source), @0xF61BD0 + @0xF61BE6
       (case 2), @0xF61B04 + @0xF61B1A (case 3). */
    static constexpr uint16_t kBitsPerSample = 16u;

    /* sub_F615D8 @0xF615E4/@0xF615EE/@0xF615F8/@0xF61602 programs 0x8B0/0x8B4/
       0x8B8/0x8BC; sub_F61614 @0xF61624/@0xF6162E writes 0x8B8/0x8BC only. */
    static constexpr uint32_t kDescCurStart = 0;
    static constexpr uint32_t kDescCurEnd   = 1;
    static constexpr uint32_t kDescNextStart = 2;
    static constexpr uint32_t kDescNextEnd   = 3;

    /* loc_F62984 @0xF62A98 sw 1 -> 0x08A0, the last write of the start path;
       loc_F61EAC @0xF61EBC and sub_F62520 @0xF6252E write 0. */
    bool Running() const { return (reg_8A0_ & 0x1u) != 0u; }
    /* loc_F618CC @0xF6194E 0x0890 |= 2; loc_F61EAC @0xF61F0C li 3 / neg / and. */
    bool PlayEnabled() const { return (reg_890_ & kChanPlay) != 0u; }
    uint16_t Channels() const { return (reg_888_ & 0x2u) != 0u ? 1u : 2u; }

    struct Block {
        uint32_t va     = 0;
        uint32_t length = 0;
        uint64_t end    = 0;
    };

    uint32_t FrameBytes() const;
    void     OnLatchWrite(uint32_t value, uint32_t keep_mask);
    void     OnChannelWrite(uint32_t value);
    void     RequireStreamFormat(std::unique_lock<std::mutex>& lk);
    void     StartStream();
    void     StartTransfers();
    void     QueueDescriptor(uint32_t start_index);
    void     QueueHostBytes(uint32_t va, uint32_t length);
    void     ArmBlockEndLocked();
    void     OnRateChange();
    void     OnBlockEnd();
    void     OnResetLine();

    CerfEmulator* emu_ = nullptr;
    std::function<void()> on_irq_change_;
    PacedWaveOut paced_;

    GuestCycleClock*        clock_ = nullptr;
    GuestCycleClock::Event* event_ = nullptr;
    RatedTickCount          frames_;

    mutable std::mutex mtx_;

    uint32_t reg_880_ = 0;
    uint32_t reg_884_ = 0;
    uint32_t reg_888_ = 0;
    uint32_t reg_890_ = 0;
    uint32_t reg_898_ = 0;
    uint32_t reg_8A0_ = 0;
    uint32_t desc_[4] = {};
    uint32_t reg_8C4_ = 0;
    uint32_t reg_8C8_ = 0;
    uint32_t reg_8CC_ = 0;
    bool     rate_doubler_ = false;

    std::atomic<uint16_t> status_8A8_{0};

    /* wavedev.dll loc_F618CC @0xF61930 jal loc_F61998 ($a1=0) / @0xF61938 ($a1=1);
       sub_F615D8 @0xF615E4 0x8B0 / @0xF615EE 0x8B4 / @0xF615F8 0x8B8 / @0xF61602
       0x8BC; sub_F61614 @0xF61624 0x8B8 / @0xF6162E 0x8BC. */
    static constexpr uint32_t kMaxQueued = 2;
    Block    blocks_[kMaxQueued] = {};
    uint32_t queued_      = 0;
    bool     ran_dry_     = false;
    uint32_t rate_hz_     = 0;
    uint16_t channels_    = 0;
};
