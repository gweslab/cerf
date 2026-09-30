#include "sa1111_sac.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../boards/board_context.h"
#include "../../boards/jornada720/jornada_720_id.h"
#include "sa1111_intc.h"
#include "sa1111_sac_dma.h"
#include "sa1111_sac_host_output.h"
#include "sa1111_sac_l3.h"
#include "sa1111_sac_request_lines.h"
#include "sa1111_sac_rx_fifo.h"
#include "sa1111_sac_tx_stream.h"
#include "sa1111_sbi.h"
#include "sa1111_system_controller.h"
#include "../../host/audio_activity_widget.h"
#include "../../state/state_stream.h"

namespace {

constexpr uint32_t kSacr0Enb = 1u << 0;
constexpr uint32_t kSacr0Rst = 1u << 3;
constexpr uint32_t kSacr1Drec  = 1u << 3;
constexpr uint32_t kSacr1Drpl  = 1u << 4;
constexpr uint32_t kSacr1Enlbf = 1u << 5;
constexpr uint32_t kSacr0TfthShift = 8u;
constexpr uint32_t kSacr0TfthMask  = 0xFu << kSacr0TfthShift;
constexpr uint32_t kSacr0RfthShift = 12u;
constexpr uint32_t kSacr0RfthMask  = 0xFu << kSacr0RfthShift;

/* SA-1111 Developer's Manual Table 3-3 note 1: "All reserved bits are read back as zero."
   Table 7-7 SACR0 bits 0, 2, 3, 11:8, 15:12; Table 7-8 SACR1 bits 5:0. */
constexpr uint32_t kSacr0Defined = 0xFF0Du;
constexpr uint32_t kSacr1Defined = 0x3Fu;

}

bool Sa1111Sac::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::Jornada720;
}

void Sa1111Sac::OnUnitReady() {
    emu_.Get<AudioActivityWidget>().NotePresent();
    stream_ = &emu_.Get<Sa1111SacTxStream>();
    rx_     = &emu_.Get<Sa1111SacRxFifo>();
    lines_  = &emu_.Get<Sa1111SacRequestLines>();
    host_   = &emu_.Get<Sa1111SacHostOutput>();
    l3_     = &emu_.Get<Sa1111SacL3>();
    dma_    = &emu_.Get<Sa1111SacDma>();
    dma_->SetFifoControlReader([this] {
        return Sa1111SacDma::FifoControl{Enabled(), ThresholdLevel()};
    });
    emu_.Get<Sa1111Intc>().RegisterSampler(Sa1111SacRequestLines::kSourceMask,
                                           [this] { SyncRequestLines(); });
    emu_.Get<Sa1111SystemController>().RegisterClockListener([this] { OnSystemClockWrite(); });
    clock_ = &emu_.Get<GuestCycleClock>();
    clock_->RegisterRateListener([this] { ApplyFrameRate(clock_->Cycles()); });
    uint64_t num = 0, den = 1;
    emu_.Get<Sa1111SystemController>().AudioFrameRate(num, den);
    if (!stream_->SetRatio(clock_->CpuHz(), emu_.Get<Sa1111Sbi>().CasLatency(), num, den)) {
        emu_.Get<Fatal>().Die("Sa1111Sac: frame clock %llu/%llu Hz against the %llu Hz core "
                              "overflows the 64-bit scale", static_cast<unsigned long long>(num),
                              static_cast<unsigned long long>(den),
                              static_cast<unsigned long long>(clock_->CpuHz()));
    }
}

uint32_t Sa1111Sac::UnitReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    switch (off) {
        case 0x00: return sacr0_;
        case 0x04: return sacr1_;
        case 0x0C: {
            const uint64_t now = clock_->Cycles();
            return FifoStatus(now) | l3_->StatusBits(now);
        }
        case 0x10: return FifoStatus(clock_->Cycles());
        case 0x1C: return l3_->Address();
        case 0x20:
            emu_.Get<Fatal>().Die("Sa1111Sac: L3CDR read (an L3 read transfer) is not "
                                  "modelled");
        /* Table 7-9 note: SACR2 "power-up/reset default value of this register is 0000h";
           §2.3 zero for ACCAR, ACCDR and the read-only ACSAR (Tables 7-15 to 7-17). */
        case 0x08: case 0x24: case 0x28: case 0x2C: return 0u;
        case 0x34: case 0x38: case 0x3C: case 0x40: case 0x44:
        case 0x48: case 0x4C: case 0x50: case 0x54: case 0x58:
            return dma_->ReadRegister(off);
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Sa1111Sac::UnitWriteWord(uint32_t addr, uint32_t value) {
    WriteRegister(addr, value);
    PublishRequestLines(clock_->Cycles());
}

void Sa1111Sac::WriteRegister(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (off != 0x00u && RstActive()) {
        emu_.Get<Fatal>().Die("Sa1111Sac: write 0x%08X to +0x%02X with SACR0 RST active is not "
                              "modelled", value, off);
    }
    switch (off) {
        case 0x00: WriteSacr0(value); return;
        case 0x04: WriteSacr1(value); return;
        case 0x18:                                /* SASCR, Table 7-12. */
            if (value & (1u << 5)) {
                const uint64_t now = clock_->Cycles();
                dma_->CatchUp(now);
                stream_->ClearUnderrun(now);
            }
            if (value & (1u << 6))  rx_->ClearOverrun(stream_->Position(clock_->Cycles()));
            l3_->ClearStatus(clock_->Cycles(), value);
            return;
        case 0x1C: l3_->WriteAddress(clock_->Cycles(), value, sacr1_); return;
        case 0x20: l3_->WriteData(clock_->Cycles(), value, sacr1_); return;
        case 0x34: case 0x38: case 0x3C: case 0x40: case 0x44:
        case 0x48: case 0x4C: case 0x50: case 0x54: case 0x58:
            dma_->WriteRegister(off, value);
            return;
        case 0x5C:                                /* SAITR, Table 7-29: write-only. */
            if (value != 0u) HaltUnsupportedAccess("WriteWord", addr, value);
            return;
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

/* SA-1111 Developer's Manual Table 7-7 RST: "Reset the SAC Control and FIFOs except this
   register"; §7.4.1.1 Note: "The following bits are effective when the ENB bit is "1"". */
bool Sa1111Sac::RstActive() const {
    return (sacr0_ & (kSacr0Enb | kSacr0Rst)) == (kSacr0Enb | kSacr0Rst);
}

/* Table 7-8 note: SACR1 "The power-up/reset default value of this register is 0000h";
   §2.3: "Unless indicated otherwise, all register bits are set to zero during reset." */
void Sa1111Sac::ResetRegisters(uint64_t now, bool chip) {
    dma_->Reset();
    stream_->Clear(now);
    rx_->Clear(stream_->Position(now));
    l3_->Reset(now, chip);
    sacr1_ = 0u;
}

void Sa1111Sac::OnChipReset(bool held) {
    const uint64_t now = clock_->Cycles();
    if (held) {
        ResetRegisters(now, true);
        sacr0_ = kSacr0Reset;
        UpdateSerializer(now);
    } else {
        RescaleFrames(now);
    }
    PublishRequestLines(now);
}

void Sa1111Sac::WriteSacr0(uint32_t value) {
    const uint64_t now = clock_->Cycles();
    value &= kSacr0Defined;
    dma_->Evaluate(now);
    if (!RstActive() && (value & (kSacr0Enb | kSacr0Rst)) == (kSacr0Enb | kSacr0Rst)) {
        ResetRegisters(now, false);
    }
    if (dma_->TransmitRunning() && (((value ^ sacr0_) & kSacr0TfthMask) != 0u ||
                                    (value & (kSacr0Enb | kSacr0Rst)) != kSacr0Enb)) {
        emu_.Get<Fatal>().Die("Sa1111Sac: SACR0 write 0x%08X -> 0x%08X (a TFTH change, or the "
                              "SAC disabled) with the transmit DMA running is not modelled",
                              sacr0_, value);
    }
    sacr0_ = value;
    RequireI2sMode();
    UpdateSerializer(now);
    dma_->Evaluate(now);
}

void Sa1111Sac::WriteSacr1(uint32_t value) {
    if ((value & kSacr1Enlbf) != 0u) {
        emu_.Get<Fatal>().Die("Sa1111Sac: SACR1 ENLBF loop back (0x%08X) is not modelled",
                              value);
    }
    sacr1_ = value & kSacr1Defined;
    l3_->OnSacr1Write(clock_->Cycles(), sacr1_);
    UpdateSerializer(clock_->Cycles());
}

/* Table 7-10 TFS: "0 - Transmit FIFO level exceeds TFL threshold, or SAC disabled". */
bool Sa1111Sac::Enabled() const {
    return (sacr0_ & kSacr0Enb) != 0u && (sacr0_ & kSacr0Rst) == 0u;
}

/* Table 7-8 DRPL: "1 = Replaying Function is Disabled"; Table 7-7 ENB: "1 = Pins
   function as Serial Audio Controller". */
bool Sa1111Sac::SerializerWanted() const {
    return Enabled() && (sacr1_ & kSacr1Drpl) == 0u;
}

/* Table 7-8 DREC: "0 = Recording Function is Enabled". */
bool Sa1111Sac::RecordingWanted() const {
    return Enabled() && (sacr1_ & kSacr1Drec) == 0u;
}

/* Table 3-4 PLL_Bypass: "Bypass PLL, send input CLK direct to dividers; from SKCR". */
void Sa1111Sac::RequireFrameClock() const {
    if (!emu_.Get<Sa1111SystemController>().I2sClockEnabled()) {
        emu_.Get<Fatal>().Die("Sa1111Sac: serializer running with SKPCR I2SCLKEn clear is not "
                              "modelled");
    }
    const auto& sbi = emu_.Get<Sa1111Sbi>();
    if (sbi.PllClockRunning()) return;
    emu_.Get<Fatal>().Die("Sa1111Sac: serializer running with SKCR 0x%08X (PLL bypassed, VCO "
                          "off, Sleep or Doze) is not modelled", sbi.Skcr());
}

/* Table 3-9 SeLAC: "1 = AC Link"; §7.4.1.3: SACR2 controls the AC-link functions "when
   SACMDSL bit of SKCR selects AC-link mode". */
void Sa1111Sac::RequireI2sMode() const {
    if ((sacr0_ & kSacr0Enb) == 0u || emu_.Get<Sa1111Sbi>().I2sSelected()) return;
    emu_.Get<Fatal>().Die("Sa1111Sac: SACR0 ENB set (0x%08X) with SKCR SeLAC selecting the AC "
                          "link is not modelled", sacr0_);
}

void Sa1111Sac::UpdateSerializer(uint64_t now) {
    const bool play   = SerializerWanted();
    const bool record = RecordingWanted();
    if (play == stream_->Running() && record == rx_->Running()) return;
    dma_->Evaluate(now);
    if ((play && !stream_->Running()) || (record && !rx_->Running())) RequireFrameClock();
    const uint64_t pos = stream_->Position(now);
    if (record != rx_->Running()) {
        if (record) rx_->Start(pos);
        else        rx_->Stop(pos);
    }
    if (play != stream_->Running()) {
        if (play) stream_->Run(now);
        else      stream_->Hold(now);
    }
    dma_->Evaluate(now);
}

/* Table 7-7 TFTH: "This value should be set to the desired threshold value minus one." */
uint32_t Sa1111Sac::ThresholdLevel() const {
    return ((sacr0_ & kSacr0TfthMask) >> kSacr0TfthShift) + 1u;
}

/* Table 7-7 RFTH: "This value should be set to the desired threshold value minus one." */
uint32_t Sa1111Sac::RxThresholdLevel() const {
    return ((sacr0_ & kSacr0RfthMask) >> kSacr0RfthShift) + 1u;
}

/* Table 7-10 BSY: "1 - SAC currently transmitting or receiving a frame". */
uint32_t Sa1111Sac::FifoStatus(uint64_t now) {
    dma_->Evaluate(now);
    const uint64_t pos = stream_->Position(now);
    uint32_t status = stream_->StatusBits(now, Enabled(), ThresholdLevel()) |
                      rx_->StatusBits(pos, Enabled(), RxThresholdLevel());
    if (stream_->Running() || rx_->Running()) status |= 1u << 2;
    return status;
}

void Sa1111Sac::PublishRequestLines(uint64_t now) {
    dma_->CatchUp(now);
    lines_->Publish(now, Enabled(), ThresholdLevel(), RxThresholdLevel());
}

void Sa1111Sac::SyncRequestLines() { PublishRequestLines(clock_->Cycles()); }

void Sa1111Sac::RescaleFrames(uint64_t now) {
    uint64_t num = 0, den = 1;
    emu_.Get<Sa1111SystemController>().AudioFrameRate(num, den);
    if (!stream_->Rescale(now, clock_->CpuHz(), emu_.Get<Sa1111Sbi>().CasLatency(), num, den)) {
        emu_.Get<Fatal>().Die("Sa1111Sac: the transmit frame phase does not fit the %llu/%llu "
                              "Hz frame clock", static_cast<unsigned long long>(num),
                              static_cast<unsigned long long>(den));
    }
    host_->SetRate(num, den);
}

/* SA-1111 Developer's Manual §2.3 (printed 2-4): "When nRESET is asserted, all on-chip
   activity halts". */
void Sa1111Sac::ApplyFrameRate(uint64_t now) {
    dma_->Evaluate(now);
    if (!ChipHoldPending()) stream_->RequireInFlightTiming(now, clock_->CpuHz());
    RescaleFrames(now);
    dma_->Evaluate(now);
}

void Sa1111Sac::OnSystemClockWrite() {
    const uint64_t now = clock_->Cycles();
    RequireI2sMode();
    dma_->OnClockChange();
    if (stream_->Running() || rx_->Running()) RequireFrameClock();
    l3_->OnClockChange(now);
    ApplyFrameRate(now);
    PublishRequestLines(now);
}

void Sa1111Sac::SaveState(StateWriter& w) {
    const uint64_t now = clock_->Cycles();
    w.Write("sacr0", sacr0_); w.Write("sacr1", sacr1_);
    l3_->Save(w, now);
    dma_->Save(w, now);
    stream_->Save(w, now);
    rx_->Save(w, stream_->Position(now));
}

void Sa1111Sac::RestoreState(StateReader& r) {
    const uint64_t now = clock_->Cycles();
    r.Read("sacr0", sacr0_); r.Read("sacr1", sacr1_);
    l3_->Restore(r, now);
    dma_->Restore(r);
    stream_->Restore(r, now);
    rx_->Restore(r, stream_->Position(now));
}

void Sa1111Sac::PostRestore() {
    const uint64_t now = clock_->Cycles();
    RescaleFrames(now);
    lines_->Baseline(now, Enabled(), ThresholdLevel(), RxThresholdLevel());
    dma_->PostRestore();
}

REGISTER_SERVICE(Sa1111Sac);
