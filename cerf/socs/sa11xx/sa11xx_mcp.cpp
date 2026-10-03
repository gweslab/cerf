#include "sa11xx_mcp.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../boards/board_context.h"
#include "sa1110_id.h"
#include "sa1100_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "sa11xx_dma.h"
#include "sa11xx_mcp_audio_stream.h"
#include "sa11xx_mcp_codec.h"
#include "sa11xx_ppc.h"

#include <algorithm>

namespace {

constexpr uint32_t kMccr0Mce = 1u << 16;

/* SA-1110 Developer's Manual §11.12.5.3 MCDR2 (printed 11-143 to 11-145): data 15:0, R/W 16,
   codec register address 20:17; §11.12.6.13 / §11.12.6.14 MCSR CWC 12, CRC 13. */
constexpr uint32_t kMcdr2Write     = 1u << 16;
constexpr uint32_t kMcdr2AddrShift = 17;
constexpr uint32_t kCwc            = 1u << 12;
constexpr uint32_t kCrc            = 1u << 13;

/* §11.12.1.1: subframe 0 is the first 64 SCLK of a frame. */
constexpr uint64_t kSubframe0Ticks = 64u;

}

bool Sa11xxMcp::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && (bd->GetSocId() == SocId::Sa1110 || bd->GetSocId() == SocId::Sa1100);
}

void Sa11xxMcp::OnReady() {
    clock_ = &emu_.Get<GuestCycleClock>();
    dma_   = &emu_.Get<Sa11xxDma>();
    audio_ = &emu_.Get<Sa11xxMcpAudioStream>();
    cmd_ev_ = clock_->Add([this] {
        const uint64_t now = clock_->Cycles();
        SettleCommand(now);
        ArmCommand(now);
    });
    clock_->RegisterRateListener([this] { ArmCommand(clock_->Cycles()); });
    emu_.Get<Sa11xxPpc>().RegisterMccr1Listener([this] { ControlChanged(); });
    /* SA-1110 Developer's Manual §11.12.3.11 (printed 11-137): "the MCE bit is the only control
       bit that is reset to a known state"; MCSR reset row (printed 11-149): CRC 0, CWC 0. */
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        mccr0_    &= ~kMccr0Mce;
        cmd_valid_ = false;
        cwc_       = false;
        crc_       = false;
        clock_->Disarm(cmd_ev_);
    });
    emu_.Get<PeripheralDispatcher>().Register(this);
}

void Sa11xxMcp::ControlChanged() {
    const uint64_t now = clock_->Cycles();
    SettleCommand(now);
    audio_->WriteControl(now, mccr0_, emu_.Get<Sa11xxPpc>().Mccr1());
    SettleCommand(now);
    ArmCommand(now);
    dma_->OnPortChange();
    for (auto& fn : control_listeners_) fn();
}

void Sa11xxMcp::RegisterControlListener(std::function<void()> fn) {
    control_listeners_.push_back(std::move(fn));
}

/* §11.12.6.13: CWC after the written value "is returned to the MCP via the next subframe 0";
   §11.12.6.14: CRC when the value read "is returned to the MCP via the same subframe 0". */
uint64_t Sa11xxMcp::CompletionOffset(bool write) const {
    return kSubframe0Ticks + (write ? Sa11xxMcpAudioStream::kFrameTicks : 0u);
}

/* §11.12.5.3 (printed 11-144): "the operation is performed every MCP data frame until a new value
   is written to the register"; §11.12.1.1: the first frame starts as the MCP is enabled. */
void Sa11xxMcp::SettleCommand(uint64_t now) {
    uint64_t t = 0;
    if (!cmd_valid_ || !audio_->SclkTick(now, t)) return;
    if (cmd_run_ != audio_->Run()) {
        cmd_run_   = audio_->Run();
        cmd_first_ = CompletionOffset(cmd_write_);
        cmd_clear_ = 0u;
    }
    const uint64_t carry = cmd_first_ - CompletionOffset(cmd_write_);
    if (t >= carry) cmd_sent_ = true;
    auto* codec = emu_.TryGet<Sa11xxMcpCodec>();
    /* Figure 11-31 (printed 11-129): "The register is updated with the write at the end of
       subframe" 0 of the frame that carries it. */
    if (cmd_write_ && !cmd_applied_ && t >= carry + kSubframe0Ticks) {
        if (codec) codec->WriteReg(cmd_reg_, cmd_value_);
        cmd_applied_ = true;
    }
    if (t < cmd_first_) return;
    const uint64_t frame = Sa11xxMcpAudioStream::kFrameTicks;
    const uint64_t last  = cmd_first_ + (t - cmd_first_) / frame * frame;
    if (!cmd_write_) cmd_value_ = codec ? codec->ReadReg(cmd_reg_) : 0u;
    mcdr2_ = (static_cast<uint32_t>(cmd_reg_) << kMcdr2AddrShift) | cmd_value_;
    if (last <= cmd_clear_) return;
    if (cmd_write_) cwc_ = true;
    else            crc_ = true;
}

void Sa11xxMcp::ArmCommand(uint64_t now) {
    uint64_t t = 0;
    if (!cmd_valid_ || !cmd_write_ || cmd_applied_ || cmd_first_ == kNever ||
        cmd_run_ != audio_->Run() || !audio_->SclkTick(now, t)) {
        clock_->Disarm(cmd_ev_);
        return;
    }
    const uint64_t apply = cmd_first_ - CompletionOffset(true) + kSubframe0Ticks;
    clock_->Arm(cmd_ev_, std::max(audio_->CycleOfSclk(apply), now));
}

/* §11.12.6.13 / §11.12.6.14: CWC and CRC are "automatically cleared when MCDR2 is read or
   written". */
void Sa11xxMcp::ClearCompletion(uint64_t now) {
    SettleCommand(now);
    cwc_ = false;
    crc_ = false;
    uint64_t t = 0;
    cmd_clear_ = audio_->SclkTick(now, t) ? t : 0u;
}

uint32_t Sa11xxMcp::ReadWord(uint32_t addr) {
    const uint64_t now = clock_->Cycles();
    switch (addr - MmioBase()) {
        case 0x00: return mccr0_;
        case 0x08:
            emu_.Get<Fatal>().Die("Sa11xxMcp: MCDR0 read; programmed I/O from the audio receive "
                                  "FIFO is not modelled");
        case 0x0C:
            emu_.Get<Fatal>().Die("Sa11xxMcp: MCDR1 read; the telecom path is not modelled");
        case 0x10: {
            SettleCommand(now);
            /* §11.12.5.3 MCDR2 15:0 (printed 11-144): "If a codec write was last performed, contains
               data of previous register access; next frame contains the data that was written." */
            uint64_t t = 0;
            if (cmd_valid_ && cmd_write_ && cmd_first_ != kNever && audio_->SclkTick(now, t) &&
                t + Sa11xxMcpAudioStream::kFrameTicks >= cmd_first_ && t < cmd_first_) {
                emu_.Get<Fatal>().Die("Sa11xxMcp: MCDR2 read inside the frame that returns the "
                                      "previous contents of codec register %u; not modelled",
                                      cmd_reg_);
            }
            const uint32_t value = mcdr2_;
            ClearCompletion(now);
            return value;
        }
        case 0x18:
            SettleCommand(now);
            return audio_->Status(now) | (cwc_ ? kCwc : 0u) | (crc_ ? kCrc : 0u);
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void Sa11xxMcp::WriteWord(uint32_t addr, uint32_t value) {
    switch (addr - MmioBase()) {
        case 0x00:
            mccr0_ = value;
            ControlChanged();
            return;
        case 0x08:
            emu_.Get<Fatal>().Die("Sa11xxMcp: MCDR0 write 0x%08X; programmed I/O into the audio "
                                  "transmit FIFO is not modelled", value);
        case 0x0C:
            emu_.Get<Fatal>().Die("Sa11xxMcp: MCDR1 write 0x%08X; the telecom path is not "
                                  "modelled", value);
        case 0x10: RouteCodecCommand(value); return;
        case 0x18: audio_->ClearStatus(clock_->Cycles(), value); return;
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

/* §11.12.1.4 (printed 11-131): the MCDR2 contents "are transferred to the correct fields within
   the serial shifter on the next rising edge of the SFRM signal". */
void Sa11xxMcp::RouteCodecCommand(uint32_t cmd) {
    const uint64_t now = clock_->Cycles();
    ClearCompletion(now);
    uint64_t t = 0;
    const bool running = audio_->SclkTick(now, t);
    if (cmd_valid_ && (!cmd_sent_ || (cmd_write_ && !cmd_applied_))) {
        emu_.Get<Fatal>().Die("Sa11xxMcp: MCDR2 0x%08X replaces a codec command that has not reached "
                              "the codec yet; not modelled", cmd);
    }
    const uint8_t  reg      = static_cast<uint8_t>((cmd >> kMcdr2AddrShift) & 0xFu);
    const bool     is_write = (cmd & kMcdr2Write) != 0u;
    const uint16_t value    = is_write ? static_cast<uint16_t>(cmd & 0xFFFFu) : 0u;
    if (is_write && audio_->CodecWrite(now, reg, value)) dma_->OnPortChange();
    cmd_valid_   = true;
    cmd_write_   = is_write;
    cmd_sent_    = false;
    cmd_applied_ = !is_write;
    cmd_reg_     = reg;
    cmd_value_   = value;
    cmd_run_     = running ? audio_->Run() : 0u;
    cmd_first_   = running ? audio_->NextFrameEdge(now) + CompletionOffset(is_write) : kNever;
    cmd_clear_   = running ? t : 0u;
    ArmCommand(now);
}

void Sa11xxMcp::SaveState(StateWriter& w) {
    SettleCommand(clock_->Cycles());
    w.Write("mccr0", mccr0_);
    w.Write<uint8_t>("cmd_valid", cmd_valid_ ? 1u : 0u);
    w.Write<uint8_t>("cmd_write", cmd_write_ ? 1u : 0u);
    w.Write<uint8_t>("cmd_sent", cmd_sent_ ? 1u : 0u);
    w.Write<uint8_t>("cmd_applied", cmd_applied_ ? 1u : 0u);
    w.Write("cmd_reg", cmd_reg_);
    w.Write("cmd_value", cmd_value_);
    w.Write("cmd_run", cmd_run_);
    w.Write("cmd_first", cmd_first_);
    w.Write("cmd_clear", cmd_clear_);
    w.Write<uint8_t>("cmd_cwc", cwc_ ? 1u : 0u);
    w.Write<uint8_t>("cmd_crc", crc_ ? 1u : 0u);
    w.Write("mcdr2", mcdr2_);
    audio_->Save(w);
    if (auto* codec = emu_.TryGet<Sa11xxMcpCodec>()) codec->SaveState(w);
}

void Sa11xxMcp::RestoreState(StateReader& r) {
    uint8_t valid = 0, write = 0, sent = 0, applied = 0, cwc = 0, crc = 0;
    r.Read("mccr0", mccr0_);
    r.Read("cmd_valid", valid);
    r.Read("cmd_write", write);
    r.Read("cmd_sent", sent);
    r.Read("cmd_applied", applied);
    r.Read("cmd_reg", cmd_reg_);
    r.Read("cmd_value", cmd_value_);
    r.Read("cmd_run", cmd_run_);
    r.Read("cmd_first", cmd_first_);
    r.Read("cmd_clear", cmd_clear_);
    r.Read("cmd_cwc", cwc);
    r.Read("cmd_crc", crc);
    r.Read("mcdr2", mcdr2_);
    cmd_valid_ = valid != 0u;
    cmd_write_ = write != 0u;
    cmd_sent_  = sent != 0u;
    cmd_applied_ = applied != 0u;
    cwc_       = cwc != 0u;
    crc_       = crc != 0u;
    audio_->Restore(r);
    if (auto* codec = emu_.TryGet<Sa11xxMcpCodec>()) codec->RestoreState(r);
}

void Sa11xxMcp::PostRestore() {
    if (auto* codec = emu_.TryGet<Sa11xxMcpCodec>()) codec->PostRestore();
    audio_->RefreshLine(clock_->Cycles());
    ArmCommand(clock_->Cycles());
}

REGISTER_SERVICE(Sa11xxMcp);
