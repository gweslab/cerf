#include "siemens_mp377_sm501_audio_mcu.h"
#include "siemens_mp377_sm501_internal.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../socs/irq_controller.h"
#include "../../state/state_stream.h"

namespace siemens_mp377 {
namespace {

uint32_t AtomicUpdateByte(std::atomic<uint32_t>& target, uint32_t byte, uint8_t value) {
    const uint32_t mask = 0xFFu << (byte * 8u);
    const uint32_t bits = static_cast<uint32_t>(value) << (byte * 8u);
    uint32_t current = target.load(std::memory_order_acquire);
    uint32_t next = 0u;
    do {
        next = (current & ~mask) | bits;
    } while (!target.compare_exchange_weak(current, next, std::memory_order_acq_rel, std::memory_order_acquire));
    return next;
}

} // namespace

bool SiemensMp377Sm501AudioMcu::ShouldRegister() {
    auto* board = emu_.TryGet<BoardContext>();
    return board && board->GetBoard() == Board::SiemensMP377;
}

void SiemensMp377Sm501AudioMcu::OnReady() {
    ResetDevice();
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        if (emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) return;
        ResetDevice();
    });
}

bool SiemensMp377Sm501AudioMcu::IsControlRegister(uint32_t off) {
    return off >= kControlBase && off < kControlEnd;
}

bool SiemensMp377Sm501AudioMcu::IsSram(uint32_t off) {
    return off >= kProgramBase && off < kSramEnd;
}

bool SiemensMp377Sm501AudioMcu::IsProgramSram(uint32_t off) {
    return off >= kProgramBase && off < kProgramEnd;
}

bool SiemensMp377Sm501AudioMcu::IsEnabled() const {
    return enabled_.load(std::memory_order_acquire);
}

uint32_t SiemensMp377Sm501AudioMcu::ReadControl(uint32_t, uint32_t off) {
    std::lock_guard<std::recursive_mutex> lock(core_mutex_);
    auto& regs = emu_.Get<SiemensMp377Sm501Regs>();
    switch (off) {
    case kResetReg: return enabled_.load(std::memory_order_acquire) ? 1u : 0u;
    case kModeReg: return regs.regs_[kModeReg / 4u] & 0xFFu;
    case kToCpuIrqReg: {
        const uint32_t token = to_cpu_token_.load(std::memory_order_acquire);
        ClearProtocolInterrupt();
        return token;
    }
    case kFromCpuIrqReg: return from_cpu_token_.load(std::memory_order_acquire);
    default: emu_.Get<Fatal>().Die("[MP377 SM501 audio MCU] read of unmodelled control register 0x%X", off);
    }
}

uint32_t SiemensMp377Sm501AudioMcu::ReadSramWord(uint32_t address, uint32_t off) {
    std::lock_guard<std::recursive_mutex> lock(core_mutex_);
    auto& regs = emu_.Get<SiemensMp377Sm501Regs>();
    const bool mailbox_state = (off & ~3u) == (kMailboxReady & ~3u);
    /* siemens_mp377_v1040 SM501 8051 firmware: CODE:017C and CODE:03F5
       expose the two startup phases through XDATA 3FFF.  Synchronize the
       autonomous initialization at that documented host-visible boundary. */
    if (mailbox_state && IsEnabled() && AudioByte(kMailboxReady) == 0u)
        RunUntilMailboxReady(1u);
    if (IsProgramSram(off) && IsEnabled()) {
        LOG(Caution,
            "MP377 SM501 8051 SRAM: blocked host read while 8051 enabled pa=0x%08X off=0x%06X reset=0x%08X "
            "mode=0x%08X\n",
            address, off, regs.regs_[kResetReg / 4u], regs.regs_[kModeReg / 4u]);
        regs.HaltUnsupportedAccess("SM501 8051 program/data SRAM read while 8051 enabled", address, 0u);
    }
    const uint32_t value = regs.regs_[off / 4u];
    if (mailbox_state && AudioByte(kMailboxReady) == 1u)
        RunUntilMailboxReady(2u);
    if ((off & ~3u) == (kMailboxBusy & ~3u) && AudioByte(kMailboxBusy) != 0u) {
        /* siemens_mp377_v1040 VGXaudio sub_29880F8 polls XDATA 3FFD
           through the dual-port SRAM and requires the firmware-owned busy
           transition 1 -> 0 to remain observable by the host. */
        RunMailboxCommand();
    }
    return value;
}

void SiemensMp377Sm501AudioMcu::WriteControl(uint32_t off, uint32_t old_value, uint32_t value) {
    std::lock_guard<std::recursive_mutex> lock(core_mutex_);
    auto& regs = emu_.Get<SiemensMp377Sm501Regs>();
    switch (off) {
    case kResetReg: {
        const bool old_enabled = enabled_.load(std::memory_order_acquire);
        const bool enabled = (value & 1u) != 0u;
        enabled_.store(enabled, std::memory_order_release);
        regs.regs_[off / 4u] = enabled ? 1u : 0u;
        if (!enabled) {
            from_cpu_irq_pending_.store(false, std::memory_order_release);
            to_cpu_irq_pending_.store(false, std::memory_order_release);
            from_cpu_token_.store(0u, std::memory_order_release);
            to_cpu_token_.store(0u, std::memory_order_release);
            regs.regs_[kToCpuIrqReg / 4u] = 0u;
            regs.regs_[kFromCpuIrqReg / 4u] = 0u;
            regs.ClearSm501InterruptBits(kOutputIrqBit);
            Reset();
        } else if (!old_enabled) {
            Reset();
        }
        break;
    }
    case kModeReg: regs.regs_[off / 4u] = value & 0xFFu; break;
    case kToCpuIrqReg: regs.regs_[off / 4u] = old_value; break;
    case kFromCpuIrqReg:
        from_cpu_token_.store(value, std::memory_order_release);
        from_cpu_irq_pending_.store(true, std::memory_order_release);
        core_.SignalProtocolInterrupt();
        regs.regs_[off / 4u] = value;
        RunUntilMailboxBusy();
        break;
    default:
        emu_.Get<Fatal>().Die("[MP377 SM501 audio MCU] write of unmodelled control register "
                              "0x%X = 0x%08X",
                              off, value);
    }
}

void SiemensMp377Sm501AudioMcu::WriteSramWord(uint32_t address, uint32_t off, uint32_t old_value, uint32_t value) {
    std::lock_guard<std::recursive_mutex> lock(core_mutex_);
    auto& regs = emu_.Get<SiemensMp377Sm501Regs>();
    if (IsProgramSram(off) && IsEnabled()) {
        regs.regs_[off / 4u] = old_value;
        LOG(Caution,
            "MP377 SM501 8051 SRAM: blocked host write while 8051 enabled pa=0x%08X off=0x%06X old=0x%08X new=0x%08X "
            "reset=0x%08X mode=0x%08X\n",
            address, off, old_value, value, regs.regs_[kResetReg / 4u], regs.regs_[kModeReg / 4u]);
        regs.HaltUnsupportedAccess("SM501 8051 program/data SRAM write while 8051 enabled", address, value);
    }
}

uint8_t SiemensMp377Sm501AudioMcu::ReadSramByte(uint32_t offset) const {
    std::lock_guard<std::recursive_mutex> lock(core_mutex_);
    return AudioByte(offset);
}

void SiemensMp377Sm501AudioMcu::WriteSramByte(uint32_t offset, uint8_t value) {
    std::lock_guard<std::recursive_mutex> lock(core_mutex_);
    SetAudioByte(offset, value);
}

void SiemensMp377Sm501AudioMcu::Reset() {
    std::lock_guard<std::recursive_mutex> lock(core_mutex_);
    core_.Reset();
}

void SiemensMp377Sm501AudioMcu::ResetDevice() {
    std::lock_guard<std::recursive_mutex> lock(core_mutex_);
    auto& regs = emu_.Get<SiemensMp377Sm501Regs>();
    enabled_.store(false, std::memory_order_release);
    from_cpu_irq_pending_.store(false, std::memory_order_release);
    to_cpu_irq_pending_.store(false, std::memory_order_release);
    to_cpu_token_.store(0u, std::memory_order_release);
    from_cpu_token_.store(0u, std::memory_order_release);
    regs.regs_[kResetReg / 4u] = 0u;
    regs.regs_[kModeReg / 4u] = 0u;
    regs.regs_[kToCpuIrqReg / 4u] = 0u;
    regs.regs_[kFromCpuIrqReg / 4u] = 0u;
    regs.ClearSm501InterruptBits(kOutputIrqBit);
    Reset();
}

void SiemensMp377Sm501AudioMcu::RunSlice(uint32_t budget, bool clock_ac97) {
    if (!enabled_.load(std::memory_order_acquire)) return;
    if (budget > 65536u) budget = 65536u;
    uint32_t cycles = 0u;
    while (cycles < budget) cycles += StepCore(clock_ac97);
}

uint32_t SiemensMp377Sm501AudioMcu::StepCore(bool clock_ac97) {
    const uint32_t cycles = core_.Step(*this);
    if (clock_ac97) {
        const auto& regs = emu_.Get<SiemensMp377Sm501Regs>();
        const uint8_t mode = static_cast<uint8_t>(regs.regs_[kModeReg / 4u]);
        emu_.Get<SiemensMp377Sm501Ac97>().AdvanceMachineCycles(cycles, mode);
    }
    return cycles;
}

void SiemensMp377Sm501AudioMcu::RunMmioSlice(uint32_t budget) {
    std::lock_guard<std::recursive_mutex> lock(core_mutex_);
    /* SM501 Databook v1.02, chapters 6 and 11. */
    RunSlice(budget, false);
}

void SiemensMp377Sm501AudioMcu::RunUntilMailboxReady(uint8_t target) {
    std::lock_guard<std::recursive_mutex> lock(core_mutex_);
    /* Initialization contains nested 1000-by-200 software delay loops at
       CODE:0244..0291 and CODE:02AA..02F7. */
    constexpr uint64_t kInstructionWatchdog = 12800000u;
    const uint64_t first_instruction = core_.Executed();
    while (AudioByte(kMailboxReady) < target &&
           core_.Executed() - first_instruction < kInstructionWatchdog) {
        StepCore(true);
    }
    if (AudioByte(kMailboxReady) < target) {
        emu_.Get<Fatal>().Die(
            "[MP377 SM501 audio MCU] firmware startup watchdog ready=0x%02X target=0x%02X pc=0x%04X instructions=%llu",
            AudioByte(kMailboxReady), target, core_.ProgramCounter(),
            static_cast<unsigned long long>(core_.Executed() - first_instruction));
    }
}

void SiemensMp377Sm501AudioMcu::RunUntilMailboxBusy() {
    std::lock_guard<std::recursive_mutex> lock(core_mutex_);
    /* siemens_mp377_v1040 SM501 8051 firmware: CODE:003B dispatches the CPU
       protocol interrupt to CODE:0E9D and CODE:0E2C claims the mailbox by
       setting XDATA 3FFD. */
    constexpr uint64_t kInstructionWatchdog = 1000000u;
    const uint64_t first_instruction = core_.Executed();
    while (AudioByte(kMailboxBusy) == 0u &&
           core_.Executed() - first_instruction < kInstructionWatchdog) {
        StepCore(false);
    }
    if (AudioByte(kMailboxBusy) == 0u) {
        emu_.Get<Fatal>().Die(
            "[MP377 SM501 audio MCU] firmware did not accept mailbox cmd=0x%02X pc=0x%04X instructions=%llu",
            AudioByte(kMailboxCmd), core_.ProgramCounter(),
            static_cast<unsigned long long>(core_.Executed() - first_instruction));
    }
}

void SiemensMp377Sm501AudioMcu::RunMailboxCommand() {
    std::lock_guard<std::recursive_mutex> lock(core_mutex_);
    /* siemens_mp377_v1040 SM501 8051 firmware: CODE:0E9B releases XDATA
       3FFD after the command handler stores its result in XDATA 3FF1. */
    constexpr uint64_t kInstructionWatchdog = 1000000u;
    const uint64_t first_instruction = core_.Executed();
    const bool command_uses_ac97_frames = AudioByte(kMailboxCmd) == 0x0Fu;
    while (AudioByte(kMailboxBusy) != 0u &&
           core_.Executed() - first_instruction < kInstructionWatchdog)
        StepCore(command_uses_ac97_frames);
    if (AudioByte(kMailboxBusy) != 0u || AudioByte(kMailboxStatus) == 0u) {
        emu_.Get<Fatal>().Die(
            "[MP377 SM501 audio MCU] firmware mailbox watchdog cmd=0x%02X status=0x%02X busy=0x%02X pc=0x%04X instructions=%llu",
            AudioByte(kMailboxCmd), AudioByte(kMailboxStatus),
            AudioByte(kMailboxBusy), core_.ProgramCounter(),
            static_cast<unsigned long long>(core_.Executed() - first_instruction));
    }
}

void SiemensMp377Sm501AudioMcu::SignalAc97Interrupt() {
    std::lock_guard<std::recursive_mutex> lock(core_mutex_);
    /* siemens_mp377_v1040 SM501 8051 firmware: CODE:0043 vectors to the
       AC97 handler at CODE:08AF after CODE:0030 enables extended source 2. */
    core_.SignalAc97Interrupt();
}

void SiemensMp377Sm501AudioMcu::RunOneAc97Frame() {
    emu_.Get<SiemensMp377Sm501Ac97>().ClockFrame();
    constexpr uint64_t kInstructionWatchdog = 4096u;
    const uint64_t first_instruction = core_.Executed();
    bool entered = false;
    while (core_.Executed() - first_instruction < kInstructionWatchdog) {
        StepCore(false);
        entered = entered || core_.HighPriorityInterruptInService();
        if (entered && !core_.HighPriorityInterruptInService()) return;
    }
    emu_.Get<Fatal>().Die(
        "[MP377 SM501 audio MCU] AC97 frame watchdog pc=0x%04X instructions=%llu",
        core_.ProgramCounter(), static_cast<unsigned long long>(core_.Executed() - first_instruction));
}

void SiemensMp377Sm501AudioMcu::RunAc97Frames(uint32_t frames) {
    std::lock_guard<std::recursive_mutex> lock(core_mutex_);
    if (!IsEnabled()) return;
    /* SM501 MMCC Databook v1.02, chapters 11/12; siemens_mp377_v1040
       SM501 firmware CODE:09A2..0A43, XDATA 3FFCh/9008h. */
    for (uint32_t frame = 0u; frame < frames; ++frame) RunOneAc97Frame();
}

void SiemensMp377Sm501AudioMcu::SaveState(StateWriter& w) const {
    std::lock_guard<std::recursive_mutex> lock(core_mutex_);
    core_.SaveState(w);
    w.Write(enabled_.load(std::memory_order_acquire));
    w.Write(from_cpu_irq_pending_.load(std::memory_order_acquire));
    w.Write(to_cpu_irq_pending_.load(std::memory_order_acquire));
    w.Write(to_cpu_token_.load(std::memory_order_acquire));
    w.Write(from_cpu_token_.load(std::memory_order_acquire));
}

void SiemensMp377Sm501AudioMcu::RestoreState(StateReader& r) {
    std::lock_guard<std::recursive_mutex> lock(core_mutex_);
    core_.RestoreState(r);
    bool enabled = false;
    bool from_cpu_irq_pending = false;
    bool to_cpu_irq_pending = false;
    uint32_t to_cpu_token = 0u;
    uint32_t from_cpu_token = 0u;
    r.Read(enabled);
    r.Read(from_cpu_irq_pending);
    r.Read(to_cpu_irq_pending);
    r.Read(to_cpu_token);
    r.Read(from_cpu_token);
    enabled_.store(enabled, std::memory_order_release);
    from_cpu_irq_pending_.store(from_cpu_irq_pending, std::memory_order_release);
    to_cpu_irq_pending_.store(to_cpu_irq_pending, std::memory_order_release);
    to_cpu_token_.store(to_cpu_token, std::memory_order_release);
    from_cpu_token_.store(from_cpu_token, std::memory_order_release);
}

void SiemensMp377Sm501AudioMcu::Fault(const char* what, uint32_t detail) {
    emu_.Get<Fatal>().Die("[MP377 SM501 audio MCU] 8051 %s 0x%02X at PC 0x%04X", what,
                          detail, core_.ProgramCounter());
}

uint8_t SiemensMp377Sm501AudioMcu::FetchCode(uint16_t address) const {
    const auto& regs = emu_.Get<SiemensMp377Sm501Regs>();
    /* SM501 Databook v1.02, Appendix B-1, Figure 12-2. */
    const uint16_t sram_address = static_cast<uint16_t>(address & 0x3FFFu);
    return static_cast<uint8_t>(regs.regs_[(kProgramBase + sram_address) / 4u] >> ((sram_address & 3u) * 8u));
}

uint8_t SiemensMp377Sm501AudioMcu::ReadExternal(uint16_t address) {
    auto& regs = emu_.Get<SiemensMp377Sm501Regs>();
    if (address < 0x4000u) return AudioByte(kProgramBase + address);
    if (address >= 0x9004u && address < 0x9010u) {
        const uint32_t byte = address & 3u;
        switch (address & ~3u) {
        case 0x9004u: return static_cast<uint8_t>(regs.regs_[kModeReg / 4u] >> (byte * 8u));
        case 0x9008u: return static_cast<uint8_t>(to_cpu_token_.load(std::memory_order_acquire) >> (byte * 8u));
        case 0x900Cu: {
            const uint8_t value = static_cast<uint8_t>(from_cpu_token_.load(std::memory_order_acquire) >> (byte * 8u));
            if (byte == 0u) {
                from_cpu_irq_pending_.store(false, std::memory_order_release);
            }
            return value;
        }
        }
    }
    if (address >= 0x9100u && address < 0x9184u) {
        return emu_.Get<SiemensMp377Sm501Ac97>().ReadByte(SiemensMp377Sm501Ac97::kBase + address - 0x9100u,
                                                          address == 0x9181u);
    }
    emu_.Get<Fatal>().Die("[MP377 SM501 8051] XREAD of unmodelled address 0x%04X at PC 0x%04X", address,
                          core_.ProgramCounter());
}

void SiemensMp377Sm501AudioMcu::WriteExternal(uint16_t address, uint8_t value) {
    auto& regs = emu_.Get<SiemensMp377Sm501Regs>();
    if (address < 0x4000u) {
        SetAudioByte(kProgramBase + address, value);
        /* siemens_mp377_v1040 SM501 8051 firmware command 07,
           CODE:0F46..0F6D, XDATA 3FF1. */
        if (address == static_cast<uint16_t>(kMailboxStatus - kProgramBase) && value != 0u) {
            const uint8_t command = AudioByte(kMailboxCmd);
            if (command == 0x07u)
                emu_.Get<SiemensMp377Sm501AudioOutput>().SetPlaybackEnabled(AudioByte(kMailboxArg0) != 0u);
            else if (command == 0x0Eu)
                emu_.Get<SiemensMp377Sm501AudioOutput>().SetCaptureEnabled(AudioByte(kMailboxArg0) != 0u);
        }
        return;
    }
    if (address >= 0x9004u && address < 0x9010u) {
        const uint32_t byte = address & 3u;
        switch (address & ~3u) {
        case 0x9004u: {
            uint32_t mode = regs.regs_[kModeReg / 4u];
            mode = (mode & ~(0xFFu << (byte * 8u))) | (static_cast<uint32_t>(value) << (byte * 8u));
            regs.regs_[kModeReg / 4u] = mode & 0xFFu;
            return;
        }
        case 0x9008u: {
            const uint32_t token = AtomicUpdateByte(to_cpu_token_, byte, value);
            regs.regs_[kToCpuIrqReg / 4u] = token;
            /* SM501 Databook v1.02 page 12-5: writing bits 7:0 generates
               the 8051 Protocol Interrupt, independent of the token value. */
            if (byte == 0u) {
                to_cpu_irq_pending_.store(true, std::memory_order_release);
                regs.RaiseSm501InterruptBits(kOutputIrqBit);
            }
            return;
        }
        case 0x900Cu: return;
        }
    }
    if (address >= 0x9100u && address < 0x9184u) {
        emu_.Get<SiemensMp377Sm501Ac97>().WriteByte(SiemensMp377Sm501Ac97::kBase + address - 0x9100u, value);
        return;
    }
    emu_.Get<Fatal>().Die("[MP377 SM501 8051] XWRITE of unmodelled address 0x%04X = 0x%02X "
                          "at PC 0x%04X",
                          address, value, core_.ProgramCounter());
}

uint8_t SiemensMp377Sm501AudioMcu::AudioByte(uint32_t off) const {
    const auto& regs = emu_.Get<SiemensMp377Sm501Regs>();
    return static_cast<uint8_t>(regs.regs_[(off & ~3u) / 4u] >> ((off & 3u) * 8u));
}

void SiemensMp377Sm501AudioMcu::SetAudioByte(uint32_t off, uint8_t value) {
    auto& regs = emu_.Get<SiemensMp377Sm501Regs>();
    auto& word = regs.regs_[(off & ~3u) / 4u];
    const uint32_t shift = (off & 3u) * 8u;
    word = (word & ~(0xFFu << shift)) | (static_cast<uint32_t>(value) << shift);
}

void SiemensMp377Sm501AudioMcu::ClearProtocolInterrupt() {
    auto& regs = emu_.Get<SiemensMp377Sm501Regs>();
    regs.ClearSm501InterruptBits(kOutputIrqBit);
    to_cpu_irq_pending_.store(false, std::memory_order_release);
}

REGISTER_SERVICE(SiemensMp377Sm501AudioMcu);

} // namespace siemens_mp377
