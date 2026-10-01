#include "imx31_kpp.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../guest_cpu_reset.h"
#include "imx31_avic.h"
#include "imx31_ccm.h"
#include "imx31_id.h"

#include <cstdint>
#include <mutex>

namespace {

constexpr uint32_t kBase = 0x43FA8000u;
constexpr uint32_t kKpcr = 0x00u;
constexpr uint32_t kKpsr = 0x02u;
constexpr uint32_t kKddr = 0x04u;
constexpr uint32_t kKpdr = 0x06u;

/* KPSR fields - MCIMX31RM Table 27-6. */
constexpr uint16_t kKpkd = 0x0001u;
constexpr uint16_t kKpkr = 0x0002u;
constexpr uint16_t kKdsc = 0x0004u;
constexpr uint16_t kKrss = 0x0008u;
constexpr uint16_t kKdie = 0x0100u;
constexpr uint16_t kKrie = 0x0200u;

constexpr uint16_t kMatrixRows = 0x001Fu;

/* MCIMX31RM Table 27-6: the synchronizer delay is 4 cycles of the 32 kHz clock. */
constexpr uint32_t kSyncCkilCycles = 4u;

constexpr uint32_t kAvicSourceKpp = 24u;

}

REGISTER_SERVICE(Imx31Kpp);

bool Imx31Kpp::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Imx31;
}

void Imx31Kpp::OnReady() {
    clock_      = &emu_.Get<GuestCycleClock>();
    sync_event_ = clock_->Add([this] { OnSync(); });
    clock_->RegisterRateListener([this] { Retime(); });
    host_requests_ = &emu_.Get<HostRequestChannel>();
    host_requests_->RegisterListener([this] { OnHostKeys(); });
    {
        std::lock_guard<std::mutex> lk(mtx_);
        SetRatio();
        const uint64_t now = clock_->Cycles();
        ckil_.Anchor(now, 0u);
        ArmSyncLocked(now);
    }
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) { ResetRegisters(); });
    emu_.Get<PeripheralDispatcher>().Register(this);
}

/* MCIMX31RM Table 27-2: KPCR, KPSR and KDDR reset to 0; 27.3.3.4: KPDR is not
   initialized by a reset. Table 27-6 KPKR: after reset de-asserts it follows the rows. */
void Imx31Kpp::ResetRegisters() {
    std::lock_guard<std::mutex> lk(mtx_);
    kpcr_         = 0u;
    kpsr_         = 0u;
    kddr_         = 0u;
    pending_kpsr_ = 0u;
    depress_out_  = false;
    release_out_  = true;
    ArmSyncLocked(clock_->Cycles());
    ApplyIrqLocked();
}

void Imx31Kpp::SetRatio() {
    if (!ckil_.SetRatio(clock_->CpuHz(), emu_.Get<Imx31Ccm>().CkilHz())) {
        emu_.Get<Fatal>().Die("Imx31Kpp: CKIL %llu Hz against the %llu Hz core clock "
                              "does not reduce",
                              static_cast<unsigned long long>(emu_.Get<Imx31Ccm>().CkilHz()),
                              static_cast<unsigned long long>(clock_->CpuHz()));
    }
}

void Imx31Kpp::Retime() {
    std::lock_guard<std::mutex> lk(mtx_);
    const uint64_t now = clock_->Cycles();
    if (!ckil_.Rescale(now, clock_->CpuHz(), emu_.Get<Imx31Ccm>().CkilHz())) {
        emu_.Get<Fatal>().Die("Imx31Kpp: CKIL rescale to the %llu Hz core clock does not "
                              "reduce", static_cast<unsigned long long>(clock_->CpuHz()));
    }
    ArmEventLocked(now);
}

uint16_t Imx31Kpp::RowSenseLocked() const {
    uint16_t rows = kMatrixRows;
    for (uint8_t c = 0; c < 4; ++c)
        if (((kpdr_col_ >> (8u + c)) & 1u) == 0u)
            rows &= static_cast<uint16_t>(~pressed_[c]);
    return rows;
}

bool Imx31Kpp::AnyEnabledRowLowLocked() const {
    return (static_cast<uint16_t>(~RowSenseLocked()) & kMatrixRows & kpcr_) != 0u;
}

void Imx31Kpp::ArmSyncLocked(uint64_t now) {
    sync_tick_    = ckil_.CountAt(now) + kSyncCkilCycles;
    sync_pending_ = true;
    ArmEventLocked(now);
}

void Imx31Kpp::ArmEventLocked(uint64_t now) {
    if (pending_kpsr_ != 0u) {
        clock_->Arm(sync_event_, now);
    } else if (sync_pending_) {
        const int32_t ahead = static_cast<int32_t>(sync_tick_ - ckil_.CountAt(now));
        clock_->Arm(sync_event_, ckil_.CycleOfTick(ckil_.TicksSince(now) +
                                                   static_cast<uint64_t>(ahead > 0 ? ahead : 0)));
    } else {
        clock_->Disarm(sync_event_);
    }
}

void Imx31Kpp::CaptureDueLocked(uint64_t now) {
    if (!sync_pending_ || !clock_->IsDue(sync_event_, now)) return;
    const uint16_t before = kpsr_;
    EvaluateChainsLocked();
    pending_kpsr_ = static_cast<uint16_t>(pending_kpsr_ | (kpsr_ & ~before));
    kpsr_         = before;
    sync_pending_ = false;
}

/* MCIMX31RM Table 27-6: KPKD sets when an enabled row is detected low after
   synchronization, KPKR when all enabled rows are detected high after it. */
void Imx31Kpp::EvaluateChainsLocked() {
    const bool low = AnyEnabledRowLowLocked();
    if (!depress_out_ && low) kpsr_ |= kKpkd;
    if (release_out_ && !low) kpsr_ |= kKpkr;
    depress_out_ = low;
    release_out_ = low;
}

void Imx31Kpp::OnSync() {
    std::lock_guard<std::mutex> lk(mtx_);
    const uint64_t now = clock_->Cycles();
    kpsr_         = static_cast<uint16_t>(kpsr_ | pending_kpsr_);
    pending_kpsr_ = 0u;
    if (sync_pending_ && static_cast<int32_t>(ckil_.CountAt(now) - sync_tick_) >= 0) {
        sync_pending_ = false;
        EvaluateChainsLocked();
    }
    ArmEventLocked(now);
    ApplyIrqLocked();
}

void Imx31Kpp::DriveIrqLocked() {
    auto& avic = emu_.Get<Imx31Avic>();
    if (irq_on_) avic.AssertSource(kAvicSourceKpp);
    else         avic.DeassertSource(kAvicSourceKpp);
}

void Imx31Kpp::ApplyIrqLocked() {
    const bool desired = ((kpsr_ & kKpkd) && (kpsr_ & kKdie)) ||
                         ((kpsr_ & kKpkr) && (kpsr_ & kKrie));
    if (desired == irq_on_) return;
    irq_on_ = desired;
    DriveIrqLocked();
}

uint16_t Imx31Kpp::ReadReg16Locked(uint32_t off) {
    switch (off) {
        case kKpcr: return kpcr_;
        case kKpsr: return kpsr_ & (kKpkd | kKpkr | kKdie | kKrie);
        case kKddr: return kddr_;
        case kKpdr: return static_cast<uint16_t>(kpdr_col_ | RowSenseLocked());
    }
    HaltUnsupportedAccess("ReadReg16", kBase + off, 0);
}

void Imx31Kpp::WriteReg16Locked(uint32_t off, uint16_t value) {
    CaptureDueLocked(clock_->Cycles());
    const bool low_before = AnyEnabledRowLowLocked();
    bool resync = false;
    switch (off) {
        case kKpcr: kpcr_ = value; break;
        case kKpsr:
            kpsr_ = static_cast<uint16_t>(kpsr_ & ~(value & (kKpkd | kKpkr)));
            pending_kpsr_ = static_cast<uint16_t>(pending_kpsr_ & ~(value & (kKpkd | kKpkr)));
            kpsr_ = static_cast<uint16_t>((kpsr_ & ~(kKdie | kKrie)) |
                                          (value & (kKdie | kKrie)));
            if ((value & kKdsc) != 0u) { depress_out_ = false; resync = true; }
            if ((value & kKrss) != 0u) { release_out_ = true;  resync = true; }
            break;
        case kKddr: kddr_ = value; break;
        case kKpdr: kpdr_col_ = value & 0xFF00u; break;
        default: HaltUnsupportedAccess("WriteReg16", kBase + off, value);
    }
    if (resync || AnyEnabledRowLowLocked() != low_before) ArmSyncLocked(clock_->Cycles());
    ApplyIrqLocked();
}

void Imx31Kpp::SetMatrixKey(uint8_t col, uint8_t row, bool pressed) {
    if (col >= 4u || row >= 5u) {
        emu_.Get<Fatal>().Die("Imx31Kpp: key cell col=%u row=%u is outside the 4x5 matrix",
                              col, row);
    }
    {
        std::lock_guard<std::mutex> lk(mtx_);
        const uint8_t bit = static_cast<uint8_t>(1u << row);
        if (((host_pressed_[col] & bit) != 0) == pressed) return;
        if (pressed) host_pressed_[col] |= bit;
        else         host_pressed_[col] &= static_cast<uint8_t>(~bit);
    }
    host_requests_->Request();
}

/* MCIMX31RM Table 27-6: a row change reaches KPKD / KPKR through the synchronizer. */
void Imx31Kpp::OnHostKeys() {
    std::lock_guard<std::mutex> lk(mtx_);
    CaptureDueLocked(clock_->Cycles());
    const bool low_before = AnyEnabledRowLowLocked();
    bool changed = false;
    for (uint8_t c = 0; c < 4; ++c) {
        changed |= pressed_[c] != host_pressed_[c];
        pressed_[c] = host_pressed_[c];
    }
    if (!changed) return;
    if (AnyEnabledRowLowLocked() != low_before) ArmSyncLocked(clock_->Cycles());
}

uint8_t Imx31Kpp::ReadByte(uint32_t addr) {
    const uint32_t off = (addr - kBase) & ~1u;
    std::lock_guard<std::mutex> lk(mtx_);
    const uint16_t v = ReadReg16Locked(off);
    return ((addr & 1u) ? (v >> 8) : v) & 0xFFu;
}

void Imx31Kpp::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off = (addr - kBase) & ~1u;
    std::lock_guard<std::mutex> lk(mtx_);
    uint16_t v = ReadReg16Locked(off);
    if ((addr & 1u) != 0u) {
        v = static_cast<uint16_t>((v & 0x00FFu) | (uint16_t(value) << 8));
        if (off == kKpsr) v = static_cast<uint16_t>(v & ~(kKpkd | kKpkr));
    } else {
        v = static_cast<uint16_t>((v & 0xFF00u) | value);
    }
    WriteReg16Locked(off, v);
}

uint16_t Imx31Kpp::ReadHalf(uint32_t addr) {
    std::lock_guard<std::mutex> lk(mtx_);
    return ReadReg16Locked(addr - kBase);
}

void Imx31Kpp::WriteHalf(uint32_t addr, uint16_t value) {
    std::lock_guard<std::mutex> lk(mtx_);
    WriteReg16Locked(addr - kBase, value);
}

uint32_t Imx31Kpp::ReadWord(uint32_t addr) {
    const uint32_t off = addr - kBase;
    std::lock_guard<std::mutex> lk(mtx_);
    return ReadReg16Locked(off) | (uint32_t(ReadReg16Locked(off + 2)) << 16);
}

void Imx31Kpp::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - kBase;
    std::lock_guard<std::mutex> lk(mtx_);
    WriteReg16Locked(off, static_cast<uint16_t>(value & 0xFFFFu));
    WriteReg16Locked(off + 2, static_cast<uint16_t>(value >> 16));
}

void Imx31Kpp::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(mtx_);
    const uint64_t now = clock_->Cycles();
    w.Write("kpcr", kpcr_);
    w.Write("kpsr", kpsr_);
    w.Write("kddr", kddr_);
    w.Write("kpdr_col", kpdr_col_);
    w.WriteBytes("pressed", pressed_, sizeof(pressed_));
    w.Write<uint8_t>("depress_out", depress_out_ ? 1u : 0u);
    w.Write<uint8_t>("release_out", release_out_ ? 1u : 0u);
    w.Write<uint8_t>("sync_pending", sync_pending_ ? 1u : 0u);
    w.Write("sync_tick", sync_tick_);
    w.Write("ckil_count", ckil_.CountAt(now));
    w.Write("ckil_phase", ckil_.PhaseAt(now));
    w.Write("ckil_phase_den", ckil_.PhaseDenominator());
}

void Imx31Kpp::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(mtx_);
    uint8_t depress = 0, release = 0, pending = 0;
    r.Read("kpcr", kpcr_);
    r.Read("kpsr", kpsr_);
    r.Read("kddr", kddr_);
    r.Read("kpdr_col", kpdr_col_);
    r.ReadBytes("pressed", pressed_, sizeof(pressed_));
    r.Read("depress_out", depress);
    r.Read("release_out", release);
    r.Read("sync_pending", pending);
    r.Read("sync_tick", sync_tick_);
    r.Read("ckil_count", restored_count_);
    r.Read("ckil_phase", restored_phase_);
    r.Read("ckil_phase_den", restored_den_);
    depress_out_  = depress != 0u;
    release_out_  = release != 0u;
    sync_pending_ = pending != 0u;
    pending_kpsr_ = 0u;
    const bool low_saved = AnyEnabledRowLowLocked();
    for (uint8_t c = 0; c < 4; ++c) {
        pressed_[c]      = 0u;
        host_pressed_[c] = 0u;
    }
    if (AnyEnabledRowLowLocked() != low_saved) {
        sync_tick_    = restored_count_ + kSyncCkilCycles;
        sync_pending_ = true;
    }
    clock_->Disarm(sync_event_);
}

void Imx31Kpp::PostRestore() {
    std::lock_guard<std::mutex> lk(mtx_);
    const uint64_t now = clock_->Cycles();
    SetRatio();
    ckil_.AnchorAtPhase(now, restored_count_, restored_phase_, restored_den_);
    ArmEventLocked(now);
    irq_on_ = ((kpsr_ & kKpkd) && (kpsr_ & kKdie)) || ((kpsr_ & kKpkr) && (kpsr_ & kKrie));
    DriveIrqLocked();
}
