#include "../../peripherals/usb/usb_state.h"
#include "imx51_usboh3.h"
#include "imx51_usb_device_transfers.h"
#include "usb_device_host.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "imx51_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "imx51_usb_transceiver_clocks.h"
#include "../guest_cpu_reset.h"
#include "../irq_controller.h"

#include <array>
#include <cstdint>

namespace {

constexpr uint32_t kBase = 0x73F80000u;

constexpr uint32_t kOffUsbcmd   = 0x00000140u;  /* USBCMD within each core */
constexpr uint32_t kUsbcmdReset = 1u << 1;      /* USBCMD.RST */
constexpr uint32_t kOffCaplen   = 0x00000100u;  /* CAPLENGTH(b0)+HCIVERSION(b16) */
/* CAPLENGTH 0x40 (operational regs at cap+0x40) | HCIVERSION 0x0100 (EHCI 1.00). */
constexpr uint32_t kCapReset = 0x01000040u;
/* EHCI 1.0 Spec Table 2-5 (p13) + Table 2-6 (p14, N_PORTS bits 3:0). */
constexpr uint32_t kOffHcsparams = kOffCaplen + 0x04u;
constexpr uint32_t kHcsparamsOnePort = 1u;
/* MCIMX51RM §60.4.2.4.4 HCCPARAMS "Default Value: 0006h"; Table 60-87 USBCMD "00080B00h if
   Asynchronous Schedule Park Capability is a one". */
constexpr uint32_t kOffHccparams = kOffCaplen + 0x08u;
constexpr uint32_t kHccparamsBorn = 0x00000006u;
constexpr uint32_t kUsbcmdBorn    = 0x00080B00u;

constexpr uint32_t kOffUsbsts = 0x00000144u;  /* USBSTS (=USBCMD+4) */
constexpr uint32_t kCmdRs  = 1u << 0;   /* USBCMD.RS  Run/Stop */
constexpr uint32_t kCmdPse = 1u << 4;   /* USBCMD.PSE */
constexpr uint32_t kCmdAse = 1u << 5;   /* USBCMD.ASE */
constexpr uint32_t kStsHch = 1u << 12;  /* USBSTS.HCH (RO; set when RS=0) */
constexpr uint32_t kStsPss = 1u << 14;  /* USBSTS.PS  (RO==PSE) */
constexpr uint32_t kStsAss = 1u << 15;  /* USBSTS.AS  (RO==ASE) */
constexpr uint32_t kUsbstsRoMask = kStsHch | (1u << 13) | kStsPss | kStsAss;

constexpr uint32_t kOffUlpiview = 0x00000170u;
constexpr uint32_t kUlpiWu  = 1u << 31;
constexpr uint32_t kUlpiRun = 1u << 30;
constexpr uint32_t kUlpiRw  = 1u << 29;

/* Device-controller registers within the OTG core (MCIMX51RM Ch 60 Table 60-2). */
constexpr uint32_t kOffUsbmode      = 0x000001A8u;
constexpr uint32_t kUsbmodeCmMask   = 0x3u;
constexpr uint32_t kUsbmodeDevice   = 0x2u;   /* CM=10: device controller */
constexpr uint32_t kOffPortsc       = 0x00000184u;
constexpr uint32_t kPortscCcs       = 1u << 0;
constexpr uint32_t kPortscPe        = 1u << 2;
constexpr uint32_t kPortscHsp       = 1u << 9;
constexpr uint32_t kPortscPspdShift = 26;
constexpr uint32_t kPortscPspdHs    = 0x2u << kPortscPspdShift;
constexpr uint32_t kPortscDevAttached =
    kPortscCcs | kPortscPe | kPortscHsp | kPortscPspdHs;

/* EHCI 1.0 Spec Table 2-16 (p27), PP field: with HCSPARAMS.PPC=0 (no port
   power switches, kHcsparamsOnePort below) PP is RO and hard-wired to 1 -
   "port power is always available". Host-mode PORTSC1 must reflect this on
   every read, or guest port-reset gating that requires PP=1 never opens. */
constexpr uint32_t kPortscPp = 1u << 12;

constexpr uint32_t kOffPhyCtrl0  = 0x00000808u;
constexpr uint32_t kOffUsbCtrl1  = 0x00000810u;
/* MCIMX51RM Figure 60-4 (PHY_CTRL_0 reset row). */
constexpr uint32_t kPhyCtrl0Born = 0x80001400u;

constexpr uint32_t kOffUsbintr       = 0x00000148u;
constexpr uint32_t kOffFrindex       = 0x0000014Cu;
constexpr uint32_t kOffEndptlistaddr = 0x00000158u;  /* dQH array base (2 KB aligned) */
constexpr uint32_t kOffEndptsetupstat= 0x000001ACu;  /* per-EP setup-received (w1c) */
constexpr uint32_t kOffEndptprime    = 0x000001B0u;  /* per-ep-dir prime (self-clear) */
constexpr uint32_t kOffEndptflush    = 0x000001B4u;
constexpr uint32_t kOffEndptcomplete = 0x000001BCu;  /* per-ep-dir complete (w1c) */
/* USBSTS device interrupt bits (MCIMX51RM Ch 60, p2896-2897). */
constexpr uint32_t kStsUi  = 1u << 0;   /* USB transaction complete */
constexpr uint32_t kStsUei = 1u << 1;   /* error */
constexpr uint32_t kStsPci = 1u << 2;   /* port change detect */
constexpr uint32_t kStsUri = 1u << 6;   /* USB reset received */
constexpr uint32_t kDevIntBits = kStsUi | kStsUei | kStsPci | kStsUri;
constexpr uint32_t kFrameStatusBits =
    FreescaleUsbFrameIndex::kStsSri | FreescaleUsbFrameIndex::kStsFri;
constexpr uint32_t kUsbOtgIrq = 18u;    /* TZIC source 18 (SBOOT sub_8005DC4C) */

constexpr uint8_t kUsb3317Id[4] = {0x24u, 0x04u, 0x06u, 0x00u};

}  /* namespace */

REGISTER_SERVICE(Imx51Usboh3);

bool Imx51Usboh3::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Imx51;
}

void Imx51Usboh3::OnReady() {
    for (auto& phy : phy_)
        for (uint8_t i = 0; i < 4; ++i) phy[i] = kUsb3317Id[i];
    emu_.Get<PeripheralDispatcher>().Register(this);
    transfers_   = &emu_.Get<Imx51UsbDeviceTransfers>();
    clock_       = &emu_.Get<GuestCycleClock>();
    frame_event_ = clock_->Add([this] { OnScheduleTimer(); });
    irq_event_   = clock_->Add([this] { OnFrameIrqEvent(); });
    frame_index_.Attach();
    transceiver_clocks_ = &emu_.Get<Imx51UsbTransceiverClocks>();
    transceiver_clocks_->RegisterChangeListener([this](FreescaleLowPowerMode mode) {
        std::lock_guard<std::mutex> lk(async_schedule_mtx_);
        RefreshTransceiverClocks(mode);
    });
    clock_->RegisterRateListener([this] { OnCpuRateChanged(); });
    /* MCIMX51RM Table 54-10: system_rst_b "Resets functional modules" in every reset row. */
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        std::lock_guard<std::mutex> lk(async_schedule_mtx_);
        ResetController();
        RefreshDeviceIrq();
    });
    ResetController();
}

void Imx51Usboh3::ResetController() {
    regs_.fill(0u);
    for (uint32_t core = 0; core < kNonCore; core += kCoreSpan) {
        regs_[(core + kOffCaplen) >> 2]    = kCapReset;
        regs_[(core + kOffHccparams) >> 2] = kHccparamsBorn;
        regs_[(core + kOffUsbcmd) >> 2]    = kUsbcmdBorn;
        /* Out of reset the host controller is halted (Table 60-40/41). */
        regs_[(core + kOffUsbsts) >> 2] = kStsHch;
    }
    regs_[kOffHcsparams >> 2] = kHcsparamsOnePort;
    regs_[kOffPhyCtrl0 >> 2]  = kPhyCtrl0Born;
    reset_seen_ = false;
    frame_index_.ResetAll();
    clock_->Disarm(irq_event_);
    frames_running_ = false;
    UpdateScheduleTimer();
    /* MCIMX51RM Table 60-52 CCS: "This value reflects the current state of the port". */
    if (otg_host_root_port_.IsConnected()) OnPortConnectChanged(0);
}

/* MCIMX51RM §60.4.5.4.1: micro-frame starts are "timed precisely to 125 us using the
   transceiver clock as a reference clock". */
void Imx51Usboh3::RefreshTransceiverClocks(FreescaleLowPowerMode mode) {
    bool changed = false;
    for (uint32_t core = 0; core < kCores; ++core) {
        if (!frame_index_.Running(core)) continue;
        const bool on = transceiver_clocks_->CoreClockRuns(
            core, regs_[(core * kCoreSpan + kOffPortsc) >> 2], regs_[kOffPhyCtrl0 >> 2],
            regs_[kOffUsbCtrl1 >> 2], mode);
        if (on == frame_index_.Clocked(core)) continue;
        frame_index_.SetClocked(core, on);
        changed = true;
    }
    if (!changed) return;
    UpdateScheduleTimer();
    ArmFrameIrq();
}

void Imx51Usboh3::UpdateScheduleTimer() {
    const auto cmd = regs_[kOffUsbcmd >> 2];
    if (Core0IsDevice() || !otg_host_root_port_.IsConnected() || !frame_index_.Clocked(0u) ||
        !(cmd & kCmdRs) || !(cmd & (kCmdAse | kCmdPse))) {
        frames_running_ = false;
        clock_->Disarm(frame_event_);
        return;
    }
    if (frames_running_) return;
    frames_running_ = true;
    ArmNextFrame();
}

void Imx51Usboh3::ArmNextFrame() {
    clock_->Arm(frame_event_, frame_index_.NextFrameCycle(0u));
}

void Imx51Usboh3::OnScheduleTimer() {
    std::lock_guard<std::mutex> lk(async_schedule_mtx_);
    ExecuteAsyncSchedule();
    ExecutePeriodicSchedule();
    ArmNextFrame();
}

void Imx51Usboh3::OnCpuRateChanged() {
    std::lock_guard<std::mutex> lk(async_schedule_mtx_);
    frame_index_.Rescale();
    ArmFrameIrq();
    if (!frames_running_) return;
    const uint64_t now = clock_->Cycles();
    if (!clock_->IsDue(frame_event_, now)) ArmNextFrame();
}

uint32_t Imx51Usboh3::MmioBase() const { return kBase; }
uint32_t Imx51Usboh3::MmioSize() const { return kSize; }

uint8_t Imx51Usboh3::ReadByte(uint32_t addr) {
    std::lock_guard<std::mutex> lk(async_schedule_mtx_);
    const uint32_t off = addr - kBase;
    return static_cast<uint8_t>(ReadLocked(off & ~3u) >> ((off & 3u) * 8u));
}
uint16_t Imx51Usboh3::ReadHalf(uint32_t addr) {
    std::lock_guard<std::mutex> lk(async_schedule_mtx_);
    const uint32_t off = addr - kBase;
    return static_cast<uint16_t>(ReadLocked(off & ~3u) >> ((off & 2u) * 8u));
}
uint32_t Imx51Usboh3::ReadWord(uint32_t addr) {
    std::lock_guard<std::mutex> lk(async_schedule_mtx_);
    return ReadLocked(addr - kBase);
}

uint32_t Imx51Usboh3::ReadLocked(uint32_t off) {
    /* Device mode (core0): CERF is the always-present host, so PORTSC1 reflects a
       connected, enabled, high-speed device port (sub_8005D97C polls it). */
    if (off == kOffPortsc && Core0IsDevice())
        return regs_[off >> 2] | kPortscDevAttached;
    if (off >= kNonCore) return regs_[off >> 2];
    const uint32_t coff = off % kCoreSpan;
    const uint32_t core = off / kCoreSpan;
    if (coff == kOffPortsc && !Core0IsDevice())
        return regs_[off >> 2] | kPortscPp;
    if (coff == kOffUsbsts) return regs_[off >> 2] | frame_index_.Status(core);
    if (coff == kOffFrindex) return frame_index_.Frindex(core);
    return regs_[off >> 2];
}

void Imx51Usboh3::WriteCoreFrameReg(uint32_t off, uint32_t value) {
    if ((off % kCoreSpan) != kOffFrindex) return;
    const uint32_t core = off / kCoreSpan;
    if (core == 0u && Core0IsDevice()) return;
    if (frame_index_.Running(core)) {
        emu_.Get<Fatal>().Die("Imx51Usboh3: FRINDEX write 0x%08X on core %u with Run/Stop set",
                              value, core);
    }
    frame_index_.WriteFrindex(core, value);
    ArmFrameIrq();
}

void Imx51Usboh3::WriteWord(uint32_t addr, uint32_t value) {
    std::lock_guard<std::mutex> lk(async_schedule_mtx_);
    const uint32_t off = addr - kBase;
    if (off < kNonCore) {
        const uint32_t coff = off % kCoreSpan;
        const bool core0_dev = off < kCoreSpan && Core0IsDevice();
        WriteCoreFrameReg(off, value);
        if (coff == kOffFrindex) return;
        if (coff == kOffUsbcmd) {
            if ((value & kUsbcmdReset) != 0u) {
                if (frame_index_.Running(off / kCoreSpan)) {
                    emu_.Get<Fatal>().Die("Imx51Usboh3: USBCMD 0x%08X sets RST on core %u "
                                          "with Run/Stop set", value, off / kCoreSpan);
                }
                frame_index_.Reset(off / kCoreSpan);
            }
            value &= ~kUsbcmdReset;   /* RST self-clears at reset completion */
            const uint32_t old = regs_[off >> 2];
            regs_[off >> 2] = value;
            frame_index_.SetFrameListSize(off / kCoreSpan,
                                          FreescaleUsbFrameIndex::FrameListSizeCode(value));
            frame_index_.SetRunning(off / kCoreSpan, (value & kCmdRs) != 0u, !core0_dev);
            RefreshTransceiverClocks(FreescaleLowPowerMode::kRun);
            if (core0_dev) {
                /* RS 0->1: CERF (host) attaches and drives a bus reset ->
                   USBSTS.URI|PCI, raising the OTG interrupt. */
                if ((value & kCmdRs) && !(old & kCmdRs))
                    regs_[kOffUsbsts >> 2] |= kStsUri | kStsPci;
                RefreshDeviceIrq();
            } else {
                ReflectScheduleStatus(off, value);
            }
            if (off < kCoreSpan) UpdateScheduleTimer();
            if (off < kCoreSpan && !core0_dev) RefreshDeviceIrq();
            ArmFrameIrq();
            return;
        }
        if (coff == kOffUsbsts) {
            const uint32_t old = regs_[off >> 2];
            regs_[off >> 2] = (old & kUsbstsRoMask) | (old & ~kUsbstsRoMask & ~value);
            frame_index_.ClearStatus(off / kCoreSpan,
                                     value & kFrameStatusBits);
            if (core0_dev) {
                RefreshDeviceIrq();
                /* URI cleared marks the start of SBOOT's reset handler
                   (sub_8005D554); it clears ENDPTSETUPSTAT next, so enumeration
                   must wait until the handler's ENDPTFLUSH write below - a SETUP
                   delivered here would have its ENDPTSETUPSTAT wiped. */
                if ((old & kStsUri) && (value & kStsUri))
                    reset_seen_ = true;
            } else if (off < kCoreSpan) {
                RefreshDeviceIrq();
            }
            ArmFrameIrq();
            return;
        }
        if (coff == kOffUsbintr) {
            regs_[off >> 2] = value;
            if (off < kCoreSpan) RefreshDeviceIrq();
            ArmFrameIrq();
            return;
        }
        if (core0_dev && (coff == kOffEndptsetupstat || coff == kOffEndptcomplete)) {
            regs_[off >> 2] &= ~value;   /* write-1-clear */
            return;
        }
        if (core0_dev && coff == kOffEndptprime) {
            ExecutePrime(value);
            regs_[off >> 2] = 0;         /* prime self-clears once serviced */
            return;
        }
        if (core0_dev && coff == kOffEndptflush) {
            regs_[off >> 2] = 0;
            /* The reset handler's ENDPTFLUSH is the first one after URI; by here
               it has already cleared ENDPTSETUPSTAT, so the host can deliver its
               first SETUP and it will survive to the next ISR. */
            if (reset_seen_) {
                reset_seen_ = false;
                if (UsbDeviceHost* host = transfers_->Host()) host->OnDeviceReset();
            }
            return;
        }
        if (coff == kOffUlpiview) {
            regs_[off >> 2] = UlpiTransfer(off / kCoreSpan, value);
            return;
        }
        if (off < kCoreSpan && !core0_dev && coff == kOffPortsc) {
            WriteOtgHostPortsc(value);
            RefreshTransceiverClocks(FreescaleLowPowerMode::kRun);
            return;
        }
    }
    regs_[off >> 2] = value;
    if (off == kOffUsbmode) UpdateScheduleTimer();
    if (off == kOffPhyCtrl0 || off == kOffUsbCtrl1 ||
        (off < kNonCore && off % kCoreSpan == kOffPortsc)) {
        RefreshTransceiverClocks(FreescaleLowPowerMode::kRun);
    }
}

void Imx51Usboh3::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(async_schedule_mtx_);
    w.WriteBytes("regs", regs_.data(), sizeof(regs_));
    w.WriteBytes("phy", phy_.data(), sizeof(phy_));
    w.Write<uint8_t>("reset_seen", reset_seen_ ? 1 : 0);
    frame_index_.Save(w);
    if (UsbDeviceHost* host = transfers_->Host()) host->SaveState(w);
    otg_host_root_port_.SaveState(w);
}
void Imx51Usboh3::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(async_schedule_mtx_);
    r.ReadBytes("regs", regs_.data(), sizeof(regs_));
    r.ReadBytes("phy", phy_.data(), sizeof(phy_));
    uint8_t b = 0; r.Read("reset_seen", b); reset_seen_ = b != 0;
    frame_index_.Restore(r);
    if (UsbDeviceHost* host = transfers_->Host()) host->RestoreState(r);
    otg_host_root_port_.RestoreState(r);
    clock_->Disarm(frame_event_);
    clock_->Disarm(irq_event_);
}

void Imx51Usboh3::PostRestore() {
    std::lock_guard<std::mutex> lk(async_schedule_mtx_);
    otg_host_root_port_.PostRestore();
    RefreshTransceiverClocks(FreescaleLowPowerMode::kRun);
    RefreshDeviceIrq();
    frames_running_ = false;
    clock_->Disarm(frame_event_);
    UpdateScheduleTimer();
    ArmFrameIrq();
}

bool Imx51Usboh3::Core0IsDevice() const {
    return (regs_[kOffUsbmode >> 2] & kUsbmodeCmMask) == kUsbmodeDevice;
}

/* MCIMX51RM Table 60-42: SRE and FRE raise the interrupt while SRI or FRI is set. */
void Imx51Usboh3::RefreshDeviceIrq() {
    const uint32_t sts = regs_[kOffUsbsts >> 2] | frame_index_.Status(0u);
    const bool pending = (sts & regs_[kOffUsbintr >> 2] &
                          (kDevIntBits | kFrameStatusBits)) != 0;
    auto& intc = emu_.Get<IrqController>();
    if (pending) intc.AssertIrq(static_cast<int>(kUsbOtgIrq));
    else         intc.DeAssertIrq(static_cast<int>(kUsbOtgIrq));
}

void Imx51Usboh3::ArmFrameIrq() {
    uint64_t due = FreescaleUsbFrameIndex::kNever;
    for (uint32_t core = 0; core < kCores; ++core) {
        const uint32_t enabled =
            regs_[(core * kCoreSpan + kOffUsbintr) >> 2] & kFrameStatusBits;
        if (enabled == 0u) continue;
        const uint64_t at = frame_index_.NextStatusCycle(core, enabled);
        if (at < due) due = at;
    }
    if (due == FreescaleUsbFrameIndex::kNever) clock_->Disarm(irq_event_);
    else                                   clock_->Arm(irq_event_, due);
}

void Imx51Usboh3::OnFrameIrqEvent() {
    std::lock_guard<std::mutex> lk(async_schedule_mtx_);
    for (uint32_t core = 1; core < kCores; ++core) {
        const uint32_t live = frame_index_.Status(core) &
                              regs_[(core * kCoreSpan + kOffUsbintr) >> 2] & kFrameStatusBits;
        if (live != 0u) {
            emu_.Get<Fatal>().Die("Imx51Usboh3: core %u USBSTS 0x%X meets USBINTR 0x%08X; "
                                  "that core's interrupt line is not modeled", core, live,
                                  regs_[(core * kCoreSpan + kOffUsbintr) >> 2]);
        }
    }
    RefreshDeviceIrq();
    ArmFrameIrq();
}

void Imx51Usboh3::ReflectScheduleStatus(uint32_t usbcmd_off, uint32_t usbcmd) {
    const uint32_t i = (usbcmd_off >> 2) + 1;  /* USBSTS = USBCMD + 4 */
    uint32_t s = regs_[i];
    s = (usbcmd & kCmdAse) ? (s | kStsAss) : (s & ~kStsAss);
    s = (usbcmd & kCmdPse) ? (s | kStsPss) : (s & ~kStsPss);
    s = (usbcmd & kCmdRs)  ? (s & ~kStsHch) : (s | kStsHch);
    regs_[i] = s;
}

uint32_t Imx51Usboh3::UlpiTransfer(uint32_t core, uint32_t value) {
    if (value & kUlpiWu)      return value & ~kUlpiWu;
    if (!(value & kUlpiRun))  return value;
    auto& phy = phy_[core % kCores];
    const uint8_t addr = static_cast<uint8_t>(value >> 16) & (kPhyRegCount - 1);
    if (value & kUlpiRw) {
        phy[addr] = static_cast<uint8_t>(value);
        return value & ~kUlpiRun;
    }
    return (value & ~kUlpiRun & ~0xFF00u) | (static_cast<uint32_t>(phy[addr]) << 8);
}

uint32_t Imx51Usboh3::DqhBase() const {
    return regs_[kOffEndptlistaddr >> 2] & ~0x7FFu;
}

void Imx51Usboh3::RegisterDeviceHost(UsbDeviceHost* host) {
    transfers_->SetHost(host);
}

void Imx51Usboh3::DeliverSetup(const uint8_t setup[8]) {
    if (!transfers_->WriteSetup(DqhBase(), setup)) return;
    regs_[kOffEndptsetupstat >> 2] |= 1u;
    regs_[kOffUsbsts >> 2] |= kStsUi;
    RefreshDeviceIrq();
}

void Imx51Usboh3::ExecutePrime(uint32_t prime_bits) {
    const uint32_t done = transfers_->ExecutePrime(DqhBase(), prime_bits);
    if (done == 0u) return;
    regs_[kOffEndptcomplete >> 2] |= done;
    regs_[kOffUsbsts >> 2] |= kStsUi;
    RefreshDeviceIrq();
}
