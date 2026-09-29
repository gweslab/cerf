#include "imx31_ipu.h"

#include "../../core/bit_field.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "imx31_id.h"
#include "imx31_avic.h"
#include "imx31_ccm.h"
#include "../../host/host_window.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"

namespace {

/* IPU_CONF enables, MCIMX31RM Fig 44-8 / Table 44-17. SDC_EN bit 4, DI_EN bit 6.
   Recovery drives the panel via DI alone (DI_EN set, SDC_EN clear) - gating the
   display-active check on SDC_EN only leaves the recovery splash blank. */
constexpr uint32_t kIpuConfSdcEnBit = 1u << 4;
constexpr uint32_t kIpuConfDiEnBit  = 1u << 6;
constexpr uint32_t kIpuConfDisplayOn = kIpuConfSdcEnBit | kIpuConfDiEnBit;

/* MCIMX31RM Table 44-14. */
constexpr uint32_t kIpuConfOff    = 0x000u;
constexpr uint32_t kBuf0RdyOff    = 0x004u;
constexpr uint32_t kBuf1RdyOff    = 0x008u;
constexpr uint32_t kDbModeSelOff  = 0x00Cu;
constexpr uint32_t kCurBufOff     = 0x010u;
constexpr uint32_t kImaAddrOff    = 0x020u;
constexpr uint32_t kImaDataOff    = 0x024u;
constexpr uint32_t kIntCtrl1Off   = 0x028u;
constexpr uint32_t kIntCtrl2Off   = 0x02Cu;
constexpr uint32_t kIntCtrl3Off   = 0x030u;
constexpr uint32_t kIntStat1Off   = 0x03Cu;
constexpr uint32_t kIdmacChaEnOff = 0x0A8u;
constexpr uint32_t kIdmacBusyOff  = 0x0B0u;
constexpr uint32_t kSdcComConfOff = 0x0B4u;
constexpr uint32_t kSdcBgPosOff   = 0x0C0u;
constexpr uint32_t kSdcHorOff     = 0x0D0u;
constexpr uint32_t kSdcVerOff     = 0x0D4u;
constexpr uint32_t kDiHspClkPerOff = 0x134u;
constexpr uint32_t kDiDisp3TimeOff = 0x15Cu;
constexpr uint32_t kDiDispAccCcOff = 0x1B4u;

constexpr uint32_t kBgChannel = 14u;
constexpr uint32_t kBgBit     = 1u << kBgChannel;

/* MCIMX31RM Figure 44-25: SDC_BG_EOF bit 1, SDC_DISP3_VSYNC bit 16. */
constexpr uint32_t kStat3SdcBgEof = 1u << 1;
constexpr uint32_t kStat3Vsync    = 1u << 16;

/* MCIMX31RM Figure 44-53 / Table 44-72. */
constexpr uint32_t kComBgEn = 1u << 9;

/* MCIMX31RM Table 3-14: CGR1 CG11 gates the IPU. */
constexpr uint32_t kCgr1Ipu = 11u;

/* MCIMX31RM Table 2-3: 41 IPU error, 42 IPU general interrupt. */
constexpr uint32_t kAvicIpuError   = 41u;
constexpr uint32_t kAvicIpuGeneral = 42u;

struct ResetEntry { uint32_t off; uint32_t value; };
constexpr ResetEntry kNonZeroResets[] = {
    { 0x08Cu, 0x20002000u },
    { 0x090u, 0x20002000u },
    { 0x094u, 0x20002000u },
    { 0x0E0u, 0x20200420u },
    { 0x160u, 0x0000FFFFu }, { 0x164u, 0x0000FFFFu }, { 0x168u, 0x0000FFFFu },
    { 0x16Cu, 0x0000FFFFu }, { 0x170u, 0x0000FFFFu }, { 0x174u, 0x0000FFFFu },
    { 0x178u, 0x0000FFFFu }, { 0x17Cu, 0x0000FFFFu }, { 0x180u, 0x0000FFFFu },
    { 0x184u, 0x0000FFFFu }, { 0x188u, 0x0000FFFFu }, { 0x18Cu, 0x0000FFFFu },
    { 0x190u, 0x0000FFFFu }, { 0x194u, 0x0000FFFFu }, { 0x198u, 0x0000FFFFu },
    { 0x19Cu, 0x0000FFFFu }, { 0x1A0u, 0x0000FFFFu }, { 0x1A4u, 0x0000FFFFu },
    { 0x1A8u, 0x0000FFFFu }, { 0x1ACu, 0x0000FFFFu }, { 0x1B0u, 0x0000FFFFu },
};

enum class Kind { RW, ROnly, W1C };

Kind ClassifyOffset(uint32_t off) {
    if (off == 0x01Cu) return Kind::ROnly;
    if (off == 0x058u) return Kind::ROnly;
    if (off == 0x0B0u) return Kind::ROnly;
    if (off >= 0x03Cu && off <= 0x04Cu) return Kind::W1C;
    return Kind::RW;
}

bool OffsetToSlot(uint32_t off, uint32_t kLast, uint32_t* slot_out) {
    if (off > kLast || (off & 0x3u) != 0u) return false;
    *slot_out = off / 4u;
    return true;
}

}

bool Imx31Ipu::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Imx31;
}

void Imx31Ipu::OnReady() {
    cpm_ = &emu_.Get<Imx31IpuCpm>();
    AttachScanClock();
    auto& ccm = emu_.Get<Imx31Ccm>();
    ccm.RegisterRateListener([this] { OnScanSourceClockChange(); });
    ccm.RegisterGate1Listener([this] {
        std::lock_guard<std::mutex> lk(state_mtx_);
        if (ScanActiveLocked()) RequireIpuClockLocked(FreescaleLowPowerMode::kRun, "a CGR1 write");
    });
    emu_.Get<GuestCycleClock>().RegisterIdleListener([this] { OnIdle(); });
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        {
            std::lock_guard<std::mutex> lk(state_mtx_);
            StopScanLocked();
            ApplyResetsLocked();
        }
        PublishLines(Lines{});
    });
    {
        std::lock_guard<std::mutex> lk(state_mtx_);
        ApplyResetsLocked();
    }
    emu_.Get<PeripheralDispatcher>().Register(this);
}

/* MCIMX31RM Table 44-14 reset values; Figure 44-12: CUR_BUF resets to the
   channel's DBMS bit, which resets to 0. */
void Imx31Ipu::ApplyResetsLocked() {
    for (auto& r : regs_) r = 0u;
    for (const auto& e : kNonZeroResets) regs_[e.off / 4u] = e.value;
    cpm_->Reset();
    bg_in_frame_ = false;
}

/* MCIMX31RM §44.3.3.1.2 / §44.3.3.1.3: "Writing '1' to each field will set each
   bit. Writing '0' to each field simultaneously will clear all the bits."
   Figure 44-12: CUR_BUF is w1r and resets to the channel's DBMS bit. */
void Imx31Ipu::WriteRegLocked(uint32_t off, uint32_t value) {
    uint32_t slot;
    if (!OffsetToSlot(off, kLastOff, &slot)) return;
    if (off == kBuf0RdyOff || off == kBuf1RdyOff) {
        regs_[slot] = value == 0u ? 0u : (regs_[slot] | value);
        return;
    }
    if (off == kCurBufOff) {
        const uint32_t dbms = regs_[kDbModeSelOff / 4u];
        regs_[slot] = (regs_[slot] & ~value) | (dbms & value);
        return;
    }
    switch (ClassifyOffset(off)) {
    case Kind::ROnly: break;
    case Kind::W1C:   regs_[slot] &= ~value; break;
    case Kind::RW:    regs_[slot] = value;   break;
    }
}

void Imx31Ipu::OnIpuConfWriteLocked(uint32_t old_conf, uint32_t new_conf, uint64_t now) {
    if (((old_conf & kIpuConfDisplayOn) != 0) != ((new_conf & kIpuConfDisplayOn) != 0)) {
        PublishSdcDimsLocked();
    }
    const bool was_sdc = (old_conf & kIpuConfSdcEnBit) != 0;
    const bool now_sdc = (new_conf & kIpuConfSdcEnBit) != 0;
    if (now_sdc && (new_conf & kIpuConfDiEnBit) == 0u) {
        emu_.Get<Fatal>().Die("Imx31Ipu: IPU_CONF 0x%08X runs the SDC with DI_EN clear; the SDC "
                              "without the DI timing control is not modelled", new_conf);
    }
    if (was_sdc == now_sdc) return;
    if (!now_sdc) {
        StopScanLocked();
        bg_in_frame_ = false;
        return;
    }
    if (const char* why = Imx31SdcTiming::Unmodelled(SdcRegsLocked())) {
        emu_.Get<Fatal>().Die("Imx31Ipu: SDC_EN with %s (SDC_COM_CONF 0x%08X)", why,
                              regs_[kSdcComConfOff / 4u]);
    }
    RequireIpuClockLocked(FreescaleLowPowerMode::kRun, "SDC_EN");
    LatchScanTimingLocked();
    FrameStartLocked();
    StartScanLocked(now);
}

void Imx31Ipu::LatchScanTimingLocked() {
    latched_sdc_ = SdcRegsLocked();
}

void Imx31Ipu::PublishSdcDimsLocked() {
    if ((regs_[0] & kIpuConfDisplayOn) == 0) return;
    uint32_t w, h;
    EffectiveDimsLocked(&w, &h);
    if (w <= 1u || h <= 1u) return;
    if (w == last_pub_w_ && h == last_pub_h_) return;
    last_pub_w_ = w;
    last_pub_h_ = h;
    emu_.Get<HostWindow>().OnLcdEnabled();
}

Imx31SdcTimingRegs Imx31Ipu::SdcRegsLocked() const {
    const ChannelFormat f = cpm_->Decode(kBgChannel);
    Imx31SdcTimingRegs r;
    r.com_conf    = regs_[kSdcComConfOff / 4u];
    r.hor         = regs_[kSdcHorOff / 4u];
    r.ver         = regs_[kSdcVerOff / 4u];
    r.bg_pos      = regs_[kSdcBgPosOff / 4u];
    r.disp3_time  = regs_[kDiDisp3TimeOff / 4u];
    r.hsp_clk_per = regs_[kDiHspClkPerOff / 4u];
    r.acc_cc      = regs_[kDiDispAccCcOff / 4u];
    r.bg_fw       = f.fw;
    r.bg_fh       = f.fh;
    return r;
}

RasterScanClock::Frame Imx31Ipu::ScanFrameLocked() const {
    return Imx31SdcTiming::Frame(SdcRegsLocked());
}

/* MCIMX31RM §44.4.4.6 (p. 44-277): F_REF = F_HSP / ((SCREEN_WIDTH+1) (SCREEN_HEIGHT+1)
   (DISP3_IF_CLK_PER_WR / HSP_CLK_PERIOD1,2) (DISP3_IF_CLK_CNT_D+1)). */
RasterScanPeripheral::ScanShape Imx31Ipu::ScanShapeLocked() const {
    const Imx31SdcTimingRegs sdc = SdcRegsLocked();
    const uint64_t hsp = emu_.Get<Imx31Ccm>().HspClkHz();
    const uint64_t per_word = uint64_t{Imx31SdcTiming::PerWr(sdc)} *
                              Imx31SdcTiming::ClocksPerWord(sdc);
    return ScanShape{{hsp * Imx31SdcTiming::HspPeriod(sdc), per_word}, ScanFrameLocked()};
}

/* MCIMX31RM §44.4.8.3: an event reaches the functional interrupt only through its
   INT_CTRL_1..3 enable bit. */
bool Imx31Ipu::EdgeRaisesInterruptLocked(uint32_t edge_index, bool this_frame) const {
    const uint32_t ctrl1 = regs_[kIntCtrl1Off / 4u];
    const uint32_t ctrl2 = regs_[kIntCtrl2Off / 4u];
    const uint32_t ctrl3 = regs_[kIntCtrl3Off / 4u];
    const bool     bg_en = (regs_[kSdcComConfOff / 4u] & kComBgEn) != 0u;
    if (edge_index == 0u) {
        const bool bg = this_frame ? bg_in_frame_ : bg_en;
        return bg && ((ctrl3 & kStat3SdcBgEof) != 0u || (ctrl1 & kBgBit) != 0u);
    }
    const bool nfack = bg_en && (regs_[kBuf0RdyOff / 4u] & kBgBit) != 0u;
    return (ctrl3 & kStat3Vsync) != 0u || (nfack && (ctrl2 & kBgBit) != 0u);
}

void Imx31Ipu::RequireStableScanLocked(uint32_t off) const {
    if (!ScanActiveLocked()) return;
    const Imx31SdcTimingRegs sdc = SdcRegsLocked();
    if (const char* why = Imx31SdcTiming::Unmodelled(sdc)) {
        emu_.Get<Fatal>().Die("Imx31Ipu: SDC scanning with %s (SDC_COM_CONF 0x%08X)", why,
                              regs_[kSdcComConfOff / 4u]);
    }
    if (!Imx31SdcTiming::SameScan(latched_sdc_, sdc)) {
        emu_.Get<Fatal>().Die("Imx31Ipu: the write of 0x%08X to 0x%03X changes the SDC scan timing "
                              "while SDC_EN is set", regs_[off / 4u], off);
    }
}

void Imx31Ipu::FrameStartLocked() {
    regs_[(kIntStat1Off + 8u) / 4u] |= kStat3Vsync;
    const bool bg_en = (regs_[kSdcComConfOff / 4u] & kComBgEn) != 0;
    const bool ch_en = (regs_[kIdmacChaEnOff / 4u] & kBgBit) != 0;
    if (bg_en && !ch_en) {
        emu_.Get<Fatal>().Die("Imx31Ipu: BG_EN with IDMAC channel 14 disabled is not modelled");
    }
    bg_in_frame_ = bg_en;
    if (!bg_in_frame_) return;
    if (regs_[kDbModeSelOff / 4u] & kBgBit) {
        emu_.Get<Fatal>().Die("Imx31Ipu: SDC background frame with IDMAC channel 14 in double "
                              "buffer mode (DB_MODE_SEL 0x%08X) is not modelled",
                              regs_[kDbModeSelOff / 4u]);
    }
    uint32_t& rdy = regs_[kBuf0RdyOff / 4u];
    if ((rdy & kBgBit) == 0u) return;
    rdy &= ~kBgBit;
    regs_[(kIntStat1Off + 4u) / 4u] |= kBgBit;
}

/* MCIMX31RM Table 44-166: SDC_BG_EOF "End of background frame on SDC output"
   and DMASDC_0_EOF. */
void Imx31Ipu::FrameEdgeLocked(uint32_t edge_index) {
    if (edge_index == 0u) {
        if (!bg_in_frame_) return;
        regs_[(kIntStat1Off + 8u) / 4u] |= kStat3SdcBgEof;
        regs_[kIntStat1Off / 4u]        |= kBgBit;
        return;
    }
    FrameStartLocked();
}

/* MCIMX31RM Table 44-71: busy "in the middle of frame". */
uint32_t Imx31Ipu::IdmacBusyLocked(uint64_t now) const {
    if (!ScanLiveLocked() || !bg_in_frame_) return 0u;
    const uint64_t first = Imx31SdcTiming::BgFirstTick(latched_sdc_);
    const uint64_t end   = Imx31SdcTiming::Frame(latched_sdc_).edge[0];
    const uint64_t tick  = ScanTickInFrameLocked(now);
    return (tick >= first && tick < end) ? kBgBit : 0u;
}

/* MCIMX31RM §44.4.8.3: the IG produces the functional and the error interrupt,
   all maskable; Tables 44-166 / 44-167: functional in INT_STAT_1..3, error in
   INT_STAT_4..5. */
Imx31Ipu::Lines Imx31Ipu::LinesLocked() const {
    Lines l;
    for (uint32_t n = 0; n < 5u; ++n) {
        const uint32_t pending = regs_[(kIntStat1Off / 4u) + n] & regs_[(kIntCtrl1Off / 4u) + n];
        if (pending == 0u) continue;
        if (n < 3u) l.functional = true;
        else        l.error      = true;
    }
    return l;
}

void Imx31Ipu::PublishLines(const Lines& lines) {
    auto& avic = emu_.Get<Imx31Avic>();
    if (lines.functional) avic.AssertSource(kAvicIpuGeneral);
    else                  avic.DeassertSource(kAvicIpuGeneral);
    if (lines.error)      avic.AssertSource(kAvicIpuError);
    else                  avic.DeassertSource(kAvicIpuError);
}

/* MCIMX31RM Table 3-30: CG(11)=00 in run mode (transition 0, p. 3-58), WFI into WAIT
   with CG(11)=01 and into DOZE with 01||10 (transitions 1 and 3, p. 3-59) request IPU
   standby; the IPU clock stops after ipu_stby_ack. */
void Imx31Ipu::RequireIpuClockLocked(FreescaleLowPowerMode mode, const char* when) const {
    const uint32_t cg = emu_.Get<Imx31Ccm>().ClockGate1(kCgr1Ipu);
    if (Imx31Ccm::ClockGateRunsIn(cg, mode)) return;
    emu_.Get<Fatal>().Die("Imx31Ipu: %s in low-power mode %u with CGR1 CG11 %u stops the IPU "
                          "clock of the SDC scan; the IPU standby is not modelled", when,
                          static_cast<unsigned>(mode), cg);
}

void Imx31Ipu::OnIdle() {
    std::lock_guard<std::mutex> lk(state_mtx_);
    if (!ScanActiveLocked()) return;
    RequireIpuClockLocked(emu_.Get<FreescaleTimerClocks>().WfiMode(), "WFI");
}

void Imx31Ipu::ScanEdgesRan() {
    Lines lines;
    {
        std::lock_guard<std::mutex> lk(state_mtx_);
        lines = LinesLocked();
    }
    PublishLines(lines);
}

uint32_t Imx31Ipu::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    uint32_t slot;
    if (!OffsetToSlot(off, kLastOff, &slot)) HaltUnsupportedAccess("ReadWord", addr, 0);
    uint32_t value;
    bool     edged;
    {
        std::lock_guard<std::mutex> lk(state_mtx_);
        const uint64_t now = ScanNow();
        edged = CatchUpLocked(now);
        value = off == kIdmacBusyOff ? IdmacBusyLocked(now) : regs_[slot];
    }
    if (edged) ScanEdgesRan();
    return value;
}

void Imx31Ipu::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    uint32_t slot;
    if (!OffsetToSlot(off, kLastOff, &slot)) HaltUnsupportedAccess("WriteWord", addr, value);
    Lines lines;
    {
        std::lock_guard<std::mutex> lk(state_mtx_);
        const uint64_t now = ScanNow();
        CatchUpLocked(now);
        const uint32_t old_val = regs_[slot];
        WriteRegLocked(off, value);
        if (off == kIpuConfOff) OnIpuConfWriteLocked(old_val, regs_[slot], now);
        if (off == kImaAddrOff) cpm_->WriteImaAddr(value);
        if (off == kImaDataOff && cpm_->WriteImaData(value) == kBgChannel) PublishSdcDimsLocked();
        if (off == kSdcHorOff || off == kSdcVerOff) PublishSdcDimsLocked();
        if (off == kSdcComConfOff || off == kSdcBgPosOff || off == kSdcHorOff ||
            off == kSdcVerOff || off == kDiDisp3TimeOff || off == kDiHspClkPerOff ||
            off == kImaDataOff || off == kDiDispAccCcOff) {
            RequireStableScanLocked(off);
        }
        RearmScanLocked();
        lines = LinesLocked();
    }
    PublishLines(lines);
}

bool Imx31Ipu::IsEnabled() const {
    std::lock_guard<std::mutex> guard(state_mtx_);
    return (regs_[0] & kIpuConfDisplayOn) != 0;
}

void Imx31Ipu::EffectiveDimsLocked(uint32_t* w, uint32_t* h) const {
    const ChannelFormat f = cpm_->Decode(kBgChannel);
    if (f.fw > 1u && f.fh > 1u) {
        *w = f.fw;
        *h = f.fh;
        return;
    }
    *w = cerf::BitField(regs_[kSdcHorOff / 4u], 16u, 0x3FFu) + 1u;
    *h = cerf::BitField(regs_[kSdcVerOff / 4u], 16u, 0x3FFu) + 1u;
}

uint32_t Imx31Ipu::GetGuestW() const {
    std::lock_guard<std::mutex> guard(state_mtx_);
    uint32_t w, h;
    EffectiveDimsLocked(&w, &h);
    return w;
}

uint32_t Imx31Ipu::GetGuestH() const {
    std::lock_guard<std::mutex> guard(state_mtx_);
    uint32_t w, h;
    EffectiveDimsLocked(&w, &h);
    return h;
}

uint32_t Imx31Ipu::GetSdcBgFbPa() const {
    std::lock_guard<std::mutex> guard(state_mtx_);
    return cpm_->Eba0(kBgChannel);
}

Imx31Ipu::ChannelFormat Imx31Ipu::GetSdcBgFormat() const {
    std::lock_guard<std::mutex> guard(state_mtx_);
    return cpm_->Decode(kBgChannel);
}

void Imx31Ipu::SetupSdcScanout(uint32_t fb_pa, uint32_t w, uint32_t h) {
    std::lock_guard<std::mutex> guard(state_mtx_);
    cpm_->EncodeRgb565(kBgChannel, fb_pa, w, h);
    regs_[kSdcHorOff / 4u] = (w - 1u) << 16;
    regs_[kSdcVerOff / 4u] = (h - 1u) << 16;
}

void Imx31Ipu::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(state_mtx_);
    w.WriteBytes("regs", regs_, sizeof(regs_));
    cpm_->SaveState(w);
    w.Write("last_pub_w", last_pub_w_);
    w.Write("last_pub_h", last_pub_h_);
    w.Write<uint8_t>("bg_in_frame", bg_in_frame_ ? 1u : 0u);
    SaveScanLocked(w);
}

void Imx31Ipu::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(state_mtx_);
    r.ReadBytes("regs", regs_, sizeof(regs_));
    cpm_->RestoreState(r);
    r.Read("last_pub_w", last_pub_w_);
    r.Read("last_pub_h", last_pub_h_);
    uint8_t bg = 0;
    r.Read("bg_in_frame", bg);
    RestoreScanLocked(r);
    bg_in_frame_ = bg != 0u;
}

void Imx31Ipu::PostRestore() {
    Lines lines;
    {
        std::lock_guard<std::mutex> lk(state_mtx_);
        if (regs_[0] & kIpuConfSdcEnBit) LatchScanTimingLocked();
        ResumeScanLocked(ScanNow());
        lines = LinesLocked();
    }
    PublishLines(lines);
}

REGISTER_SERVICE(Imx31Ipu);
