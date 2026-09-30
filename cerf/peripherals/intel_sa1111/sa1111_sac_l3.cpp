#include "sa1111_sac_l3.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "../../boards/jornada720/jornada_720_id.h"
#include "../../state/state_stream.h"
#include "sa1111_sbi.h"
#include "sa1111_system_controller.h"

namespace {

/* SA-1111 Developer's Manual Table 7-34 (printed 7-25): Tcy(CLK)(L3) 500 ns min, tsu(L3)A,
   th(L3)A, tsu(L3)D, th(L3)D, tstp(L3) 190 ns min; Figures 7-7 / 7-8 (printed 7-24 / 7-25):
   eight L3_CLK periods per byte, tstp(L3) before the data byte. */
constexpr uint64_t kNsHz       = 1000000000u;
constexpr uint64_t kAddressNs  = 190u + 8u * 500u + 190u;
constexpr uint64_t kDataNs     = 190u + 190u + 8u * 500u + 190u;

constexpr Sa1111SerialTransfer::Keys kL3Keys = {"l3_xfer_busy", "l3_xfer_ns", "l3_xfer_elapsed_ns",
                                                "l3_xfer_phase", "l3_xfer_phase_den"};

/* Table 7-8 (printed 7-11): L3EN bit 1, L3MB bit 2 "1 = L3 Control Bus Data is Multiple Byte
   Transfer". §7.4.6 (printed 7-16): "If both address LSBs are "01", it is a read request". */
constexpr uint32_t kSacr1L3En   = 1u << 1;
constexpr uint32_t kSacr1L3Mb   = 1u << 2;
constexpr uint32_t kReadRequest = 0x1u;
constexpr uint32_t kL3Wd        = 1u << 16;

}

Sa1111SacL3::Sa1111SacL3(CerfEmulator& emu)
    : Service(emu),
      xfer_(emu, "Sa1111SacL3", kNsHz, kL3Keys, [this](uint64_t now) { Settle(now); }) {}

bool Sa1111SacL3::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::Jornada720;
}

void Sa1111SacL3::OnReady() { xfer_.Attach(); }

/* Table 7-10 (printed 7-13): L3WD "L3 Control Bus Data Write Done", "1 - L3 Control Bus Data
   Write Data is Done". */
void Sa1111SacL3::Settle(uint64_t now) {
    if (!xfer_.Finished(now)) return;
    xfer_.Clear();
    if (!data_) return;
    data_ = false;
    sent_ = true;
}

void Sa1111SacL3::RequireBusModelled(uint32_t sacr1) const {
    if ((sacr1 & kSacr1L3En) != 0u && (sacr1 & kSacr1L3Mb) == 0u) return;
    emu_.Get<Fatal>().Die("Sa1111SacL3: L3 transfer with SACR1 0x%08X (L3EN clear or L3MB "
                          "set) is not modelled", sacr1);
}

/* §5.1.1 (printed 5-1): "programmable SYS_CLK and L3"; Table 3-4 PLL_Bypass: "Bypass PLL,
   send input CLK direct to dividers". */
void Sa1111SacL3::RequireClocks() const {
    const auto& sc  = emu_.Get<Sa1111SystemController>();
    const auto& sbi = emu_.Get<Sa1111Sbi>();
    if (sc.L3ClockEnabled() && sc.PllRunningAtResetRate()) return;
    emu_.Get<Fatal>().Die("Sa1111SacL3: L3 transfer with SKPCR L3CLKEn clear, SKCR 0x%08X (PLL "
                          "bypassed, VCO off, Sleep or Doze), no 3.6864 MHz CLK input, or SKCDR "
                          "0x%08X (a PLL rate other than the reset one) is not modelled",
                          sbi.Skcr(), sc.Skcdr());
}

/* §7.4.6 (printed 7-16): "The address register is written first, so address and command
   (embedded in 2 LSBs of the address byte) are sent to the target codec." */
void Sa1111SacL3::WriteAddress(uint64_t now, uint32_t value, uint32_t sacr1) {
    Settle(now);
    if (xfer_.Busy(now) || (value & 0x3u) == kReadRequest) {
        emu_.Get<Fatal>().Die("Sa1111SacL3: L3CAR write 0x%08X (during an L3 transfer, or an L3 "
                              "read request) is not modelled", value);
    }
    RequireBusModelled(sacr1);
    RequireClocks();
    car_       = value & 0xFFu;
    addressed_ = true;
    xfer_.Start(now, kAddressNs);
}

/* §7.4.6: "When the L3 Data Register is subsequently written, the register's contents are
   transmitted serially to the codec." */
void Sa1111SacL3::WriteData(uint64_t now, uint32_t value, uint32_t sacr1) {
    Settle(now);
    if (!addressed_ || data_) {
        emu_.Get<Fatal>().Die("Sa1111SacL3: L3CDR write 0x%08X with no L3CAR write before it, or "
                              "during a data byte, is not modelled", value);
    }
    RequireBusModelled(sacr1);
    RequireClocks();
    LOG(Periph, "[Sa1111Sac] L3 codec write addr=0x%02X val=0x%02X\n", car_, value & 0xFFu);
    addressed_ = false;
    data_      = true;
    if (xfer_.Busy(now)) xfer_.Extend(kDataNs);
    else                 xfer_.Start(now, kDataNs);
}

uint32_t Sa1111SacL3::StatusBits(uint64_t now) {
    Settle(now);
    return sent_ ? kL3Wd : 0u;
}

/* Table 7-12 (printed 7-15): SASCR DTS bit 16 clears L3WD. */
void Sa1111SacL3::ClearStatus(uint64_t now, uint32_t sascr) {
    Settle(now);
    if ((sascr & kL3Wd) != 0u) sent_ = false;
}

bool Sa1111SacL3::DataSent(uint64_t now) const {
    return sent_ || (data_ && xfer_.Finished(now));
}

void Sa1111SacL3::OnSacr1Write(uint64_t now, uint32_t sacr1) {
    Settle(now);
    if (xfer_.Busy(now)) RequireBusModelled(sacr1);
}

void Sa1111SacL3::OnClockChange(uint64_t now) {
    Settle(now);
    if (xfer_.Busy(now)) RequireClocks();
}

/* §2.3 (printed 2-4): "When nRESET is asserted, all on-chip activity halts". */
void Sa1111SacL3::Reset(uint64_t now, bool chip) {
    Settle(now);
    if (xfer_.Busy(now) && !chip) {
        emu_.Get<Fatal>().Die("Sa1111SacL3: SACR0 RST during an L3 transfer is not modelled");
    }
    xfer_.Clear();
    car_       = 0u;
    addressed_ = false;
    data_      = false;
    sent_      = false;
}

void Sa1111SacL3::Save(StateWriter& w, uint64_t now) {
    Settle(now);
    w.Write("l3car", car_);
    w.Write<uint8_t>("l3_addressed", addressed_ ? 1u : 0u);
    w.Write<uint8_t>("l3_data", data_ ? 1u : 0u);
    w.Write<uint8_t>("l3wd", sent_ ? 1u : 0u);
    xfer_.Save(w, now);
}

void Sa1111SacL3::Restore(StateReader& r, uint64_t now) {
    uint8_t addressed = 0u, data = 0u, sent = 0u;
    r.Read("l3car", car_);
    r.Read("l3_addressed", addressed);
    r.Read("l3_data", data);
    r.Read("l3wd", sent);
    addressed_ = addressed != 0u;
    data_      = data != 0u;
    sent_      = sent != 0u;
    xfer_.Restore(r, now);
}

REGISTER_SERVICE(Sa1111SacL3);
