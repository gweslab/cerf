#include "ite_it8368.h"

#include "../../boards/board_context.h"
#include "../../boards/philips_nino_300/philips_nino_300_id.h"
#include "../../boards/philips_velo_1/philips_velo_1_id.h"
#include "../../boards/sharp_mobilon_hc4100/sharp_mobilon_hc4100_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../state/state_stream.h"
#include "../pcmcia/pcmcia_slot.h"

namespace {

/* it8368reg.h IT8368_*_REG. */
constexpr uint32_t kRegGpioDataOut    = 0x00;
constexpr uint32_t kRegMfioDataOut    = 0x02;
constexpr uint32_t kRegGpioDir        = 0x04;
constexpr uint32_t kRegMfioDir        = 0x06;
/* it8368reg.h defines no register at 0x08 (gap between IT8368_MFIODIR_REG
   0x06 and IT8368_MFIOSEL_REG 0x0a). */
constexpr uint32_t kRegReserved08     = 0x08;
constexpr uint32_t kRegMfioSel        = 0x0A;
constexpr uint32_t kRegGpioDataIn     = 0x0C;
constexpr uint32_t kRegMfioDataIn     = 0x0E;
constexpr uint32_t kRegGpioPosIntEn   = 0x10;
constexpr uint32_t kRegMfioPosIntEn   = 0x12;
constexpr uint32_t kRegGpioNegIntEn   = 0x14;
constexpr uint32_t kRegMfioNegIntEn   = 0x16;
constexpr uint32_t kRegGpioPosIntStat = 0x18;
constexpr uint32_t kRegMfioPosIntStat = 0x1A;
constexpr uint32_t kRegGpioNegIntStat = 0x1C;
constexpr uint32_t kRegMfioNegIntStat = 0x1E;
constexpr uint32_t kRegCtrl           = 0x20;

/* it8368reg.h IT8368_GPIODATAIN_MASK - twelve GPIOs, bits 12:0. */
constexpr uint16_t kGpioMask = 0x1FFF;

/* it8368reg.h IT8368_MFIO*_MASK - eleven MFIO pins, bits 10:0. */
constexpr uint16_t kMfioMask = 0x07FF;

/* it8368reg.h IT8368_MFIOSEL_VGAEN. */
constexpr uint16_t kMfioSelVgaEn = 0x0800;

/* it8368reg.h IT8368_PIN_*. */
constexpr uint16_t kPinCrdSw     = 0x1000;
constexpr uint16_t kPinCrdDet2   = 0x0800;
constexpr uint16_t kPinCrdDet1   = 0x0400;
constexpr uint16_t kPinCrdVccOn1 = 0x0080;
constexpr uint16_t kPinCrdVccOn0 = 0x0040;
constexpr uint16_t kPinCrdVppOn1 = 0x0020;
constexpr uint16_t kPinCrdVppOn0 = 0x0010;
constexpr uint16_t kPinBcrdWp    = 0x0008;
constexpr uint16_t kPinBcrdRdy   = 0x0004;
constexpr uint16_t kPinBcrdRst   = 0x0001;

constexpr uint16_t kPinCrdDetMask = kPinCrdDet1 | kPinCrdDet2;

constexpr uint16_t kPinCrdVccMask = kPinCrdVccOn1 | kPinCrdVccOn0;
constexpr uint16_t kPinCrdVppMask = kPinCrdVppOn1 | kPinCrdVppOn0;

/* The pins the chip drives as outputs; it8368.c:262-265 enables exactly these
   and leaves the rest as card status inputs. */
constexpr uint16_t kDrivablePins = kPinCrdVccMask | kPinCrdVppMask | kPinBcrdRst;

/* CRDSW is an output-capable pin the Velo drives high (nk.exe sub_9F40F688);
   NetBSD never uses it and no ROM path reads it back, so it is accepted as a
   driven output but has no realized effect (ApplyOutputsLocked models only the
   kDrivablePins set). */
constexpr uint16_t kOutputCapablePins = kDrivablePins | kPinCrdSw;

/* it8368reg.h IT8368_CTRL_*. */
constexpr uint16_t kCtrlFixAttrIo = 0x8000;
constexpr uint16_t kCtrlAddrSel   = 0x0010;
constexpr uint16_t kCtrlByteSwap  = 0x0008;
constexpr uint16_t kCtrlCardEn    = 0x0004;
constexpr uint16_t kCtrlGlobalEn  = 0x0002;
constexpr uint16_t kCtrlIntTriEn  = 0x0001;

/* Bit 6 is a self-clearing soft reset, undocumented in it8368reg.h: pcmcia.dll
   sub_149120C writes CTRL 0x0040 alone, settles, then reconfigures every
   register; the card-enable CTRL read-modify-write (it8368.c:294-298) carries no
   reset bit. */
constexpr uint16_t kCtrlSoftReset = 0x0040;

constexpr uint16_t kCtrlKnown = kCtrlFixAttrIo | kCtrlAddrSel | kCtrlByteSwap |
                                kCtrlCardEn | kCtrlGlobalEn | kCtrlIntTriEn;

}  /* namespace */

bool IteIt8368::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    if (!bd) return false;
    const std::string_view board = bd->GetBoardId();
    return board == BoardId::PhilipsNino300 || board == BoardId::PhilipsVelo1 ||
           board == BoardId::SharpMobilonHc4100;
}

void IteIt8368::OnReady() {
    emu_.Get<Pr31x00CardSpace>().ProvideCardBuffer(this);
}

bool IteIt8368::CardInterfaceEnabled() const { return (ctrl_ & kCtrlCardEn) != 0; }

/* Attribute decodes from A25 ($0200_0000) with CTRL FIXATTRIO clear, as the Velo OAL
   leaves it (nk.exe sub_9F40F688 writes CTRL = $0A): pcmcia.dll reads the CIS at its
   $0A00_0000 attribute window while MEM_CONFIG3 CARD1IOEN stays set, which the legacy
   CARDnIOEN decode (it8368.c:562-571) would route to I/O space instead. */
bool IteIt8368::FixedAttributeIo() const { return true; }

/* An undriven card pin floats high, so an empty socket reads CRDDET1 and CRDDET2
   set (it8368.c:419 treats either as "no card"). */
uint16_t IteIt8368::GpioDataInLocked() const {
    const uint16_t driven   = static_cast<uint16_t>(gpio_dataout_ & gpio_dir_);
    const uint16_t undriven = static_cast<uint16_t>(kGpioMask & ~gpio_dir_);
    uint16_t in = static_cast<uint16_t>(driven | undriven);

    if (!slot_->HasCard()) return in;
    /* Grounded on the card body: pcmcia.dll sub_188145C tests them before Vcc. */
    in &= static_cast<uint16_t>(~kPinCrdDetMask);

    /* sub_18817C4 reads the pins below only while GPIODATAOUT holds CRDVCCON0. */
    if (!slot_->IsPowered()) return in;

    /* High is write-protected (sub_18817C4 -> socket status bit 0). */
    in &= static_cast<uint16_t>(~kPinBcrdWp);

    /* READY/-IREQ: sub_188145C sets CTRL CARDEN only if it reads high, and
       sub_1881694 arms its falling edge as the card interrupt (it8368.c:447). */
    if (card_irq_) in &= static_cast<uint16_t>(~kPinBcrdRdy);
    else           in |= kPinBcrdRdy;
    return in;
}

void IteIt8368::LatchInputEdgesLocked() {
    const uint16_t now  = GpioDataInLocked();
    const uint16_t diff = static_cast<uint16_t>(now ^ prev_datain_);
    gpio_posintstat_ |= static_cast<uint16_t>(diff & now);
    gpio_negintstat_ |= static_cast<uint16_t>(diff & ~now);
    prev_datain_ = now;
    UpdateIntLocked();
}

void IteIt8368::SetCardIrq(bool asserted) {
    std::lock_guard<std::mutex> lk(mu_);
    card_irq_ = asserted;
    LatchInputEdgesLocked();
}

void IteIt8368::NotifyCardDetect() {
    std::lock_guard<std::mutex> lk(mu_);
    LatchInputEdgesLocked();
}

/* GLOBALEN alone enables interrupt driving (it8368.c:293-298); the Velo takes card
   interrupts with INTTRIEN clear (nk.exe sub_9F40F688 writes CTRL = $0A). */
bool IteIt8368::IntLevelLocked() const {
    const bool driving = (ctrl_ & kCtrlGlobalEn) != 0u;
    const bool pending = ((gpio_posintstat_ & gpio_posinten_) |
                          (gpio_negintstat_ & gpio_neginten_)) != 0u;
    return driving && pending;
}

void IteIt8368::UpdateIntLocked() {
    const bool level = IntLevelLocked();
    if (level == int_asserted_) return;

    if (!int_sink_) {
        LOG(Caution, "IteIt8368: INT pin has no board wiring\n");
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    int_asserted_ = level;
    int_sink_->OnIt8368IntLevel(level);
}

IteIt8368::BusOps IteIt8368::ApplyOutputsLocked() {
    const uint16_t driven = static_cast<uint16_t>(gpio_dataout_ & gpio_dir_);

    /* CRDVPPON0 alone is Vpp = Vcc (it8368reg.h:106), which a card takes as its
       operating Vpp; CRDVPPON1 raises the 12 V programming supply (it8368reg.h:107),
       and both together tri-state Vpp (it8368reg.h:108). Only Vcc reaches the socket,
       so only the 12 V rail is an unmodeled power state. */
    if (driven & kPinCrdVppOn1) {
        LOG(Caution, "IteIt8368: CRDVPPON1 (Vpp 12 V) unmodeled\n");
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    if ((driven & kPinCrdVccMask) == kPinCrdVccMask) {
        LOG(Caution, "IteIt8368: CRDVCCON1 and CRDVCCON0 both driven\n");
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    BusOps ops;
    ops.drove_pins = true;
    ops.power_on   = (driven & kPinCrdVccMask) != 0u;

    /* it8368.c:686-699 asserts BCRDRST, holds it, then clears it; the card
       leaves reset on that falling edge. */
    const bool rst_now = (driven & kPinBcrdRst) != 0u;
    ops.release_reset = rst_asserted_ && !rst_now;
    rst_asserted_ = rst_now;

    LatchInputEdgesLocked();
    return ops;
}

IteIt8368::BusOps IteIt8368::SoftResetLocked() {
    gpio_dataout_    = 0;
    gpio_dir_        = 0;
    gpio_posinten_   = 0;
    gpio_neginten_   = 0;
    gpio_posintstat_ = 0;
    gpio_negintstat_ = 0;
    mfio_posintstat_ = 0;
    mfio_negintstat_ = 0;
    mfio_dataout_    = 0;
    mfio_dir_        = 0;
    mfio_sel_        = 0;
    ctrl_            = 0;
    return ApplyOutputsLocked();
}

void IteIt8368::ApplyBusOps(const BusOps& ops) {
    slot_->SetPowered(ops.power_on);
    if (ops.release_reset) slot_->ResetCard();
}

uint16_t IteIt8368::ReadReg(uint32_t off) {
    std::lock_guard<std::mutex> lk(mu_);
    switch (off) {
        case kRegGpioDataOut: return gpio_dataout_;
        case kRegGpioDir:     return gpio_dir_;

        /* nk.exe sub_9F40F39C reads MFIODATAOUT to save/restore bit 10 around the
           debug-probe strobe; the output register reads back its latch. */
        case kRegMfioDataOut: return mfio_dataout_;

        /* it8368reg.h IT8368_MFIODIR_REG 0x06 (R/W, mask IT8368_MFIODIR_MASK);
           NetBSD it8368.c:244-246 RMWs it: read -> |= mask -> write. */
        case kRegMfioDir: return mfio_dir_;

        case kRegGpioDataIn:
            LatchInputEdgesLocked();
            return GpioDataInLocked();

        case kRegGpioPosIntStat:
            LatchInputEdgesLocked();
            return gpio_posintstat_;
        case kRegGpioNegIntStat:
            LatchInputEdgesLocked();
            return gpio_negintstat_;

        case kRegGpioPosIntEn: return gpio_posinten_;
        case kRegGpioNegIntEn: return gpio_neginten_;

        case kRegCtrl: return ctrl_;

        /* pcmcia.dll suspend save sub_14912D4 reads regs 0x00..0x20; restore
           sub_149131C writes back only offsets 4/6/0x10-0x1E/0x20. */
        case kRegMfioSel:        return mfio_sel_;
        case kRegReserved08:     return 0;

        /* it8368reg.h IT8368_MFIODATAIN_REG 0x0e; NetBSD it8368.c:243-246 drives
           every MFIO as an output. */
        case kRegMfioDataIn:
            return static_cast<uint16_t>(mfio_dataout_ & mfio_dir_);

        /* it8368reg.h IT8368_MFIOPOSINTSTAT_REG 0x1a / IT8368_MFIONEGINTSTAT_REG
           0x1e (W1C). */
        case kRegMfioPosIntStat: return mfio_posintstat_;
        case kRegMfioNegIntStat: return mfio_negintstat_;

        /* NetBSD it8368.c:253-259 clears MFIOPOSINTEN / MFIONEGINTEN. */
        case kRegMfioPosIntEn:
        case kRegMfioNegIntEn:   return 0;

        default:
            LOG(Caution, "IteIt8368::ReadReg unmodeled register $%02X\n", off);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
}

void IteIt8368::WriteReg(uint32_t off, uint16_t value) {
    BusOps ops;
    {
        std::lock_guard<std::mutex> lk(mu_);
        ops = WriteRegLocked(off, value);
    }
    if (!ops.drove_pins) return;

    ApplyBusOps(ops);

    /* Vcc and the reset pulse changed what the card drives back. */
    std::lock_guard<std::mutex> lk(mu_);
    LatchInputEdgesLocked();
}

IteIt8368::BusOps IteIt8368::WriteRegLocked(uint32_t off, uint16_t value) {
    switch (off) {
        case kRegGpioDataOut:
            if (value & ~kOutputCapablePins) {
                LOG(Caution, "IteIt8368: GPIODATAOUT 0x%04X drives an input "
                        "pin\n", value);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
            gpio_dataout_ = value;
            return ApplyOutputsLocked();

        case kRegGpioDir:
            if (value & ~kOutputCapablePins) {
                LOG(Caution, "IteIt8368: GPIODIR 0x%04X enables an output on a "
                        "card status pin\n", value);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
            gpio_dir_ = value;
            return ApplyOutputsLocked();

        case kRegMfioSel:
            if (value & ~static_cast<uint16_t>(kMfioMask | kMfioSelVgaEn)) {
                LOG(Caution, "IteIt8368: MFIOSEL 0x%04X sets a reserved bit\n",
                    value);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
            if (value & kMfioSelVgaEn) {
                LOG(Caution, "IteIt8368: MFIOSEL 0x%04X enables VGA\n", value);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
            mfio_sel_ = value;
            return {};

        case kRegGpioPosIntEn:
            if (value & ~kGpioMask) {
                LOG(Caution, "IteIt8368: GPIOPOSINTEN 0x%04X enables a pin the "
                        "chip does not have\n", value);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
            gpio_posinten_ = value;
            UpdateIntLocked();
            return {};

        case kRegGpioNegIntEn:
            if (value & ~kGpioMask) {
                LOG(Caution, "IteIt8368: GPIONEGINTEN 0x%04X enables a pin the "
                        "chip does not have\n", value);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
            gpio_neginten_ = value;
            UpdateIntLocked();
            return {};

        case kRegMfioPosIntEn:
        case kRegMfioNegIntEn:
            if (value != 0u) {
                LOG(Caution, "IteIt8368: MFIO interrupt enable $%02X = 0x%04X on a "
                        "pin held at its reset function\n", off, value);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
            return {};

        /* Write one to clear (it8368.c:337-339 clears a single latched pin). */
        case kRegGpioPosIntStat:
            gpio_posintstat_ &= static_cast<uint16_t>(~value);
            UpdateIntLocked();
            return {};
        case kRegGpioNegIntStat:
            gpio_negintstat_ &= static_cast<uint16_t>(~value);
            UpdateIntLocked();
            return {};

        /* Write one to clear (it8368.c:337-339). */
        case kRegMfioPosIntStat:
            mfio_posintstat_ &= static_cast<uint16_t>(~value);
            return {};
        case kRegMfioNegIntStat:
            mfio_negintstat_ &= static_cast<uint16_t>(~value);
            return {};

        case kRegCtrl:
            if (value & kCtrlSoftReset) {
                if (value != kCtrlSoftReset) {
                    LOG(Caution, "IteIt8368: CTRL 0x%04X combines soft reset with "
                            "other bits\n", value);
                    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
                }
                return SoftResetLocked();
            }
            if (value & ~kCtrlKnown) {
                LOG(Caution, "IteIt8368: CTRL 0x%04X sets a reserved bit\n", value);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
            /* ADDRSEL remaps LHA[14:13] onto the card window (it8368.c:238-241
               clears it), which would move every card offset the decoder derives. */
            if (value & kCtrlAddrSel) {
                LOG(Caution, "IteIt8368: CTRL ADDRSEL unmodeled\n");
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
            /* HC-4100 pcmcia.dll enables the card with BYTESWAP clear:
               sub_1491BF8 sets CARDEN, sub_14918E4 sets GLOBALEN, and BYTESWAP
               is set nowhere (init sub_149120C, enable, reset). NetBSD
               it8368e_attach (it8368.c:294-298) ORs GLOBALEN|CARDEN the same. */
            ctrl_ = value;
            UpdateIntLocked();
            return {};

        case kRegGpioDataIn:
        case kRegMfioDataIn:
            LOG(Caution, "IteIt8368: write to input register $%02X\n", off);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);

        case kRegMfioDataOut:
            if (value & ~kMfioMask) {
                LOG(Caution, "IteIt8368: MFIODATAOUT 0x%04X sets a reserved "
                        "bit\n", value);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
            mfio_dataout_ = value;
            return {};

        case kRegMfioDir:
            if (value & ~kMfioMask) {
                LOG(Caution, "IteIt8368: MFIODIR 0x%04X sets a reserved bit\n",
                    value);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
            mfio_dir_ = value;
            return {};

        default:
            LOG(Caution, "IteIt8368::WriteReg unmodeled register $%02X = 0x%04X\n",
                off, value);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
}

void IteIt8368::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(mu_);
    w.Write("gpio_dataout", gpio_dataout_);
    w.Write("gpio_dir", gpio_dir_);
    w.Write("gpio_posinten", gpio_posinten_);
    w.Write("gpio_neginten", gpio_neginten_);
    w.Write("gpio_posintstat", gpio_posintstat_);
    w.Write("gpio_negintstat", gpio_negintstat_);
    w.Write("mfio_posintstat", mfio_posintstat_);
    w.Write("mfio_negintstat", mfio_negintstat_);
    w.Write("mfio_dataout", mfio_dataout_);
    w.Write("mfio_dir", mfio_dir_);
    w.Write("mfio_sel", mfio_sel_);
    w.Write("ctrl", ctrl_);
    w.Write("prev_datain", prev_datain_);
    w.Write<uint8_t>("rst_asserted", rst_asserted_ ? 1u : 0u);
    w.Write<uint8_t>("card_irq", card_irq_ ? 1u : 0u);
}

void IteIt8368::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(mu_);
    r.Read("gpio_dataout", gpio_dataout_);
    r.Read("gpio_dir", gpio_dir_);
    r.Read("gpio_posinten", gpio_posinten_);
    r.Read("gpio_neginten", gpio_neginten_);
    r.Read("gpio_posintstat", gpio_posintstat_);
    r.Read("gpio_negintstat", gpio_negintstat_);
    r.Read("mfio_posintstat", mfio_posintstat_);
    r.Read("mfio_negintstat", mfio_negintstat_);
    r.Read("mfio_dataout", mfio_dataout_);
    r.Read("mfio_dir", mfio_dir_);
    r.Read("mfio_sel", mfio_sel_);
    r.Read("ctrl", ctrl_);
    r.Read("prev_datain", prev_datain_);
    uint8_t rst = 0;
    r.Read("rst_asserted", rst);
    rst_asserted_ = rst != 0u;
    uint8_t irq = 0;
    r.Read("card_irq", irq);
    card_irq_ = irq != 0u;

    /* Every peripheral downstream of the INT pin restores its own copy of the
       line - the pin level in Pr31x00Io's mfio_din_, the latched edge in the
       INTC's status - and restore order across peripherals is unspecified. */
    int_asserted_ = IntLevelLocked();
}

REGISTER_SERVICE(IteIt8368);
