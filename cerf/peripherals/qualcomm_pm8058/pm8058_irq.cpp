#include "pm8058_irq.h"

#include "pm8058_irq_line.h"

#include "../../boards/board_context.h"
#include "../../boards/nokia_lumia_800/nokia_lumia_800_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../state/state_stream.h"

namespace {

/* Linux drivers/mfd/pm8058-core.c: IRQ_CFG_CLR (1 << 3),
   IRQ_CFG_MASK_RE (1 << 2), IRQ_CFG_MASK_FE (1 << 1),
   IRQ_CFG_LVL_SEL (1 << 0). */
constexpr uint8_t kCfgClr      = 1u << 3;
constexpr uint8_t kCfgMaskRe   = 1u << 2;
constexpr uint8_t kCfgMaskFe   = 1u << 1;
constexpr uint8_t kCfgLvlSel   = 1u << 0;
constexpr uint8_t kCfgRetained = kCfgMaskRe | kCfgMaskFe | kCfgLvlSel;

/* Linux drivers/mfd/pm8058-core.c _write_irq_blk_bit_cfg:
   cfg = (1 << 7) | (cfg & 0xf) | (bit << 4). */
constexpr uint8_t kConfigCommit   = 1u << 7;
constexpr uint8_t kConfigBitShift = 4u;
constexpr uint8_t kConfigBitMask  = 0x7u;
constexpr uint8_t kConfigCfgMask  = 0xFu;

/* Linux drivers/mfd/qcom-pm8xxx.c pm8xxx_irq_handler: "on pm8xxx series
   masters start from bit 1 of the root", then masters = root >> 1 walked over
   num_masters. */
constexpr uint8_t kRootBitShift = 1u;

}  // namespace

bool Pm8058Irq::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::NokiaLumia800;
}

void Pm8058Irq::OnReady() {
    Reset();
    emu_.Get<GuestCpuReset>().RegisterResetListener(
        [this](ResetLineKind) { Reset(); });
}

void Pm8058Irq::Reset() {
    std::lock_guard<std::mutex> lk(mtx_);
    for (uint32_t b = 0; b < kBlocks; ++b) {
        rt_[b]      = 0;
        latched_[b] = 0;
        /* Linux drivers/mfd/pm8058-core.c pm8058_irq_mask sets
           IRQ_CFG_MASK_FE | IRQ_CFG_MASK_RE to mask a source. */
        for (uint32_t i = 0; i < kIrqsPerBlock; ++i) {
            cfg_[b][i] = kCfgMaskRe | kCfgMaskFe;
        }
    }
    blk_sel_       = 0;
    config_shadow_ = 0;
    Republish();
}

uint8_t Pm8058Irq::ReadMasterLocked(uint32_t master) const {
    uint8_t value = 0;
    for (uint32_t i = 0; i < kIrqsPerBlock; ++i) {
        if (latched_[master * kIrqsPerBlock + i] != 0u) {
            value |= (uint8_t)(1u << i);
        }
    }
    return value;
}

uint8_t Pm8058Irq::ReadRootLocked() const {
    uint8_t value = 0;
    for (uint32_t n = 0; n < kMasters; ++n) {
        if (ReadMasterLocked(n) != 0u) {
            value |= (uint8_t)(1u << (n + kRootBitShift));
        }
    }
    return value;
}

bool Pm8058Irq::OutputAssertedLocked() const { return ReadRootLocked() != 0u; }

uint8_t Pm8058Irq::ReadMaster(uint32_t master) const {
    std::lock_guard<std::mutex> lk(mtx_);
    return ReadMasterLocked(master);
}

uint8_t Pm8058Irq::ReadRoot() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return ReadRootLocked();
}

uint8_t Pm8058Irq::ReadItStatus() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return latched_[blk_sel_];
}

uint8_t Pm8058Irq::ReadRtStatus() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return rt_[blk_sel_];
}

uint8_t Pm8058Irq::ReadBlockSelect() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return blk_sel_;
}

uint8_t Pm8058Irq::ReadConfig() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return config_shadow_;
}

void Pm8058Irq::SetSourceLevel(uint32_t irq, bool high) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (irq >= kIrqs) {
        emu_.Get<Fatal>().Die(
            "pm8058 irq: source %u is outside the %u interrupts the part has",
            irq, kIrqs);
    }

    const uint32_t block = irq / kIrqsPerBlock;
    const uint32_t bit   = irq % kIrqsPerBlock;
    const uint8_t  mask  = (uint8_t)(1u << bit);

    const bool was_high = (rt_[block] & mask) != 0u;
    if (high) {
        rt_[block] |= mask;
    } else {
        rt_[block] &= (uint8_t)~mask;
    }

    const uint8_t cfg = cfg_[block][bit];
    const bool on_rising  = (cfg & kCfgMaskRe) == 0u;
    const bool on_falling = (cfg & kCfgMaskFe) == 0u;

    /* Linux drivers/mfd/pm8058-core.c pm8058_irq_ack and pm8058_irq_set_type
       both write cfg_val | IRQ_CFG_CLR, so the latch holds until that bit
       clears it and never follows the source back down. */
    if ((cfg & kCfgLvlSel) != 0u) {
        if (high ? on_rising : on_falling) latched_[block] |= mask;
    } else if (high != was_high && (high ? on_rising : on_falling)) {
        latched_[block] |= mask;
    }

    Republish();
}

void Pm8058Irq::RepublishOutput() {
    std::lock_guard<std::mutex> lk(mtx_);
    Republish();
}

void Pm8058Irq::Republish() {
    if (auto* line = emu_.TryGet<Pm8058IrqLine>()) {
        line->SetPm8058IrqAsserted(OutputAssertedLocked());
    }
}

void Pm8058Irq::WriteBlockSelect(uint8_t value) {
    std::lock_guard<std::mutex> lk(mtx_);
    const uint8_t block = (uint8_t)(value & (kBlocks - 1u));
    if (block != value) {
        emu_.Get<Fatal>().Die(
            "pm8058 irq: block select 0x%02X names a block outside the %u the "
            "part has", value, kBlocks);
    }
    blk_sel_ = block;
}

void Pm8058Irq::WriteConfig(uint8_t value) {
    std::lock_guard<std::mutex> lk(mtx_);
    if ((value & kConfigCommit) == 0u) {
        emu_.Get<Fatal>().Die(
            "pm8058 irq: config write 0x%02X for block %u leaves the commit "
            "bit clear, and no modeled path writes that form",
            value, blk_sel_);
    }

    const uint32_t bit = (value >> kConfigBitShift) & kConfigBitMask;
    const uint8_t  cfg = (uint8_t)(value & kConfigCfgMask);

    config_shadow_      = value;
    cfg_[blk_sel_][bit] = (uint8_t)(cfg & kCfgRetained);

    if ((cfg & kCfgClr) != 0u) {
        latched_[blk_sel_] &= (uint8_t)~(1u << bit);
    }

    Republish();
}

void Pm8058Irq::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(mtx_);
    for (uint32_t b = 0; b < kBlocks; ++b) {
        w.Write<uint8_t>("rt", rt_[b]);
        w.Write<uint8_t>("latched", latched_[b]);
        for (uint32_t i = 0; i < kIrqsPerBlock; ++i) {
            w.Write<uint8_t>("cfg", cfg_[b][i]);
        }
    }
    w.Write<uint8_t>("blk_sel", blk_sel_);
    w.Write<uint8_t>("config_shadow", config_shadow_);
}

void Pm8058Irq::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(mtx_);
    for (uint32_t b = 0; b < kBlocks; ++b) {
        r.Read("rt", rt_[b]);
        r.Read("latched", latched_[b]);
        for (uint32_t i = 0; i < kIrqsPerBlock; ++i) {
            r.Read("cfg", cfg_[b][i]);
        }
    }
    r.Read("blk_sel", blk_sel_);
    r.Read("config_shadow", config_shadow_);
    if (blk_sel_ >= kBlocks) {
        r.Reject(
            "pm8058 irq: restored block select %u is outside the %u blocks the "
            "part has", blk_sel_, kBlocks);
    }
}

REGISTER_SERVICE(Pm8058Irq);
