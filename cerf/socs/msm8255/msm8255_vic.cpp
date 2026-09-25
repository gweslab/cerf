#include "../irq_controller.h"

#include "../../boards/board_context.h"
#include "msm8255_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../jit/arm/arm_cpu.h"
#include "../../jit/arm/arm_jit.h"
#include "../../jit/arm/cpu_state.h"
#include "../../peripherals/peripheral_base.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"

#include <bit>
#include <cstdint>
#include <mutex>

namespace {

/* Linux arch/arm/mach-msm msm_iomap-7x30.h:
   MSM_VIC_PHYS 0xC0080000, MSM_VIC_SIZE SZ_4K. */
constexpr uint32_t kVicBase = 0xC0080000u;
constexpr uint32_t kVicSize = 0x00001000u;

/* Linux arch/arm/mach-msm irq-vic.c, CONFIG_ARCH_MSM_SCORPION arm. */
constexpr uint32_t kOffSelect0       = 0x000;
constexpr uint32_t kOffEn0           = 0x010;
constexpr uint32_t kOffEnClear0      = 0x020;
constexpr uint32_t kOffEnSet0        = 0x030;
/* irq-vic.c VIC_INT_TYPE0 "1: EDGE, 0: LEVEL". */
constexpr uint32_t kOffType0         = 0x040;
/* irq-vic.c VIC_INT_POLARITY0 "1: NEG". */
constexpr uint32_t kOffPolarity0     = 0x050;
constexpr uint32_t kOffNoPendVal     = 0x060;
/* irq-vic.c VIC_INT_MASTEREN "1: IRQ, 2: FIQ". */
constexpr uint32_t kOffMasterEn      = 0x068;
/* irq-vic.c VIC_CONFIG "1: USE SC VIC". */
constexpr uint32_t kOffConfig        = 0x06C;
constexpr uint32_t kOffIrqStatus0    = 0x080;
constexpr uint32_t kOffFiqStatus0    = 0x090;
constexpr uint32_t kOffRawStatus0    = 0x0A0;
constexpr uint32_t kOffIntClear0     = 0x0B0;
constexpr uint32_t kOffSoftInt0      = 0x0C0;
constexpr uint32_t kOffIrqVecWr      = 0x0D8;
constexpr uint32_t kOffVectPriority0 = 0x200;

constexpr uint32_t kMasterEnIrq = 1u << 0;
constexpr uint32_t kMasterEnFiq = 1u << 1;

/* irq-vic.c: VIC_NUM_REGS is 4 under CONFIG_ARCH_MSM7X30. */
constexpr uint32_t kSourceCount = 128;
constexpr uint32_t kBankCount   = 4;
constexpr uint32_t kBitsPerBank = 32;

class Msm8255Vic : public IrqController {
public:
    using IrqController::IrqController;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Msm8255;
    }

    void OnReady() override {
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
            std::lock_guard<std::mutex> lk(state_mutex_);
            for (uint32_t b = 0; b < kBankCount; ++b) {
                raw_[b] = latch_[b] = enable_[b] = type_[b] = 0u;
                select_[b] = polarity_[b] = softint_[b] = 0u;
            }
            for (uint32_t s = 0; s < kSourceCount; ++s) vect_priority_[s] = 0u;
            no_pend_val_ = 0u;
            master_en_   = 0u;
            config_      = 0u;
            Republish();
        });
    }

    void AssertIrq   (int source_bit)            override;
    void AssertSubIrq(int main_bit, int sub_bit) override;
    void DeAssertIrq (int source_bit)            override;
    void PulseIrq    (int source_bit)            override;
    uint32_t ReadPendingVector()                 override;

    uint32_t ReadReg (uint32_t off);
    void     WriteReg(uint32_t off, uint32_t value);

    void SaveState(StateWriter& w);
    void RestoreState(StateReader& r);
    void PostRestore();

private:
    struct SourceLine {
        uint32_t bank;
        uint32_t mask;
    };

    SourceLine CheckedLine(int source_bit, const char* op) const;
    void       RequireActiveHigh(const SourceLine& line, int source_bit) const;
    uint32_t PendingBank(uint32_t bank) const;
    uint32_t IrqBank(uint32_t bank) const;
    uint32_t FiqBank(uint32_t bank) const;
    bool     HasPendingIrq() const;
    void     Republish();

    static int BankInSet(uint32_t off, uint32_t base) {
        return (off >= base && off < base + 0x10u)
                   ? static_cast<int>((off - base) / 4u)
                   : -1;
    }

    mutable std::mutex state_mutex_;
    uint32_t raw_[kBankCount]{};
    uint32_t latch_[kBankCount]{};
    uint32_t enable_[kBankCount]{};
    uint32_t type_[kBankCount]{};
    uint32_t select_[kBankCount]{};
    uint32_t polarity_[kBankCount]{};
    uint32_t softint_[kBankCount]{};
    uint32_t vect_priority_[kSourceCount]{};
    uint32_t no_pend_val_ = 0;
    uint32_t master_en_   = 0;
    uint32_t config_      = 0;
};

uint32_t Msm8255Vic::PendingBank(uint32_t bank) const {
    return ((latch_[bank] & type_[bank]) | (raw_[bank] & ~type_[bank])) |
           softint_[bank];
}

uint32_t Msm8255Vic::IrqBank(uint32_t bank) const {
    return PendingBank(bank) & enable_[bank] & ~select_[bank];
}

uint32_t Msm8255Vic::FiqBank(uint32_t bank) const {
    return PendingBank(bank) & enable_[bank] & select_[bank];
}

bool Msm8255Vic::HasPendingIrq() const {
    if ((master_en_ & kMasterEnIrq) == 0u) return false;
    for (uint32_t b = 0; b < kBankCount; ++b) {
        if (IrqBank(b) != 0u) return true;
    }
    return false;
}

void Msm8255Vic::Republish() {
    for (uint32_t b = 0; b < kBankCount; ++b) {
        const uint32_t fiq = FiqBank(b);
        if (fiq != 0u && (master_en_ & kMasterEnFiq) != 0u) {
            emu_.Get<Fatal>().Die(
                "msm8255 vic: FIQ source pending in bank %u (mask 0x%08X); FIQ "
                "delivery is not implemented", b, fiq);
        }
    }
    auto& jit = emu_.Get<ArmJit>();
    if (HasPendingIrq()) jit.SetInterruptPending();
    else                 jit.ClearInterruptPending();
}

Msm8255Vic::SourceLine Msm8255Vic::CheckedLine(int source_bit, const char* op) const {
    if (source_bit < 0 || source_bit >= static_cast<int>(kSourceCount)) {
        emu_.Get<Fatal>().Die("msm8255 vic: %s source %d outside 0..%u",
                              op, source_bit, kSourceCount - 1u);
    }
    return { static_cast<uint32_t>(source_bit) / kBitsPerBank,
             1u << (static_cast<uint32_t>(source_bit) % kBitsPerBank) };
}

void Msm8255Vic::RequireActiveHigh(const SourceLine& line, int source_bit) const {
    if ((polarity_[line.bank] & line.mask) != 0u) {
        emu_.Get<Fatal>().Die(
            "msm8255 vic: source %d is programmed active-low; CERF sources "
            "assert logically and the inverted sense is not modelled",
            source_bit);
    }
}

void Msm8255Vic::AssertIrq(int source_bit) {
    const SourceLine line = CheckedLine(source_bit, "AssertIrq");
    std::lock_guard<std::mutex> lk(state_mutex_);
    RequireActiveHigh(line, source_bit);
    if ((raw_[line.bank] & line.mask) == 0u) latch_[line.bank] |= line.mask;
    raw_[line.bank] |= line.mask;
    Republish();
}

void Msm8255Vic::DeAssertIrq(int source_bit) {
    const SourceLine line = CheckedLine(source_bit, "DeAssertIrq");
    std::lock_guard<std::mutex> lk(state_mutex_);
    raw_[line.bank] &= ~line.mask;
    Republish();
}

void Msm8255Vic::PulseIrq(int source_bit) {
    const SourceLine line = CheckedLine(source_bit, "PulseIrq");
    std::lock_guard<std::mutex> lk(state_mutex_);
    RequireActiveHigh(line, source_bit);
    if ((type_[line.bank] & line.mask) == 0u) {
        emu_.Get<Fatal>().Die(
            "msm8255 vic: source %d delivered a zero-width pulse while its "
            "TYPE bit selects level; a pulse on a level line is not modelled",
            source_bit);
    }
    if ((raw_[line.bank] & line.mask) == 0u) latch_[line.bank] |= line.mask;
    Republish();
}

uint32_t Msm8255Vic::ReadPendingVector() {
    std::lock_guard<std::mutex> lk(state_mutex_);
    int      found      = -1;
    uint32_t found_prio = 0;
    if ((master_en_ & kMasterEnIrq) != 0u) {
        for (uint32_t b = 0; b < kBankCount; ++b) {
            uint32_t bits = IrqBank(b);
            while (bits != 0u) {
                const uint32_t src =
                    b * kBitsPerBank +
                    static_cast<uint32_t>(std::countr_zero(bits));
                bits &= bits - 1u;
                const uint32_t prio = vect_priority_[src];
                if (found >= 0) {
                    if (prio != found_prio) {
                        emu_.Get<Fatal>().Die(
                            "msm8255 vic: sources %d and %u are pending together "
                            "at priorities %u and %u, and the order the vectored "
                            "interface applies across priorities is not modelled",
                            found, src, found_prio, prio);
                    }
                    continue;
                }
                found      = static_cast<int>(src);
                found_prio = prio;
            }
        }
    }
    if (found < 0) return no_pend_val_ << 2;
    return static_cast<uint32_t>(found) << 2;
}

void Msm8255Vic::AssertSubIrq(int main_bit, int sub_bit) {
    emu_.Get<Fatal>().Die(
        "msm8255 vic: AssertSubIrq(%d, %d); the MSM VIC has no sub-interrupt "
        "layer", main_bit, sub_bit);
}

uint32_t Msm8255Vic::ReadReg(uint32_t off) {
    if ((off & 0x3u) != 0u) {
        emu_.Get<Fatal>().Die("msm8255 vic: unaligned read at offset 0x%03X",
                              off);
    }
    std::lock_guard<std::mutex> lk(state_mutex_);

    int b;
    if ((b = BankInSet(off, kOffSelect0))    >= 0) return select_[b];
    if ((b = BankInSet(off, kOffEn0))        >= 0) return enable_[b];
    if ((b = BankInSet(off, kOffType0))      >= 0) return type_[b];
    if ((b = BankInSet(off, kOffPolarity0))  >= 0) return polarity_[b];
    if ((b = BankInSet(off, kOffIrqStatus0)) >= 0) return IrqBank(b);
    if ((b = BankInSet(off, kOffFiqStatus0)) >= 0) return FiqBank(b);
    if ((b = BankInSet(off, kOffRawStatus0)) >= 0) return PendingBank(b);

    if (off == kOffMasterEn) return master_en_;

    emu_.Get<Fatal>().Die("msm8255 vic: read of unmodelled offset 0x%03X", off);
}

void Msm8255Vic::WriteReg(uint32_t off, uint32_t value) {
    if ((off & 0x3u) != 0u) {
        emu_.Get<Fatal>().Die("msm8255 vic: unaligned write at offset 0x%03X",
                              off);
    }
    std::lock_guard<std::mutex> lk(state_mutex_);

    if (off >= kOffVectPriority0 &&
        off < kOffVectPriority0 + kSourceCount * 4u) {
        vect_priority_[(off - kOffVectPriority0) / 4u] = value;
        return;
    }

    int b;
    if ((b = BankInSet(off, kOffSelect0)) >= 0) {
        select_[b] = value;
        Republish();
        return;
    }
    if ((b = BankInSet(off, kOffEn0)) >= 0) {
        enable_[b] = value;
        Republish();
        return;
    }
    if ((b = BankInSet(off, kOffEnClear0)) >= 0) {
        enable_[b] &= ~value;
        Republish();
        return;
    }
    if ((b = BankInSet(off, kOffEnSet0)) >= 0) {
        enable_[b] |= value;
        Republish();
        return;
    }
    if ((b = BankInSet(off, kOffType0)) >= 0) {
        type_[b] = value;
        Republish();
        return;
    }
    if ((b = BankInSet(off, kOffPolarity0)) >= 0) {
        polarity_[b] = value;
        return;
    }
    if ((b = BankInSet(off, kOffIntClear0)) >= 0) {
        latch_[b]   &= ~value;
        softint_[b] &= ~value;
        Republish();
        return;
    }
    if ((b = BankInSet(off, kOffSoftInt0)) >= 0) {
        softint_[b] |= value;
        Republish();
        return;
    }

    switch (off) {
        case kOffIrqVecWr:
            return;
        case kOffNoPendVal:
            no_pend_val_ = value;
            return;
        case kOffMasterEn:
            master_en_ = value;
            Republish();
            return;
        case kOffConfig:
            config_ = value;
            return;
        default:
            break;
    }
    emu_.Get<Fatal>().Die("msm8255 vic: write 0x%08X to unmodelled offset 0x%03X",
                          value, off);
}

void Msm8255Vic::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    for (uint32_t b = 0; b < kBankCount; ++b) {
        w.Write<uint32_t>("raw", raw_[b]);
        w.Write<uint32_t>("latch", latch_[b]);
        w.Write<uint32_t>("enable", enable_[b]);
        w.Write<uint32_t>("type", type_[b]);
        w.Write<uint32_t>("select", select_[b]);
        w.Write<uint32_t>("polarity", polarity_[b]);
        w.Write<uint32_t>("softint", softint_[b]);
    }
    for (uint32_t s = 0; s < kSourceCount; ++s) w.Write<uint32_t>("vect_priority", vect_priority_[s]);
    w.Write<uint32_t>("no_pend_val", no_pend_val_);
    w.Write<uint32_t>("master_en", master_en_);
    w.Write<uint32_t>("config", config_);
}

void Msm8255Vic::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(state_mutex_);
    for (uint32_t b = 0; b < kBankCount; ++b) {
        r.Read("raw", raw_[b]);
        r.Read("latch", latch_[b]);
        r.Read("enable", enable_[b]);
        r.Read("type", type_[b]);
        r.Read("select", select_[b]);
        r.Read("polarity", polarity_[b]);
        r.Read("softint", softint_[b]);
    }
    for (uint32_t s = 0; s < kSourceCount; ++s) r.Read("vect_priority", vect_priority_[s]);
    r.Read("no_pend_val", no_pend_val_);
    r.Read("master_en", master_en_);
    r.Read("config", config_);
}

void Msm8255Vic::PostRestore() {
    std::lock_guard<std::mutex> lk(state_mutex_);
    Republish();
}

class Msm8255VicMmio : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Msm8255;
    }

    void OnReady() override { emu_.Get<PeripheralDispatcher>().Register(this); }

    uint32_t MmioBase() const override { return kVicBase; }
    uint32_t MmioSize() const override { return kVicSize; }

    uint32_t ReadWord(uint32_t addr) override {
        return Owner().ReadReg(addr - MmioBase());
    }
    void WriteWord(uint32_t addr, uint32_t value) override {
        Owner().WriteReg(addr - MmioBase(), value);
    }

    void SaveState(StateWriter& w)    override { Owner().SaveState(w); }
    void RestoreState(StateReader& r) override { Owner().RestoreState(r); }
    void PostRestore()                override { Owner().PostRestore(); }

private:
    Msm8255Vic& Owner() {
        return static_cast<Msm8255Vic&>(emu_.Get<IrqController>());
    }
};

}

REGISTER_SERVICE_AS(Msm8255Vic, IrqController);
REGISTER_SERVICE   (Msm8255VicMmio);
