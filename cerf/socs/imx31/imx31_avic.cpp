#include "imx31_avic.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_detector.h"
#include "../../jit/arm_jit.h"
#include "../../peripherals/peripheral_dispatcher.h"

namespace {

constexpr uint32_t kIntCntlNidisBit = 1u << 22;
constexpr uint32_t kIntCntlFidisBit = 1u << 21;
constexpr uint32_t kIntCntlNmBit    = 1u << 18;

constexpr uint32_t kVectorBase = 0x0100u;
constexpr uint32_t kVectorLast = 0x01FCu;

int32_t Nimask5ToSigned(uint32_t v) {
    const uint32_t five = v & 0x1Fu;
    return (five & 0x10u) ? static_cast<int32_t>(five) - 32
                          : static_cast<int32_t>(five);
}

}  /* namespace */

bool Imx31Avic::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardDetector>();
    return bd && bd->GetSoc() == SocFamily::iMX31;
}

void Imx31Avic::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
}

bool Imx31Avic::IrqActiveLocked() const {
    if ((intcntl_ & kIntCntlNidisBit) != 0) return false;
    const uint64_t nipnd = Nipnd();
    if (nipnd == 0) return false;
    const int32_t nimask_s = Nimask5ToSigned(nimask_);
    for (uint32_t n = 0; n < 64; ++n) {
        if (((nipnd >> n) & 1ull) == 0) continue;
        const uint32_t prio = (niprio_[n / 8u] >> ((n % 8u) * 4u)) & 0xFu;
        if (static_cast<int32_t>(prio) > nimask_s) return true;
    }
    return false;
}

bool Imx31Avic::FiqActiveLocked() const {
    return Fipnd() != 0 && (intcntl_ & kIntCntlFidisBit) == 0;
}

void Imx31Avic::NotifyLocked() {
    if (FiqActiveLocked()) {
        LOG(SocIntc, "[AVIC] FIQ asserted (FIPND=0x%016llX); ArmJit "
                     "exception entry path delivers IRQ only — FIQ is a "
                     "separate ARM nFIQ line that the JIT exception filter "
                     "does not service\n", (unsigned long long)Fipnd());
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    auto& jit = emu_.Get<ArmJit>();
    const bool active = IrqActiveLocked();
    if (active) jit.SetInterruptPending();
    else        jit.ClearInterruptPending();
}

void Imx31Avic::AssertSource(uint32_t source_num) {
    if (source_num >= 64) return;
    const uint64_t mask = 1ull << source_num;
    std::lock_guard<std::mutex> guard(state_mtx_);
    if ((src_hw_ & mask) == 0) {
        src_hw_ |= mask;
        NotifyLocked();
    }
}

void Imx31Avic::DeassertSource(uint32_t source_num) {
    if (source_num >= 64) return;
    const uint64_t mask = 1ull << source_num;
    std::lock_guard<std::mutex> guard(state_mtx_);
    if ((src_hw_ & mask) != 0) {
        src_hw_ &= ~mask;
        NotifyLocked();
    }
}

uint32_t Imx31Avic::VecsrLocked(uint64_t pending) const {
    if (pending == 0) return 0xFFFFFFFFu;
    int      best_src  = -1;
    int32_t  best_prio = -1;
    for (uint32_t n = 0; n < 64; ++n) {
        if (((pending >> n) & 1ull) == 0) continue;
        const int32_t prio =
            static_cast<int32_t>((niprio_[n / 8u] >> ((n % 8u) * 4u)) & 0xFu);
        if (prio > best_prio) { best_prio = prio; best_src = static_cast<int>(n); }
    }
    return (static_cast<uint32_t>(best_src) << 16) |
           static_cast<uint32_t>(best_prio);
}

uint32_t Imx31Avic::ReadRegLocked(uint32_t off) const {
    if (off >= kVectorBase && off <= kVectorLast) {
        return vector_[(off - kVectorBase) / 4u];
    }
    switch (off) {
        case 0x00: return intcntl_;
        case 0x04: return nimask_;
        case 0x08: return 0;
        case 0x0C: return 0;
        case 0x10: return static_cast<uint32_t>(intenable_ >> 32);
        case 0x14: return static_cast<uint32_t>(intenable_ & 0xFFFFFFFFu);
        case 0x18: return static_cast<uint32_t>(inttype_   >> 32);
        case 0x1C: return static_cast<uint32_t>(inttype_   & 0xFFFFFFFFu);
        case 0x20: return niprio_[7];
        case 0x24: return niprio_[6];
        case 0x28: return niprio_[5];
        case 0x2C: return niprio_[4];
        case 0x30: return niprio_[3];
        case 0x34: return niprio_[2];
        case 0x38: return niprio_[1];
        case 0x3C: return niprio_[0];
        /* Table 9-18: [31:16]=source number (0xFFFF if none), [15:0]=its
           priority. DO NOT OR a valid/active bit into [31:16] — the OAL
           reads HIWORD as the raw source number and rejects >=0x40 as
           spurious, so a stray high bit makes every IRQ look spurious. */
        case 0x40: return VecsrLocked(Nipnd());
        case 0x44: return VecsrLocked(Fipnd());
        case 0x48: return static_cast<uint32_t>(Intsrc() >> 32);
        case 0x4C: return static_cast<uint32_t>(Intsrc() & 0xFFFFFFFFu);
        case 0x50: return static_cast<uint32_t>(intfrc_  >> 32);
        case 0x54: return static_cast<uint32_t>(intfrc_  & 0xFFFFFFFFu);
        case 0x58: return static_cast<uint32_t>(Nipnd()  >> 32);
        case 0x5C: return static_cast<uint32_t>(Nipnd()  & 0xFFFFFFFFu);
        case 0x60: return static_cast<uint32_t>(Fipnd()  >> 32);
        case 0x64: return static_cast<uint32_t>(Fipnd()  & 0xFFFFFFFFu);
        default:   return 0;
    }
}

void Imx31Avic::WriteRegLocked(uint32_t off, uint32_t value) {
    if (off >= kVectorBase && off <= kVectorLast) {
        vector_[(off - kVectorBase) / 4u] = value;
        return;
    }
    const uint64_t old_nipnd = Nipnd();
    const uint64_t old_fipnd = Fipnd();
    const bool     old_nidis = (intcntl_ & kIntCntlNidisBit) != 0;
    const bool     old_fidis = (intcntl_ & kIntCntlFidisBit) != 0;

    switch (off) {
        case 0x00:
            if ((value & kIntCntlNmBit) != 0) {
                LOG(SocIntc, "[AVIC] INTCNTL write 0x%08X enables hardware-"
                             "accelerated vector dispatch (NM=1); ArmJit's "
                             "IRQ exception entry path jumps to ARM's single "
                             "0xFFFF0018 vector and does not consume AVIC's "
                             "vector table\n", value);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
            intcntl_ = value;
            break;
        case 0x04:
            nimask_  = value & 0x1Fu;
            break;
        case 0x08: {
            const uint32_t s = value & 0x3Fu;
            intenable_ |= (1ull << s);
            break;
        }
        case 0x0C: {
            const uint32_t s = value & 0x3Fu;
            intenable_ &= ~(1ull << s);
            break;
        }
        case 0x10: intenable_ = (intenable_ & 0xFFFFFFFFull) |
                                (static_cast<uint64_t>(value) << 32);
                   break;
        case 0x14: intenable_ = (intenable_ & 0xFFFFFFFF00000000ull) | value; break;
        case 0x18: inttype_   = (inttype_   & 0xFFFFFFFFull) |
                                (static_cast<uint64_t>(value) << 32);
                   break;
        case 0x1C: inttype_   = (inttype_   & 0xFFFFFFFF00000000ull) | value; break;
        case 0x20: niprio_[7] = value; break;
        case 0x24: niprio_[6] = value; break;
        case 0x28: niprio_[5] = value; break;
        case 0x2C: niprio_[4] = value; break;
        case 0x30: niprio_[3] = value; break;
        case 0x34: niprio_[2] = value; break;
        case 0x38: niprio_[1] = value; break;
        case 0x3C: niprio_[0] = value; break;
        case 0x50: intfrc_    = (intfrc_    & 0xFFFFFFFFull) |
                                (static_cast<uint64_t>(value) << 32);
                   break;
        case 0x54: intfrc_    = (intfrc_    & 0xFFFFFFFF00000000ull) | value; break;
        default:   break;
    }

    const bool nidis_changed = ((intcntl_ & kIntCntlNidisBit) != 0) != old_nidis;
    const bool fidis_changed = ((intcntl_ & kIntCntlFidisBit) != 0) != old_fidis;
    if (Nipnd() != old_nipnd || Fipnd() != old_fipnd ||
        nidis_changed || fidis_changed) {
        NotifyLocked();
    }
}

uint32_t Imx31Avic::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (!IsKnownOffset(off)) HaltUnsupportedAccess("ReadWord", addr, 0);
    std::lock_guard<std::mutex> guard(state_mtx_);
    return ReadRegLocked(off);
}

void Imx31Avic::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (!IsKnownOffset(off)) HaltUnsupportedAccess("WriteWord", addr, value);
    std::lock_guard<std::mutex> guard(state_mtx_);
    WriteRegLocked(off, value);
}

REGISTER_SERVICE(Imx31Avic);
