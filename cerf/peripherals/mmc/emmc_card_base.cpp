#include "emmc_card_base.h"

#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../state/state_stream.h"

using namespace cerf_mmc;

namespace {

constexpr uint32_t kCsdStructure   = 3u;
constexpr uint32_t kSpecVers       = 4u;
constexpr uint32_t kTaac           = 0x0Eu;
constexpr uint32_t kNsac           = 0x00u;
constexpr uint32_t kTranSpeed      = 0x32u;
constexpr uint32_t kCcc            = 0x0F5u;
constexpr uint32_t kReadBlLen      = 0x09u;
constexpr uint32_t kWriteBlLen     = 0x09u;
constexpr uint32_t kCSizeSaturated = 0xFFFu;
constexpr uint32_t kCSizeMult      = 7u;
constexpr uint32_t kEraseGrpSize   = 31u;
constexpr uint32_t kEraseGrpMult   = 31u;
constexpr uint32_t kWpGrpSize      = 0u;
constexpr uint32_t kWpGrpEnable    = 1u;
constexpr uint32_t kR2wFactor      = 4u;

constexpr uint32_t kWpGroupSectors =
    (kWpGrpSize + 1u) * (kEraseGrpSize + 1u) * (kEraseGrpMult + 1u);

constexpr uint32_t kExtCsdBytes          = 512u;
constexpr uint32_t kExtCsdRev            = 192u;
constexpr uint32_t kExtCsdStructure      = 194u;
constexpr uint32_t kExtCsdCardType       = 196u;
constexpr uint32_t kExtCsdSecCount       = 212u;
constexpr uint8_t  kExtCsdRevValue       = 5u;
constexpr uint8_t  kExtCsdStructureValue = 2u;
constexpr uint8_t  kExtCsdCardTypeValue  = 1u;

void PutBits(uint32_t out[4], uint32_t start, uint32_t width, uint32_t value) {
    const uint32_t mask  = (width < 32u) ? ((1u << width) - 1u) : 0xFFFFFFFFu;
    const uint32_t off   = 3u - (start / 32u);
    const uint32_t shift = start & 31u;
    value &= mask;
    out[off] |= value << shift;
    if (width + shift > 32u) {
        out[off - 1u] |= value >> (32u - shift);
    }
}

// JEDEC JESD84-A43 section 10.2
uint8_t Crc7(const uint8_t* data, uint32_t length) {
    uint8_t crc = 0u;
    for (uint32_t i = 0; i < length; ++i) {
        uint8_t byte = data[i];
        for (uint32_t bit = 0; bit < 8u; ++bit) {
            const uint8_t in = static_cast<uint8_t>((byte >> 7) & 1u);
            const uint8_t out = static_cast<uint8_t>((crc >> 6) & 1u);
            crc = static_cast<uint8_t>((crc << 1) & 0x7Fu);
            if (in ^ out) crc ^= 0x09u;
            byte = static_cast<uint8_t>(byte << 1);
        }
    }
    return crc;
}

// JEDEC JESD84-A43 Table 32, Table 34
void SealCrc7(uint32_t out[4]) {
    uint8_t bytes[15];
    for (uint32_t i = 0; i < 15u; ++i) {
        bytes[i] = static_cast<uint8_t>(out[i / 4u] >> (8u * (3u - (i % 4u))));
    }
    out[3] = (out[3] & 0xFFFFFF00u) |
             static_cast<uint32_t>((Crc7(bytes, 15u) << 1) | 1u);
}

}  // namespace

void EmmcCardBase::OnReady() {
    power_on_wp_.assign(WpGroupCount(), 0u);
    emu_.Get<GuestCpuReset>().RegisterResetListener(
        [this](ResetLineKind) { Reset(); });
}

MmcCommandResult EmmcCardBase::Command(uint8_t index, uint32_t argument,
                                       uint32_t response[4]) {
    const MmcState before  = state_;
    const uint16_t arg_rca = static_cast<uint16_t>(argument >> 16);

    read_data_.clear();

    switch (index) {
    case kCmdGoIdleState:
        if (argument != kGoIdleArgument) break;
        multi_read_ = false;
        state_     = MmcState::Idle;
        rca_       = 0u;
        hs_timing_ = 0u;
        user_wp_   = 0u;
        return MmcCommandResult::NoResponse;

    case kCmdIoRwDirect:
        return MmcCommandResult::NoResponse;

    case kCmdSleepAwake:
    case kCmdAppCmd:
        if (before != MmcState::Idle && before != MmcState::Ready &&
            before != MmcState::Ident) {
            break;
        }
        return MmcCommandResult::NoResponse;

    case kCmdSendOpCond:
        if (before != MmcState::Idle) break;
        state_      = MmcState::Ready;
        response[0] =
            kOcrBusy | kOcrSectorAddr | kOcrVoltage | kOcrVoltageDual;
        return MmcCommandResult::Short;

    case kCmdAllSendCid:
        if (before != MmcState::Ready) break;
        state_ = MmcState::Ident;
        BuildCid(response);
        return MmcCommandResult::Long;

    case kCmdSetRelativeAddr:
        if (before != MmcState::Ident) break;
        rca_        = arg_rca;
        state_      = MmcState::Stby;
        response[0] = StatusWord(before);
        return MmcCommandResult::Short;

    case kCmdSendCsd:
        if (before != MmcState::Stby) break;
        if (arg_rca != rca_) return MmcCommandResult::NoResponse;
        BuildCsd(response);
        return MmcCommandResult::Long;

    case kCmdSendCid:
        if (before != MmcState::Stby) break;
        if (arg_rca != rca_) return MmcCommandResult::NoResponse;
        BuildCid(response);
        return MmcCommandResult::Long;

    case kCmdSelectCard:
        if (before == MmcState::Stby && arg_rca == rca_ && rca_ != 0u) {
            state_      = MmcState::Tran;
            response[0] = StatusWord(before);
            return MmcCommandResult::Short;
        }
        if (before == MmcState::Tran && arg_rca != rca_) {
            state_ = MmcState::Stby;
            return MmcCommandResult::NoResponse;
        }
        break;

    case kCmdSendStatus:
        if (before != MmcState::Stby && before != MmcState::Tran &&
            before != MmcState::Data) {
            break;
        }
        if (arg_rca != rca_) return MmcCommandResult::NoResponse;
        response[0] = StatusWord(before);
        return MmcCommandResult::Short;

    case kCmdSwitch:
        if (before != MmcState::Tran) break;
        ApplySwitch(argument);
        response[0] = StatusWord(before);
        return MmcCommandResult::Short;

    case kCmdSendExtCsd:
        if (before == MmcState::Idle) return MmcCommandResult::NoResponse;
        if (before != MmcState::Tran) break;
        BuildExtCsd();
        multi_read_ = false;
        state_      = MmcState::Data;
        response[0] = StatusWord(before);
        return MmcCommandResult::Short;

    case kCmdReadSingleBlock:
    case kCmdReadMultiBlock:
        if (before != MmcState::Tran) break;
        if (argument >= SectorCount()) {
            response[0] = StatusWord(before) | kR1AddressOutOfRange;
            return MmcCommandResult::Short;
        }
        read_data_.resize(kBlockBytes);
        ReadBlock(argument, read_data_.data());
        multi_read_  = (index == kCmdReadMultiBlock);
        next_sector_ = argument + 1u;
        state_       = MmcState::Data;
        response[0]  = StatusWord(before);
        return MmcCommandResult::Short;

    case kCmdStopTransmission:
        if (before != MmcState::Data) break;
        if ((argument & kStopHpi) != 0u) {
            emu_.Get<Fatal>().Die(
                "eMMC card in slot %u: STOP_TRANSMISSION argument 0x%08X sets "
                "the high priority interrupt bit, which is not modeled",
                SlotIndex(), argument);
        }
        multi_read_ = false;
        state_      = MmcState::Tran;
        response[0] = StatusWord(before);
        return MmcCommandResult::Short;

    case kCmdSetWriteProt:
        if (before != MmcState::Tran) break;
        if (argument >= SectorCount()) {
            response[0] = StatusWord(before) | kR1AddressOutOfRange;
            return MmcCommandResult::Short;
        }
        SetWriteProtect(argument);
        response[0] = StatusWord(before);
        return MmcCommandResult::Short;

    default:
        break;
    }

    HaltUnmodelledCommand(index, argument);
}

void EmmcCardBase::EndDataPhase() {
    if (state_ != MmcState::Data) {
        emu_.Get<Fatal>().Die(
            "eMMC card in slot %u: the host finished a data phase while the "
            "card is in state %u", SlotIndex(),
            static_cast<unsigned>(state_));
    }
    if (!multi_read_) state_ = MmcState::Tran;
}

void EmmcCardBase::NextBlock() {
    if (state_ != MmcState::Data || !multi_read_) {
        emu_.Get<Fatal>().Die(
            "eMMC card in slot %u: the host asked for another block while the "
            "card is in state %u with no multiple block read open", SlotIndex(),
            static_cast<unsigned>(state_));
    }
    if (next_sector_ >= SectorCount()) {
        emu_.Get<Fatal>().Die(
            "eMMC card in slot %u: a multiple block read runs past the last "
            "sector into sector %u, and the error reported to the stop command "
            "is not modeled", SlotIndex(), next_sector_);
    }
    read_data_.resize(kBlockBytes);
    ReadBlock(next_sector_, read_data_.data());
    ++next_sector_;
}

void EmmcCardBase::Reset() {
    state_     = MmcState::Idle;
    rca_       = 0u;
    hs_timing_ = 0u;
    user_wp_   = 0u;
    multi_read_  = false;
    next_sector_ = 0u;
    power_on_wp_.assign(power_on_wp_.size(), 0u);
    read_data_.clear();
}

uint32_t EmmcCardBase::WpGroupCount() const {
    return (SectorCount() + kWpGroupSectors - 1u) / kWpGroupSectors;
}

void EmmcCardBase::SetWriteProtect(uint32_t sector) {
    if (sector % kWpGroupSectors != 0u) {
        emu_.Get<Fatal>().Die(
            "eMMC card in slot %u: SET_WRITE_PROT addresses sector %u, which is "
            "not on a %u-sector write protect group boundary", SlotIndex(),
            sector, kWpGroupSectors);
    }
    if ((user_wp_ & kUserWpPwrWpEn) == 0u) {
        emu_.Get<Fatal>().Die(
            "eMMC card in slot %u: SET_WRITE_PROT with USER_WP 0x%02X applies "
            "temporary write protection, which is not modeled", SlotIndex(),
            static_cast<unsigned>(user_wp_));
    }
    power_on_wp_[sector / kWpGroupSectors] = 1u;
}

void EmmcCardBase::BuildExtCsd() {
    read_data_.assign(kExtCsdBytes, 0u);
    const uint32_t sectors = SectorCount();
    for (uint32_t i = 0; i < 4u; ++i) {
        read_data_[kExtCsdSecCount + i] =
            static_cast<uint8_t>(sectors >> (8u * i));
    }
    read_data_[kExtCsdRev]       = kExtCsdRevValue;
    read_data_[kExtCsdStructure] = kExtCsdStructureValue;
    read_data_[kExtCsdCardType]  = kExtCsdCardTypeValue;
    read_data_[kExtCsdHsTiming]  = hs_timing_;
    read_data_[kExtCsdUserWp]    = user_wp_;
}

uint32_t EmmcCardBase::StatusWord(MmcState before) const {
    return kR1ReadyForData | (static_cast<uint32_t>(before) << kR1StateShift);
}

void EmmcCardBase::BuildCid(uint32_t out[4]) const {
    const SdCardCid cid = Cid();
    for (uint32_t i = 0; i < 4u; ++i) out[i] = cerf::be::U32(cid.data(), i * 4u);
    SealCrc7(out);
}

void EmmcCardBase::BuildCsd(uint32_t out[4]) const {
    out[0] = out[1] = out[2] = out[3] = 0u;
    PutBits(out, 126u, 2u,  kCsdStructure);
    PutBits(out, 122u, 4u,  kSpecVers);
    PutBits(out, 112u, 8u,  kTaac);
    PutBits(out, 104u, 8u,  kNsac);
    PutBits(out,  96u, 8u,  kTranSpeed);
    PutBits(out,  84u, 12u, kCcc);
    PutBits(out,  80u, 4u,  kReadBlLen);
    PutBits(out,  62u, 12u, kCSizeSaturated);
    PutBits(out,  47u, 3u,  kCSizeMult);
    PutBits(out,  42u, 5u,  kEraseGrpSize);
    PutBits(out,  37u, 5u,  kEraseGrpMult);
    PutBits(out,  32u, 5u,  kWpGrpSize);
    PutBits(out,  31u, 1u,  kWpGrpEnable);
    PutBits(out,  26u, 3u,  kR2wFactor);
    PutBits(out,  22u, 4u,  kWriteBlLen);
    SealCrc7(out);
}

void EmmcCardBase::ApplySwitch(uint32_t argument) {
    const uint32_t access =
        (argument >> kSwitchAccessShift) & kSwitchAccessMask;
    const uint32_t index = (argument >> kSwitchIndexShift) & kSwitchByteMask;
    const uint32_t value = (argument >> kSwitchValueShift) & kSwitchByteMask;

    if (index == kExtCsdUserWp) {
        ApplyUserWp(access, value);
        return;
    }
    if (access != kSwitchWriteByte) {
        emu_.Get<Fatal>().Die(
            "eMMC card in slot %u: SWITCH access mode %u is not modeled",
            SlotIndex(), access);
    }
    if (index == kExtCsdBusWidth) {
        if (value > kBusWidth8Bit) {
            emu_.Get<Fatal>().Die(
                "eMMC card in slot %u: SWITCH selects bus mode %u, which is "
                "reserved", SlotIndex(), value);
        }
        return;
    }
    if (index == kExtCsdHsTiming) {
        if (value > kHsTimingHighSpeed) {
            emu_.Get<Fatal>().Die(
                "eMMC card in slot %u: SWITCH selects interface timing %u, "
                "which is not a value this card accepts", SlotIndex(), value);
        }
        hs_timing_ = static_cast<uint8_t>(value);
        return;
    }
    emu_.Get<Fatal>().Die(
        "eMMC card in slot %u: SWITCH writes extended CSD byte %u, which is "
        "not modeled", SlotIndex(), index);
}

void EmmcCardBase::ApplyUserWp(uint32_t access, uint32_t value) {
    uint32_t next = user_wp_;
    switch (access) {
    case kSwitchSetBits:   next |= value;  break;
    case kSwitchClearBits: next &= ~value; break;
    case kSwitchWriteByte: next = value;   break;
    default:
        emu_.Get<Fatal>().Die(
            "eMMC card in slot %u: SWITCH access mode %u on USER_WP is not "
            "modeled", SlotIndex(), access);
    }
    if ((next & ~kUserWpPwrWpEn) != 0u) {
        emu_.Get<Fatal>().Die(
            "eMMC card in slot %u: SWITCH leaves USER_WP at 0x%02X, which sets a "
            "bit that is not modeled", SlotIndex(), next);
    }
    user_wp_ = static_cast<uint8_t>(next);
}

void EmmcCardBase::HaltUnmodelledCommand(uint8_t index, uint32_t argument) {
    emu_.Get<Fatal>().Die(
        "eMMC card in slot %u: CMD%u with argument 0x%08X in card state %u is "
        "not modeled", SlotIndex(), static_cast<unsigned>(index), argument,
        static_cast<unsigned>(state_));
}

void EmmcCardBase::SaveState(StateWriter& w) {
    w.Write<uint32_t>("state", static_cast<uint32_t>(state_));
    w.Write<uint32_t>("rca", rca_);
    w.Write<uint32_t>("hs_timing", hs_timing_);
    w.Write<uint32_t>("user_wp", user_wp_);
    w.Write<uint32_t>("multi_read", multi_read_ ? 1u : 0u);
    w.Write<uint32_t>("next_sector", next_sector_);
    w.WriteBytes("power_on_wp", power_on_wp_.data(), power_on_wp_.size());
}

void EmmcCardBase::RestoreState(StateReader& r) {
    uint32_t state     = 0u;
    uint32_t rca       = 0u;
    uint32_t hs_timing = 0u;
    uint32_t user_wp   = 0u;
    uint32_t multi     = 0u;
    uint32_t next      = 0u;
    r.Read("state", state);
    r.Read("rca", rca);
    r.Read("hs_timing", hs_timing);
    r.Read("user_wp", user_wp);
    r.Read("multi_read", multi);
    r.Read("next_sector", next);
    if (multi > 1u || next > SectorCount() ||
        (multi == 1u && state != static_cast<uint32_t>(MmcState::Data))) {
        r.Reject(
            "eMMC card in slot %u: restored multiple block read %u at sector %u "
            "in state %u is not a read this card can hold", SlotIndex(), multi,
            next, state);
    }
    multi_read_  = (multi == 1u);
    next_sector_ = next;
    r.ReadBytes("power_on_wp", power_on_wp_.data(), power_on_wp_.size());
    for (const uint8_t group : power_on_wp_) {
        if (group > 1u) {
            r.Reject(
                "eMMC card in slot %u: restored write protect group state %u is "
                "not a state this card can hold", SlotIndex(),
                static_cast<unsigned>(group));
        }
    }
    if ((user_wp & ~kUserWpPwrWpEn) != 0u) {
        r.Reject(
            "eMMC card in slot %u: restored USER_WP 0x%02X sets a bit this card "
            "cannot hold", SlotIndex(), user_wp);
    }
    user_wp_ = static_cast<uint8_t>(user_wp);
    if (hs_timing > kHsTimingHighSpeed) {
        r.Reject(
            "eMMC card in slot %u: restored interface timing %u is not a value "
            "this card can hold", SlotIndex(), hs_timing);
    }
    hs_timing_ = static_cast<uint8_t>(hs_timing);
    if (state > static_cast<uint32_t>(MmcState::Data) || rca > 0xFFFFu) {
        r.Reject(
            "eMMC card in slot %u: restored state %u rca 0x%X is not a state "
            "this card can reach", SlotIndex(), state, rca);
    }
    state_ = static_cast<MmcState>(state);
    rca_   = static_cast<uint16_t>(rca);
}
