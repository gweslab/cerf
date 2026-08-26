#include "wm9713_codec.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../state/state_stream.h"

namespace {

/* symbol_mk500 touch.dll FUN_02236e30 @0x02236e30 requires reg 0x7C == 0x574D
   and reg 0x7E == 0x4C13, then decodes reg 0x5A & 0x1C as the revision index
   (0 -> 'A', 4 -> 'B', 8 -> 'C'). FUN_02238118 @0x02238118 names the matching
   part "WM9713/14". */
constexpr uint32_t kRegRevision  = 0x5Au;
constexpr uint32_t kRegVendorId1 = 0x7Cu;
constexpr uint32_t kRegVendorId2 = 0x7Eu;
constexpr uint16_t kWm97xxId1    = 0x574Du;
constexpr uint16_t kWm9713Id2    = 0x4C13u;
constexpr uint16_t kRevisionC    = 0x0008u;

/* symbol_mk500 touch.dll FUN_022371d8 @0x022371d8 writes reg 0x74 with the
   channel selects in bits [7:1], bit 8 to run continuously and bit 9 to start a
   single conversion; FUN_02237060 @0x02237060 then reads reg 0x7A. */
constexpr uint32_t kRegDigitiser1  = 0x74u;
constexpr uint32_t kRegDigitiserRd = 0x7Au;
constexpr uint16_t kDig1SelMask    = 0x00FEu;
constexpr uint16_t kDig1Ctc        = 0x0100u;
constexpr uint16_t kDig1Poll       = 0x0200u;

/* symbol_mk500 touch.dll FUN_022379ac @0x022379ac rejects a sample whose bit 15
   is clear on a pen-required channel, matches bits [14:12] against the channel
   tag from DAT_02231838 @0x02231838, and keeps bits [11:0] as the value. */
constexpr uint16_t kPenDown = 0x8000u;
constexpr uint16_t kAdcMax  = 0x0FFFu;

/* symbol_mk500 touch.dll DAT_02231838 @0x02231838 holds tag = select bit index
   << 12, so select 0x02 tags 0x1000, 0x04 tags 0x2000 and 0x08 tags 0x3000. */
constexpr uint16_t kSelX        = 0x0002u;
constexpr uint16_t kSelY        = 0x0004u;
constexpr uint16_t kSelPressure = 0x0008u;

uint16_t SelBitIndex(uint16_t sel) {
    for (uint16_t b = 1u; b <= 7u; ++b) {
        if (sel & static_cast<uint16_t>(1u << b)) return b;
    }
    return 0u;
}

uint16_t LowestSel(uint16_t sel) {
    return static_cast<uint16_t>(sel & static_cast<uint16_t>(-static_cast<int16_t>(sel)));
}

}  // namespace

bool Wm9713Codec::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoard() == Board::SymbolMk500;
}

void Wm9713Codec::OnReady() {
    reg_[kRegVendorId1] = kWm97xxId1;
    reg_[kRegVendorId2] = kWm9713Id2;
    /* symbol_mk500 touch.dll FUN_022381a0 @0x022381a0 applies the reg 0x5C and
       reg 0x68 errata writes only for revision index 0. */
    reg_[kRegRevision] = kRevisionC;
}

uint16_t Wm9713Codec::ReadReg(uint32_t reg) {
    std::lock_guard<std::mutex> lock(mutex_);
    return reg < kNumRegs ? reg_[reg] : 0u;
}

void Wm9713Codec::WriteReg(uint32_t reg, uint16_t value) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (reg >= kNumRegs) return;
    reg_[reg] = value;
    if (reg != kRegDigitiser1) return;

    LOG(Periph, "[WM9713] DIG1=0x%04X sel=0x%02X%s%s\n", value,
        value & kDig1SelMask, (value & kDig1Ctc) ? " CTC" : "",
        (value & kDig1Poll) ? " POLL" : "");

    if ((value & kDig1Poll) == 0u) return;

    /* symbol_mk500 touch.dll FUN_02237060 @0x02237060 waits for bit 9 of reg
       0x74 to clear, then takes the one tagged word from reg 0x7A. */
    const uint16_t sel = LowestSel(static_cast<uint16_t>(value & kDig1SelMask));
    reg_[kRegDigitiser1] = static_cast<uint16_t>(value & ~kDig1Poll);
    if (sel == 0u) return;
    reg_[kRegDigitiserRd] = MakeWord(sel, pen_down_, raw_x_, raw_y_);
}

bool Wm9713Codec::PopModemSlot(uint16_t& word) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (modem_rx_.empty()) return false;
    word = modem_rx_.front();
    modem_rx_.pop_front();
    return true;
}

void Wm9713Codec::SetPen(bool down, uint16_t raw_x, uint16_t raw_y) {
    std::lock_guard<std::mutex> lock(mutex_);
    pen_down_ = down;
    raw_x_    = raw_x;
    raw_y_    = raw_y;

    const uint16_t dig1 = reg_[kRegDigitiser1];
    if ((dig1 & kDig1Ctc) == 0u) return;

    /* symbol_mk500 touch.dll FUN_02237380 @0x02237380 drains one tagged word per
       enabled select bit, in ascending bit order, for each round it reads. */
    for (uint16_t b = 1u; b <= 7u; ++b) {
        const uint16_t sel = static_cast<uint16_t>(1u << b);
        if ((dig1 & sel) == 0u) continue;
        PushLocked(MakeWord(sel, down, raw_x, raw_y));
    }
}

uint16_t Wm9713Codec::MakeWord(uint16_t sel, bool down, uint16_t raw_x, uint16_t raw_y) {
    uint16_t value = kAdcMax;
    switch (sel) {
        case kSelX:        value = static_cast<uint16_t>(raw_x & kAdcMax); break;
        case kSelY:        value = static_cast<uint16_t>(raw_y & kAdcMax); break;
        case kSelPressure: break;
        default:
            LOG(Caution, "[WM9713] unmodeled digitiser channel sel=0x%02X\n", sel);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    const uint16_t tag = static_cast<uint16_t>(SelBitIndex(sel) << 12);
    return static_cast<uint16_t>((down ? kPenDown : 0u) | tag | value);
}

void Wm9713Codec::PushLocked(uint16_t word) {
    if (modem_rx_.size() >= kModemRxDepth) modem_rx_.pop_front();
    modem_rx_.push_back(word);
}

void Wm9713Codec::SaveState(StateWriter& w) {
    w.WriteBytes(reg_, sizeof(reg_));
}

void Wm9713Codec::RestoreState(StateReader& r) {
    r.ReadBytes(reg_, sizeof(reg_));
}

REGISTER_SERVICE_AS(Wm9713Codec, Ac97Codec);
