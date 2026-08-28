#include "casio_cassiopeia_e55_lcd.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../lcd/display_size_latch.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../socs/vr41xx/vr41xx_giu.h"
#include "../../state/state_stream.h"
#include "../board_context.h"

#include <cstring>

namespace {

/* casio_cassiopeia_e55 nk.exe @0x9E816B40-@0x9E816B4C load 0xF4 0x84 0xB0 0xD0, stored twice
   by @0x9E816B70-@0x9E816BA4. */
constexpr uint8_t kCtrlSeq84[8] = {0xF4u, 0x84u, 0xB0u, 0xD0u, 0xF4u, 0x84u, 0xB0u, 0xD0u};

/* casio_cassiopeia_e55 nk.exe sub_9E814C70 @0x9E814C70-@0x9E814CE8 and ddi.dll sub_14F0DE0
   @0x14F0E74-@0x14F0F04 both store 0xF4 0xC4 0xB0 0xD0 twice. */
constexpr uint8_t kCtrlSeqC4[8] = {0xF4u, 0xC4u, 0xB0u, 0xD0u, 0xF4u, 0xC4u, 0xB0u, 0xD0u};

}  /* namespace */

bool CasioCassiopeiaE55Lcd::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoard() == Board::CasioCassiopeiaE55;
}

void CasioCassiopeiaE55Lcd::OnReady() {
    fb_.assign(kFbSize, 0u);
    emu_.Get<PeripheralDispatcher>().Register(this);
}

uint8_t CasioCassiopeiaE55Lcd::ReadByte(uint32_t addr) {
    const uint32_t off = addr - kBase;
    if (InFb(off)) return fb_[off];
    HaltUnsupportedAccess("ReadByte", addr, 0);
}

uint16_t CasioCassiopeiaE55Lcd::ReadHalf(uint32_t addr) {
    const uint32_t off = addr - kBase;
    if (InFb(off) && off + 1u < kFbSize) {
        uint16_t v;
        std::memcpy(&v, fb_.data() + off, sizeof(v));
        return v;
    }
    HaltUnsupportedAccess("ReadHalf", addr, 0);
}

uint32_t CasioCassiopeiaE55Lcd::ReadWord(uint32_t addr) {
    const uint32_t off = addr - kBase;
    if (InFb(off) && off + 3u < kFbSize) {
        uint32_t v;
        std::memcpy(&v, fb_.data() + off, sizeof(v));
        return v;
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void CasioCassiopeiaE55Lcd::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off = addr - kBase;
    if (InFb(off)) {
        fb_[off] = value;
        return;
    }
    if (InCtrl(off)) {
        const uint32_t i = off - kCtrlOffset;
        if (value != kCtrlSeq84[i] && value != kCtrlSeqC4[i]) {
            HaltUnsupportedAccess("WriteByte", addr, value);
        }
        ctrl_[i] = value;
        return;
    }
    HaltUnsupportedAccess("WriteByte", addr, value);
}

void CasioCassiopeiaE55Lcd::WriteHalf(uint32_t addr, uint16_t value) {
    const uint32_t off = addr - kBase;
    if (InFb(off) && off + 1u < kFbSize) {
        std::memcpy(fb_.data() + off, &value, sizeof(value));
        return;
    }
    HaltUnsupportedAccess("WriteHalf", addr, value);
}

void CasioCassiopeiaE55Lcd::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - kBase;
    if (InFb(off) && off + 3u < kFbSize) {
        std::memcpy(fb_.data() + off, &value, sizeof(value));
        return;
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

bool CasioCassiopeiaE55Lcd::IsDisplayEnabled() {
    return emu_.Get<Vr41xxGiu>().GetPinLevel(kPanelEnableGpio);
}

void CasioCassiopeiaE55Lcd::MaybePublishDisplaySize() {
    size_latch_.PublishOnce(emu_, IsDisplayEnabled());
}

void CasioCassiopeiaE55Lcd::SaveState(StateWriter& w) {
    for (uint32_t i = 0; i < kCtrlCount; ++i) w.Write(ctrl_[i]);
    size_latch_.SaveState(w);
    w.Write<uint64_t>(fb_.size());
    if (!fb_.empty()) w.WriteBytes(fb_.data(), fb_.size());
}

void CasioCassiopeiaE55Lcd::RestoreState(StateReader& r) {
    for (uint32_t i = 0; i < kCtrlCount; ++i) r.Read(ctrl_[i]);
    size_latch_.RestoreState(r);
    uint64_t n = 0;
    r.Read(n);
    if (n != kFbSize) {
        emu_.Get<Fatal>().Die("CasioCassiopeiaE55Lcd::RestoreState: framebuffer is %llu bytes, "
                              "expected %u", static_cast<unsigned long long>(n), kFbSize);
    }
    fb_.assign(kFbSize, 0u);
    r.ReadBytes(fb_.data(), fb_.size());
}

REGISTER_SERVICE(CasioCassiopeiaE55Lcd);
