#define NOMINMAX

#include "siemens_mp377_sm501_fb.h"
#include "siemens_mp377_sm501_internal.h"

#include "../../boards/board_context.h"
#include "../../boards/siemens_mp377/siemens_mp377_id.h"
#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"

#include <cstdint>

namespace siemens_mp377 {

bool SiemensMp377Sm501Fb::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::SiemensMp377;
}

void SiemensMp377Sm501Fb::OnReady() {
    vram_.assign(kSm501FbBytes, 0u);
    emu_.Get<PeripheralDispatcher>().Register(this);
}

uint32_t SiemensMp377Sm501Fb::MmioBase() const {
    return kSm501FbBarPa;
}

uint32_t SiemensMp377Sm501Fb::MmioSize() const {
    return kSm501FbBytes;
}

uint8_t SiemensMp377Sm501Fb::ReadByte(uint32_t a) {
    return vram_[CpuVramOffset(a)];
}

uint16_t SiemensMp377Sm501Fb::ReadHalf(uint32_t a) {
    return cerf::le::U16(vram_.data(), CpuVramOffset(a));
}

uint32_t SiemensMp377Sm501Fb::ReadWord(uint32_t a) {
    return cerf::le::U32(vram_.data(), CpuVramOffset(a));
}

void SiemensMp377Sm501Fb::WriteByte(uint32_t a, uint8_t v) {
    const size_t i = CpuVramOffset(a);
    vram_[i] = v;
    NoteWrite(static_cast<uint32_t>(i));
}

void SiemensMp377Sm501Fb::WriteHalf(uint32_t a, uint16_t v) {
    const size_t i = CpuVramOffset(a);
    cerf::le::Put16(vram_.data() + i, v);
    NoteWrite(static_cast<uint32_t>(i));
}

void SiemensMp377Sm501Fb::WriteWord(uint32_t a, uint32_t v) {
    const size_t i = CpuVramOffset(a);
    cerf::le::Put32(vram_.data() + i, v);
    NoteWrite(static_cast<uint32_t>(i));
}

const uint8_t* SiemensMp377Sm501Fb::Vram() const {
    return vram_.data();
}

uint8_t* SiemensMp377Sm501Fb::MutableVramFor2d() {
    return vram_.data();
}

bool SiemensMp377Sm501Fb::WasWritten() const {
    return written_;
}

bool SiemensMp377Sm501Fb::WriteVramByte(uint32_t off, uint8_t value) {
    if (off >= kSm501FbBytes) return false;
    vram_[off] = value;
    Note2dWrite(off, 1u);
    return true;
}

bool SiemensMp377Sm501Fb::WriteVramHalf(uint32_t off, uint16_t value) {
    if (off + 1u >= kSm501FbBytes) return false;
    cerf::le::Put16(vram_.data() + off, value);
    Note2dWrite(off, 2u);
    return true;
}

bool SiemensMp377Sm501Fb::WriteVramWord(uint32_t off, uint32_t value) {
    if (off + 3u >= kSm501FbBytes) return false;
    cerf::le::Put32(vram_.data() + off, value);
    Note2dWrite(off, 4u);
    return true;
}

void SiemensMp377Sm501Fb::Note2dWrite(uint32_t off, uint32_t bytes) {
    if (bytes == 0) return;
    NoteWrite(off);
    NoteWrite(off + bytes - 1u);
}

void SiemensMp377Sm501Fb::SaveState(StateWriter& w) {
    const uint64_t n = static_cast<uint64_t>(vram_.size());
    w.Write(n);
    if (n) w.WriteBytes(vram_.data(), static_cast<size_t>(n));
    w.Write(written_);
}

void SiemensMp377Sm501Fb::RestoreState(StateReader& r) {
    uint64_t n = 0;
    r.Read(n);
    if (n != static_cast<uint64_t>(kSm501FbBytes)) {
        HaltUnsupportedAccess("SM501 VRAM state size", kSm501FbBarPa, n);
    }
    vram_.resize(kSm501FbBytes);
    r.ReadBytes(vram_.data(), vram_.size());
    r.Read(written_);
}

uint32_t SiemensMp377Sm501Fb::CpuVramOffset(uint32_t a) {
    uint32_t off = 0;
    if (!Sm501FbPaToOffset(a, off)) {
        HaltUnsupportedAccess("SM501 VRAM address outside BAR0", a, 0);
    }
    return off;
}

void SiemensMp377Sm501Fb::NoteWrite(uint32_t) {
    written_ = true;
}

REGISTER_SERVICE(SiemensMp377Sm501Fb);

} // namespace siemens_mp377
