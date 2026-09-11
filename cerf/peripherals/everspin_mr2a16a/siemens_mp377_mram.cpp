#include "siemens_mp377_mram.h"

#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../../boards/board_context.h"

namespace siemens_mp377 {

bool SiemensMp377Mram::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoard() == Board::SiemensMP377;
}

void SiemensMp377Mram::OnReady() {
    ResetErased();
    SeedBspioBootState();
    emu_.Get<PeripheralDispatcher>().Register(this);
}

uint32_t SiemensMp377Mram::MmioBase() const {
    return kMp377MramBase;
}
uint32_t SiemensMp377Mram::MmioSize() const {
    return kMp377MramSize;
}

uint8_t SiemensMp377Mram::ReadByte(uint32_t addr) {
    return mram_[addr - MmioBase()];
}

uint16_t SiemensMp377Mram::ReadHalf(uint32_t addr) {
    return static_cast<uint16_t>(ReadByte(addr) | (ReadByte(addr + 1u) << 8));
}

uint32_t SiemensMp377Mram::ReadWord(uint32_t addr) {
    return static_cast<uint32_t>(ReadByte(addr) | (ReadByte(addr + 1u) << 8) | (ReadByte(addr + 2u) << 16) |
                                 (ReadByte(addr + 3u) << 24));
}

void SiemensMp377Mram::WriteByte(uint32_t addr, uint8_t value) {
    mram_[addr - MmioBase()] = value;
}

void SiemensMp377Mram::WriteHalf(uint32_t addr, uint16_t value) {
    WriteByte(addr, static_cast<uint8_t>(value));
    WriteByte(addr + 1u, static_cast<uint8_t>(value >> 8));
}

void SiemensMp377Mram::WriteWord(uint32_t addr, uint32_t value) {
    WriteByte(addr, static_cast<uint8_t>(value));
    WriteByte(addr + 1u, static_cast<uint8_t>(value >> 8));
    WriteByte(addr + 2u, static_cast<uint8_t>(value >> 16));
    WriteByte(addr + 3u, static_cast<uint8_t>(value >> 24));
}

void SiemensMp377Mram::SaveState(StateWriter& w) {
    w.WriteBytes(mram_.data(), mram_.size());
}

void SiemensMp377Mram::RestoreState(StateReader& r) {
    r.ReadBytes(mram_.data(), mram_.size());
}

uint8_t SiemensMp377Mram::ReadAliasByte(uint32_t alias_pa) const {
    return mram_[OffsetFromAlias(alias_pa)];
}

void SiemensMp377Mram::WriteAliasByte(uint32_t alias_pa, uint8_t value) {
    mram_[OffsetFromAlias(alias_pa)] = value;
}

void SiemensMp377Mram::SeedBspioBootState() {
    PutLe32(kMp377BspioBootStateOffset, kMp377BspioBootStateUpdateOnce);
}

void SiemensMp377Mram::ResetErased() {
    mram_.fill(0xFFu);
}

uint32_t SiemensMp377Mram::OffsetFromAlias(uint32_t alias_pa) const {
    return alias_pa - kMp377MramAliasPa;
}

void SiemensMp377Mram::PutLe32(uint32_t off, uint32_t value) {
    mram_[off + 0u] = static_cast<uint8_t>(value);
    mram_[off + 1u] = static_cast<uint8_t>(value >> 8);
    mram_[off + 2u] = static_cast<uint8_t>(value >> 16);
    mram_[off + 3u] = static_cast<uint8_t>(value >> 24);
}

REGISTER_SERVICE(SiemensMp377Mram);

} // namespace siemens_mp377
