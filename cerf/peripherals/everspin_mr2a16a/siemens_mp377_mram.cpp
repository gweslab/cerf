#include "siemens_mp377_mram.h"

#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../../boards/board_context.h"
#include "../../boards/siemens_mp377/siemens_mp377_id.h"

namespace siemens_mp377 {

bool SiemensMp377Mram::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::SiemensMp377;
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
    return cerf::le::U16(mram_.data(), addr - MmioBase());
}

uint32_t SiemensMp377Mram::ReadWord(uint32_t addr) {
    return cerf::le::U32(mram_.data(), addr - MmioBase());
}

void SiemensMp377Mram::WriteByte(uint32_t addr, uint8_t value) {
    mram_[addr - MmioBase()] = value;
}

void SiemensMp377Mram::WriteHalf(uint32_t addr, uint16_t value) {
    cerf::le::Put16(mram_.data() + (addr - MmioBase()), value);
}

void SiemensMp377Mram::WriteWord(uint32_t addr, uint32_t value) {
    cerf::le::Put32(mram_.data() + (addr - MmioBase()), value);
}

void SiemensMp377Mram::SaveState(StateWriter& w) {
    w.WriteBytes("mram", mram_.data(), mram_.size());
}

void SiemensMp377Mram::RestoreState(StateReader& r) {
    r.ReadBytes("mram", mram_.data(), mram_.size());
}

uint8_t SiemensMp377Mram::ReadAliasByte(uint32_t alias_pa) const {
    return mram_[OffsetFromAlias(alias_pa)];
}

void SiemensMp377Mram::WriteAliasByte(uint32_t alias_pa, uint8_t value) {
    mram_[OffsetFromAlias(alias_pa)] = value;
}

void SiemensMp377Mram::SeedBspioBootState() {
    cerf::le::Put32(mram_.data() + kMp377BspioBootStateOffset, kMp377BspioBootStateUpdateOnce);
}

void SiemensMp377Mram::ResetErased() {
    mram_.fill(0xFFu);
}

uint32_t SiemensMp377Mram::OffsetFromAlias(uint32_t alias_pa) const {
    return alias_pa - kMp377MramAliasPa;
}

REGISTER_SERVICE(SiemensMp377Mram);

} // namespace siemens_mp377
