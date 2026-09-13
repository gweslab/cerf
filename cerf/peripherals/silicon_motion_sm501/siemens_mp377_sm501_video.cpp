#include "siemens_mp377_sm501.h"
#include "siemens_mp377_sm501_fb.h"
#include "siemens_mp377_sm501_internal.h"
#include "siemens_mp377_sm501_video.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"

namespace siemens_mp377 {

bool SiemensMp377Sm501Video::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoard() == Board::SiemensMP377;
}

const uint8_t* SiemensMp377Sm501Video::Vram() {
    return emu_.Get<SiemensMp377Sm501Fb>().Vram();
}

bool SiemensMp377Sm501Video::WasWritten() {
    return emu_.Get<SiemensMp377Sm501Fb>().WasWritten();
}

bool SiemensMp377Sm501Video::WriteVramByte(uint32_t off, uint8_t value) {
    return emu_.Get<SiemensMp377Sm501Fb>().WriteVramByte(off, value);
}

bool SiemensMp377Sm501Video::WriteVramHalf(uint32_t off, uint16_t value) {
    return emu_.Get<SiemensMp377Sm501Fb>().WriteVramHalf(off, value);
}

bool SiemensMp377Sm501Video::WriteVramWord(uint32_t off, uint32_t value) {
    return emu_.Get<SiemensMp377Sm501Fb>().WriteVramWord(off, value);
}

uint32_t SiemensMp377Sm501Video::PanelFbOffset() {
    return emu_.Get<SiemensMp377Sm501Regs>().PanelFbOffset();
}

uint32_t SiemensMp377Sm501Video::PanelWidth() {
    return emu_.Get<SiemensMp377Sm501Regs>().PanelWidthPixels();
}

uint32_t SiemensMp377Sm501Video::PanelHeight() {
    return emu_.Get<SiemensMp377Sm501Regs>().PanelHeightLines();
}

uint32_t SiemensMp377Sm501Video::PanelPitchBytes() {
    return emu_.Get<SiemensMp377Sm501Regs>().PanelPitchBytes();
}

bool SiemensMp377Sm501Video::UsesCrt() {
    /* QEMU v10.1 hw/display/sm501.c sm501_update_display(). */
    return (emu_.Get<SiemensMp377Sm501Regs>().ReadSm501Register(0x080200u) & (1u << 9u)) != 0u;
}

uint32_t SiemensMp377Sm501Video::DisplayFbOffset() {
    return UsesCrt() ? emu_.Get<SiemensMp377Sm501Regs>().CrtFbOffset() : PanelFbOffset();
}

uint32_t SiemensMp377Sm501Video::DisplayPitchBytes() {
    return UsesCrt() ? emu_.Get<SiemensMp377Sm501Regs>().CrtPitchBytes() : PanelPitchBytes();
}

uint32_t SiemensMp377Sm501Video::DisplayWidth() {
    return UsesCrt() ? emu_.Get<SiemensMp377Sm501Regs>().CrtWidthPixels() : PanelWidth();
}

uint32_t SiemensMp377Sm501Video::DisplayHeight() {
    return UsesCrt() ? emu_.Get<SiemensMp377Sm501Regs>().CrtHeightLines() : PanelHeight();
}

uint32_t SiemensMp377Sm501Video::DisplayControl() {
    return emu_.Get<SiemensMp377Sm501Regs>().ReadSm501Register(UsesCrt() ? 0x080200u : 0x080000u);
}

uint32_t SiemensMp377Sm501Video::DisplayPaletteEntry(uint8_t index) {
    const uint32_t base = UsesCrt() ? 0x080C00u : 0x080400u;
    return emu_.Get<SiemensMp377Sm501Regs>().ReadSm501Register(base + static_cast<uint32_t>(index) * 4u);
}

uint32_t SiemensMp377Sm501Video::DisplayCursorAddress() {
    return emu_.Get<SiemensMp377Sm501Regs>().ReadSm501Register(UsesCrt() ? 0x080230u : 0x0800F0u);
}

uint32_t SiemensMp377Sm501Video::DisplayCursorLocation() {
    return emu_.Get<SiemensMp377Sm501Regs>().ReadSm501Register(UsesCrt() ? 0x080234u : 0x0800F4u);
}

uint32_t SiemensMp377Sm501Video::DisplayCursorColors12() {
    return emu_.Get<SiemensMp377Sm501Regs>().ReadSm501Register(UsesCrt() ? 0x080238u : 0x0800F8u);
}

uint32_t SiemensMp377Sm501Video::DisplayCursorColor3() {
    return emu_.Get<SiemensMp377Sm501Regs>().ReadSm501Register(UsesCrt() ? 0x08023Cu : 0x0800FCu);
}

REGISTER_SERVICE(SiemensMp377Sm501Video);

} // namespace siemens_mp377
