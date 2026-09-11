#include "siemens_mp377_smi_bridge_window.h"

#include "siemens_mp377_smi_bridge.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"

namespace siemens_mp377 {

bool SiemensMp377SmiBridgeWindow::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoard() == Board::SiemensMP377;
}

void SiemensMp377SmiBridgeWindow::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
}

uint8_t SiemensMp377SmiBridgeWindow::ReadByte(uint32_t a) {
    return static_cast<uint8_t>(ReadWord(a & ~3u) >> ((a & 3u) * 8u));
}

uint16_t SiemensMp377SmiBridgeWindow::ReadHalf(uint32_t a) {
    return static_cast<uint16_t>(ReadWord(a & ~3u) >> ((a & 2u) * 8u));
}

uint32_t SiemensMp377SmiBridgeWindow::ReadWord(uint32_t a) {
    const uint32_t rel = RelativeOffset(a);
    if (!IsSupportedOffset(rel)) {
        HaltUnsupportedAccess("MP377 SMI bridge unknown register read", a, 0);
    }
    return emu_.Get<SiemensMp377SmiBridge>().Read(rel);
}

void SiemensMp377SmiBridgeWindow::WriteByte(uint32_t a, uint8_t v) {
    uint32_t w = ReadWord(a & ~3u);
    const uint32_t shift = (a & 3u) * 8u;
    w = (w & ~(0xFFu << shift)) | (static_cast<uint32_t>(v) << shift);
    WriteWord(a & ~3u, w);
}

void SiemensMp377SmiBridgeWindow::WriteHalf(uint32_t a, uint16_t v) {
    uint32_t w = ReadWord(a & ~3u);
    const uint32_t shift = (a & 2u) * 8u;
    w = (w & ~(0xFFFFu << shift)) | (static_cast<uint32_t>(v) << shift);
    WriteWord(a & ~3u, w);
}

void SiemensMp377SmiBridgeWindow::WriteWord(uint32_t a, uint32_t v) {
    const uint32_t rel = RelativeOffset(a);
    if (!IsSupportedOffset(rel)) {
        HaltUnsupportedAccess("MP377 SMI bridge unknown register write", a, v);
    }
    emu_.Get<SiemensMp377SmiBridge>().Write(rel, v);
}

uint32_t SiemensMp377SmiBridgeWindow::RelativeOffset(uint32_t a) const {
    return (a - MmioBase()) & ~3u;
}

bool SiemensMp377SmiBridgeWindow::IsSupportedOffset(uint32_t rel) {
    return rel == 0x04u || rel == 0x08u;
}

} // namespace siemens_mp377
