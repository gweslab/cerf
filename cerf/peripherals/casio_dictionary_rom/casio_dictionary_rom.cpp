#include "casio_dictionary_rom.h"

#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/cerf_paths.h"
#include "../../core/device_config.h"
#include "../../core/host_file_bytes.h"

void CasioDictionaryRomWindow::OnReady() {
    const DeviceConfig& cfg = emu_.Get<DeviceConfig>();
    if (!cfg.rom_ce_dictionary.empty()) {
        std::vector<uint8_t> bytes = ReadHostFileBytes(
            ResolveDeviceFile(cfg.device_name, cfg.rom_ce_dictionary));
        if (bytes.size() == MmioSize()) data_ = std::move(bytes);
    }
    OpenBusWindow::OnReady();
}

uint8_t CasioDictionaryRomWindow::ReadByte(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (!data_.empty() && off < data_.size()) return data_[off];
    return OpenBusWindow::ReadByte(addr);
}

uint16_t CasioDictionaryRomWindow::ReadHalf(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (!data_.empty() && off + 2u <= data_.size()) return cerf::le::U16(data_.data(), off);
    return OpenBusWindow::ReadHalf(addr);
}

uint32_t CasioDictionaryRomWindow::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (!data_.empty() && off + 4u <= data_.size()) return cerf::le::U32(data_.data(), off);
    return OpenBusWindow::ReadWord(addr);
}

void CasioDictionaryRomWindow::WriteByte(uint32_t addr, uint8_t value) {
    if (!data_.empty()) return;
    OpenBusWindow::WriteByte(addr, value);
}

void CasioDictionaryRomWindow::WriteHalf(uint32_t addr, uint16_t value) {
    if (!data_.empty()) return;
    OpenBusWindow::WriteHalf(addr, value);
}

void CasioDictionaryRomWindow::WriteWord(uint32_t addr, uint32_t value) {
    if (!data_.empty()) return;
    OpenBusWindow::WriteWord(addr, value);
}
