#include "cerf_debug_tx.h"

#include "cerf_virt_addr_map.h"
#include "../peripheral_dispatcher.h"
#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../core/log.h"
#include "../../host/uart_screen.h"

REGISTER_SERVICE(CerfDebugTxPeripheral);

bool CerfDebugTxPeripheral::ShouldRegister() {
    return emu_.Get<DeviceConfig>().guest_additions;
}

void CerfDebugTxPeripheral::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
}

uint32_t CerfDebugTxPeripheral::MmioBase() const { return CerfVirt::kDebugTxBase; }
uint32_t CerfDebugTxPeripheral::MmioSize() const { return CerfVirt::kDebugTxSize; }

uint8_t  CerfDebugTxPeripheral::ReadByte (uint32_t /*addr*/) { return 0u; }
uint16_t CerfDebugTxPeripheral::ReadHalf (uint32_t /*addr*/) { return 0u; }
uint32_t CerfDebugTxPeripheral::ReadWord (uint32_t /*addr*/) { return 0u; }

void CerfDebugTxPeripheral::WriteByte(uint32_t /*addr*/, uint8_t value) {
    AppendChar(static_cast<char>(value));
}

void CerfDebugTxPeripheral::WriteHalf(uint32_t /*addr*/, uint16_t value) {
    AppendChar(static_cast<char>(value & 0xFFu));
}

void CerfDebugTxPeripheral::WriteWord(uint32_t /*addr*/, uint32_t value) {
    AppendChar(static_cast<char>(value & 0xFFu));
}

void CerfDebugTxPeripheral::AppendChar(char c) {
    std::string flush;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (c == '\n' || c == '\r') {
            if (line_buffer_.empty()) return;
            flush.swap(line_buffer_);
        } else {
            line_buffer_.push_back(c);
            if (line_buffer_.size() < 4096u) return;
            flush.swap(line_buffer_);
        }
    }
    LOG(GuestDriver, "%s\n", flush.c_str());
    emu_.Get<UartScreen>().AddLine(std::string("[guest] ") + flush);
}
