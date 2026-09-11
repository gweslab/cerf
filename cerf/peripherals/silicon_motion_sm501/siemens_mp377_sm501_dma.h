#pragma once

#include "../../core/service.h"

#include <cstdint>

namespace siemens_mp377 {

class SiemensMp377Sm501Regs;

inline constexpr uint32_t kSm501DmaIrqBit = 1u << 20;

/* SM501 MSOC Databook, Chapter 13: DMA0 transfers between memory and the
   8051 SRAM; its registers occupy BAR1+0x0D0000..0x0D0020. */
class SiemensMp377Sm501Dma : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;

    static bool IsRegister(uint32_t offset);
    void Reset();
    uint32_t Read(uint32_t offset) const;
    void Write(uint32_t offset, uint32_t value);

private:
    static constexpr uint32_t kSdramAddressReg = 0x0D0000u;
    static constexpr uint32_t kSramAddressReg = 0x0D0004u;
    static constexpr uint32_t kSizeControlReg = 0x0D0008u;
    static constexpr uint32_t kDma1SourceReg = 0x0D0010u;
    static constexpr uint32_t kDma1DestinationReg = 0x0D0014u;
    static constexpr uint32_t kDma1SizeControlReg = 0x0D0018u;
    static constexpr uint32_t kAbortInterruptReg = 0x0D0020u;
    static constexpr uint32_t kActBit = 1u << 31;
    static constexpr uint32_t kDirectionBit = 1u << 30;
    static constexpr uint32_t kSizeMask = 0x0000FFFCu;
    static constexpr uint32_t kSdramExternalBit = 1u << 27;
    static constexpr uint32_t kSdramChipSelectBit = 1u << 26;
    static constexpr uint32_t kSdramAddressMask = 0x03FFFFFCu;
    static constexpr uint32_t kSramAddressMask = 0x0000FFFCu;
    static constexpr uint32_t kAbortChannel0Bit = 1u << 4;
    static constexpr uint32_t kInterruptChannel0Bit = 1u << 0;
    static constexpr uint32_t kAbortChannel1Bit = 1u << 5;
    static constexpr uint32_t kInterruptChannel1Bit = 1u << 1;
    static constexpr uint32_t kDma1SizeMask = 0x00FFFFFCu;

    [[noreturn]] void Unsupported(const char* operation, uint32_t offset, uint32_t value) const;
    bool DecodeSramOffset(uint32_t& offset, uint32_t size);
    bool ReadMemoryByte(uint32_t address, uint8_t& value);
    bool WriteMemoryByte(uint32_t address, uint8_t value);
    void ExecuteTransfer();
    void ExecuteDma1();
    void CompleteTransfer();
    void CompleteDma1();
    void AbortTransfer();
    void AbortDma1();
    SiemensMp377Sm501Regs& Registers() const;
};

} // namespace siemens_mp377
