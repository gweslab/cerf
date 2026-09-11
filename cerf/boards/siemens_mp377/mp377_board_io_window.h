#pragma once

#include "../../peripherals/peripheral_base.h"

#include "../../peripherals/silicon_motion_sm501/siemens_mp377_sm501_internal.h"
#include "../../peripherals/siemens_ertec400/siemens_mp377_ertec400.h"
#include "siemens_mp377_debug_leds.h"
#include "../../peripherals/everspin_mr2a16a/siemens_mp377_mram.h"
#include "../../peripherals/siemens_aspc2/siemens_mp377_aspc2.h"
#include "siemens_mp377_power_reset.h"

#include "../../core/cerf_emulator.h"
#include "../../jit/arm/arm_jit.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../board_context.h"

#include <atomic>
#include <cstdint>

/* siemens_mp377_v1040 nk.exe OEMAddressTable, VA 0x80409F00. */
namespace mp377_board_io_detail {

using siemens_mp377::kMp377Aspc2Base;
using siemens_mp377::kMp377Aspc2RamPa;
using siemens_mp377::kMp377Aspc2RamSize;
using siemens_mp377::kMp377Aspc2Size;
using siemens_mp377::kMp377MramBase;
using siemens_mp377::kMp377MramSize;
using siemens_mp377::kMp377PowerResetBase;
using siemens_mp377::kMp377PowerResetEnd;
using siemens_mp377::kSmiBridgeBase;
using siemens_mp377::kSmiBridgeEnd;

class Mp377BoardIoWindow : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;
    uint8_t ReadByte(uint32_t addr) override;
    uint16_t ReadHalf(uint32_t addr) override;
    uint32_t ReadWord(uint32_t addr) override;
    void WriteByte(uint32_t addr, uint8_t value) override;
    void WriteHalf(uint32_t addr, uint16_t value) override;
    void WriteWord(uint32_t addr, uint32_t value) override;

};

constexpr uint32_t kEbus1Base = 0xF2000000u;
constexpr uint32_t kEbus1End = 0xF4000000u;

constexpr uint32_t kAtuPrimaryEnd = 0xC8000000u;

/* siemens_mp377_v1040 nk.exe OEMAddressTable, VA 0x80409F00. */
constexpr uint32_t kAtuPrimarySm501RegsBase = 0xC0000000u;
constexpr uint32_t kAtuPrimarySm501RegsEnd = kAtuPrimarySm501RegsBase + siemens_mp377::kSm501RegsBytes;
constexpr uint32_t kAtuPrimarySm501FbBase = 0xC2000000u;
constexpr uint32_t kAtuPrimarySm501FbEnd = kAtuPrimarySm501FbBase + siemens_mp377::kSm501FbBytes;

/* siemens_mp377_v1040 nk.exe, PC 0x804426BC. */
constexpr uint32_t kAtuPrimaryConsoleBase = 0xC4000000u;

inline bool InAtuVramAlias(uint32_t addr, uint32_t bytes) {
    return bytes != 0u && addr >= kAtuPrimaryConsoleBase &&
           (addr - kAtuPrimaryConsoleBase) + bytes <= siemens_mp377::kSm501FbBytes;
}

inline uint32_t AtuConsoleVramOffset(uint32_t addr) {
    return addr - kAtuPrimaryConsoleBase;
}

inline uint32_t AtuPrimarySm501RegsBusAddr(uint32_t addr) {
    return siemens_mp377::kSm501RegsBarBus + (addr - kAtuPrimarySm501RegsBase);
}

inline uint32_t AtuPrimarySm501FbBusAddr(uint32_t addr) {
    return siemens_mp377::kSm501FbBarBus + (addr - kAtuPrimarySm501FbBase);
}

class SiemensMp377AtuOutboundPrimaryGuard : public Mp377BoardIoWindow {
public:
    using Mp377BoardIoWindow::Mp377BoardIoWindow;

    void WriteByte(uint32_t addr, uint8_t value) override {
        if (InAtuVramAlias(addr, 1u)) {
            auto& video = emu_.Get<siemens_mp377::SiemensMp377Sm501Video>();
            if (video.WriteVramByte(AtuConsoleVramOffset(addr), value)) return;
        }
        Mp377BoardIoWindow::WriteByte(addr, value);
    }

    void WriteHalf(uint32_t addr, uint16_t value) override {
        if (InAtuVramAlias(addr, 2u)) {
            auto& video = emu_.Get<siemens_mp377::SiemensMp377Sm501Video>();
            if (video.WriteVramHalf(AtuConsoleVramOffset(addr), value)) return;
        }
        Mp377BoardIoWindow::WriteHalf(addr, value);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        if (InAtuVramAlias(addr, 4u)) {
            auto& video = emu_.Get<siemens_mp377::SiemensMp377Sm501Video>();
            if (video.WriteVramWord(AtuConsoleVramOffset(addr), value)) return;
        }
        Mp377BoardIoWindow::WriteWord(addr, value);
    }
};

} // namespace mp377_board_io_detail
