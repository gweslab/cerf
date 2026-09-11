#pragma once

#include "siemens_mp377_sm501.h"
#include "siemens_mp377_sm501_fb.h"
#include "siemens_mp377_sm501_dma.h"
#include "siemens_mp377_sm501_ac97.h"
#include "siemens_mp377_sm501_audio_output.h"
#include "siemens_mp377_sm501_audio_mcu.h"
#include "siemens_mp377_sm501_power_gpio.h"
#include "siemens_mp377_sm501_regs.h"
#include "siemens_mp377_sm501_video.h"
#include "../../boards/siemens_mp377/siemens_mp377_smi_bridge.h"
#include "../../boards/siemens_mp377/siemens_mp377_smi_bridge_c480.h"
#include "../../boards/siemens_mp377/siemens_mp377_smi_bridge_window.h"
#include "../../boards/siemens_mp377/siemens_mp377_touch_panel.h"

#include "../../peripherals/peripheral_base.h"
#include "../../state/emulation_freeze.h"
#include "../../state/state_stream.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace siemens_mp377 {

class SiemensMp377Sm501Blitter;

/* SM501 Databook v1.02, Tables 2-1 and 2-3; siemens_mp377_v1040
   smibase.dll display-driver initialization. */
inline constexpr uint32_t kSm501Gpio31_0ControlReg = 0x000008u;
inline constexpr uint32_t kSm501SystemControlReg = 0x000000u;
inline constexpr uint32_t kSm501MiscControlReg = 0x000004u;
inline constexpr uint32_t kSm501Gpio63_32ControlReg = 0x00000Cu;
inline constexpr uint32_t kSm501DramControlReg = 0x000010u;
inline constexpr uint32_t kSm501ArbitrationControlReg = 0x000014u;
inline constexpr uint32_t kSm501CommandListStatusReg = 0x000024u;
inline constexpr uint32_t kSm501IrqStatusReg = 0x00002Cu;
inline constexpr uint32_t kSm501IrqMaskReg = 0x000030u;
inline constexpr uint32_t kSm501CurrentGateReg = 0x000038u;
inline constexpr uint32_t kSm501CurrentClockReg = 0x00003Cu;
inline constexpr uint32_t kSm501PowerMode0GateReg = 0x000040u;
inline constexpr uint32_t kSm501PowerMode0ClockReg = 0x000044u;
inline constexpr uint32_t kSm501PowerMode1GateReg = 0x000048u;
inline constexpr uint32_t kSm501PowerMode1ClockReg = 0x00004Cu;
inline constexpr uint32_t kSm501SleepModeGateReg = 0x000050u;
inline constexpr uint32_t kSm501PowerModeControlReg = 0x000054u;
inline constexpr uint32_t kSm501EndianControlReg = 0x00005Cu;
inline constexpr uint32_t kSm501DeviceIdReg = 0x000060u;
inline constexpr uint32_t kSm501GpioDataLowReg = 0x010000u;
inline constexpr uint32_t kSm501GpioDataHighReg = 0x010004u;
inline constexpr uint32_t kSm501GpioDirectionLowReg = 0x010008u;
inline constexpr uint32_t kSm501GpioDirectionHighReg = 0x01000Cu;
inline constexpr uint32_t kSm501GpioIrqSetupReg = 0x010010u;
inline constexpr uint32_t kSm501GpioIrqStatusReg = 0x010014u;

inline constexpr uint32_t kSm501CommandListIdle = 0x00180002u;
inline constexpr uint32_t kSm501PowerModeGateDefault = 0x00021807u;
inline constexpr uint32_t kSm501PowerModeClockDefault = 0x2A1A0A09u;
inline constexpr uint32_t kSm501SleepModeGateDefault = 0x00018000u;
inline constexpr uint32_t kSm501DeviceId = 0x050100A0u;

inline constexpr uint32_t kSm501GateAc97I2sBit = 1u << 18;
inline constexpr uint32_t kSm501Gpio24Ac97RstBit = 1u << 24;
inline constexpr uint32_t kSm501Gpio25Ac97SyncBit = 1u << 25;
inline constexpr uint32_t kSm501Gpio26Ac97BitclkBit = 1u << 26;
inline constexpr uint32_t kSm501Gpio27Ac97SdoutBit = 1u << 27;
inline constexpr uint32_t kSm501Gpio28Ac97SdinBit = 1u << 28;
inline constexpr uint32_t kSm501GpioAc97Mask = kSm501Gpio24Ac97RstBit | kSm501Gpio25Ac97SyncBit |
                                               kSm501Gpio26Ac97BitclkBit | kSm501Gpio27Ac97SdoutBit |
                                               kSm501Gpio28Ac97SdinBit;
inline constexpr uint32_t kSm501GpioAc97OutputMask =
    kSm501Gpio24Ac97RstBit | kSm501Gpio25Ac97SyncBit | kSm501Gpio27Ac97SdoutBit;

inline constexpr uint32_t kMp377CodecResetGpioBit = 1u << 9;

inline bool Sm501IsAc97SharedRegister(uint32_t offset) {
    if (SiemensMp377Sm501Ac97::IsRegister(offset)) return true;
    return offset == kSm501PowerMode0GateReg || offset == kSm501PowerMode0ClockReg ||
           offset == kSm501PowerMode1GateReg || offset == kSm501PowerMode1ClockReg ||
           offset == kSm501SleepModeGateReg || offset == kSm501PowerModeControlReg ||
           offset == kSm501Gpio31_0ControlReg || offset == kSm501GpioDataLowReg ||
           offset == kSm501GpioDirectionLowReg;
}

} // namespace siemens_mp377
