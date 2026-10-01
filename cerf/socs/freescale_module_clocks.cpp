#include "freescale_module_clocks.h"

#include "../core/cerf_emulator.h"
#include "../core/fatal.h"
#include "../jit/guest_cycle_clock.h"

namespace {

const char* ModuleName(FreescaleModule module) {
    switch (module) {
        case FreescaleModule::kRom:         return "ROM";
        case FreescaleModule::kIim:         return "IIM";
        case FreescaleModule::kUart1:       return "UART1";
        case FreescaleModule::kUart2:       return "UART2";
        case FreescaleModule::kUart3:       return "UART3";
        case FreescaleModule::kUart5:       return "UART5";
        case FreescaleModule::kUart1Ipg:    return "UART1 ipg";
        case FreescaleModule::kUart2Ipg:    return "UART2 ipg";
        case FreescaleModule::kUart3Ipg:    return "UART3 ipg";
        case FreescaleModule::kUart5Ipg:    return "UART5 ipg";
        case FreescaleModule::kI2c1:        return "I2C1";
        case FreescaleModule::kI2c2:        return "I2C2";
        case FreescaleModule::kI2c3:        return "I2C3";
        case FreescaleModule::kSdhc1:       return "SDHC1";
        case FreescaleModule::kEsdhc2:      return "ESDHC2";
        case FreescaleModule::kSsi1:        return "SSI1";
        case FreescaleModule::kSsi2:        return "SSI2";
        case FreescaleModule::kSsi3:        return "SSI3";
        case FreescaleModule::kEcspi1:      return "ECSPI1";
        case FreescaleModule::kCspi2:       return "CSPI2";
        case FreescaleModule::kCspi3:       return "CSPI3";
        case FreescaleModule::kSdma:        return "SDMA";
        case FreescaleModule::kUsbPhy:      return "USB PHY";
        case FreescaleModule::kUsboh3Clk60: return "USBOH3 60 MHz";
        case FreescaleModule::kUsbotg:      return "USBOTG";
        case FreescaleModule::kGpu3dCore:   return "GPU3D core";
        case FreescaleModule::kGpu3dMemory: return "GPU3D memory";
        case FreescaleModule::kVpu:         return "VPU";
        case FreescaleModule::kNfc:         return "NFC";
        case FreescaleModule::kGpu2d:       return "GPU2D";
        case FreescaleModule::kAta:         return "ATA";
        case FreescaleModule::kOwire:       return "1-Wire";
    }
    return "";
}

}

void FreescaleModuleClocks::RequireRunning(FreescaleModule module, const char* operation) {
    const FreescaleLowPowerMode mode = emu_.Get<GuestCycleClock>().InIdle()
        ? emu_.Get<FreescaleTimerClocks>().WfiMode() : FreescaleLowPowerMode::kRun;
    if (ModuleRunsIn(module, mode)) return;
    emu_.Get<Fatal>().Die("FreescaleModuleClocks: %s %s with its module clock off in low-power "
                          "mode %u", ModuleName(module), operation, static_cast<unsigned>(mode));
}
