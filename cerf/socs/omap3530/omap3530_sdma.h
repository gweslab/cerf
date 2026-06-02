#pragma once

#include "omap3530_sdma_base.h"

#include <cstdint>

class Omap3530Sdma : public Omap3530SdmaBase {
public:
    using Omap3530SdmaBase::Omap3530SdmaBase;

    bool ShouldRegister() override;

    uint32_t MmioBase() const override { return 0x48056000u; }
    uint32_t MmioSize() const override { return 0x00001000u; }

    enum SyncSource : uint32_t {
        kSyncMcbsp3Tx = 17, kSyncMcbsp3Rx = 18,
        kSyncMcbsp4Tx = 19, kSyncMcbsp4Rx = 20,
        kSyncMcbsp5Tx = 21, kSyncMcbsp5Rx = 22,
        kSyncI2c1Tx   = 27, kSyncI2c1Rx   = 28,
        kSyncI2c2Tx   = 29, kSyncI2c2Rx   = 30,
        kSyncMcbsp1Tx = 31, kSyncMcbsp1Rx = 32,
        kSyncMcbsp2Tx = 33, kSyncMcbsp2Rx = 34,
        kSyncSpi1Tx0  = 35, kSyncSpi1Rx0  = 36,
        kSyncSpi1Tx1  = 37, kSyncSpi1Rx1  = 38,
        kSyncSpi1Tx2  = 39, kSyncSpi1Rx2  = 40,
        kSyncSpi1Tx3  = 41, kSyncSpi1Rx3  = 42,
        kSyncSpi2Tx0  = 43, kSyncSpi2Rx0  = 44,
        kSyncSpi2Tx1  = 45, kSyncSpi2Rx1  = 46,
        kSyncMmc2Tx   = 47, kSyncMmc2Rx   = 48,
        kSyncUart1Tx  = 49, kSyncUart1Rx  = 50,
        kSyncUart2Tx  = 51, kSyncUart2Rx  = 52,
        kSyncUart3Tx  = 53, kSyncUart3Rx  = 54,
        kSyncUsb0Tx0  = 55, kSyncUsb0Rx0  = 56,
        kSyncUsb0Tx1  = 57, kSyncUsb0Rx1  = 58,
        kSyncUsb0Tx2  = 59, kSyncUsb0Rx2  = 60,
        kSyncMmc1Tx   = 61, kSyncMmc1Rx   = 62,
        kSyncMmc3Tx   = 77, kSyncMmc3Rx   = 78,
    };

protected:
    uint32_t ChannelCount() const override { return 32u; }
    int      IrqForLine(int j) const override { return 12 + j; }
};
