#pragma once

#include "../../peripherals/usb/usb_hub.h"

class FordSync2MediaHub final : public UsbHub {
public:
    static constexpr int kSdPort = 0;
    static constexpr int kUsbPort = 1;
    static constexpr int kPortCount = 2;
    static constexpr uint32_t kStateKind = 4;

    FordSync2MediaHub();
    uint32_t StateKind() const override { return kStateKind; }
    void SetMedia(int port, std::unique_ptr<UsbDevice> device);
};
