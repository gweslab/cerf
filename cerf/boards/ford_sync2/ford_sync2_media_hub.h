#pragma once

#include "ford_sync2_media_hub_sd_reader.h"
#include "../../peripherals/usb/usb_hub.h"

class FordSync2UsbMediaHub final : public UsbHub {
public:
    FordSync2UsbMediaHub() : UsbHub(2) {
        for (int i = 0; i < 2; ++i) {
            Port(i).SetRestoreFactory([i](uint32_t kind) -> std::unique_ptr<UsbDevice> {
                if (i == 0 && kind == 3) return std::make_unique<FordSync2MediaHubSdReader>();
                if (i == 1 && kind == 2) return std::make_unique<UsbMassStorageDevice>();
                return {};
            });
        }
    }
    uint32_t StateKind() const override { return 4; }

    void SetMedia(int port, std::unique_ptr<UsbDevice> device) {
        Port(port).Detach();
        if (device) Port(port).Attach(std::move(device));
    }
};
