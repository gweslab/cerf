#include "ford_sync2_media_hub.h"
#include "ford_sync2_media_hub_sd_reader.h"

FordSync2MediaHub::FordSync2MediaHub() : UsbHub(kPortCount) {
    Port(kSdPort).SetRestoreFactory([](uint32_t kind) -> std::unique_ptr<UsbDevice> {
        return kind == FordSync2MediaHubSdReader::kStateKind
            ? std::make_unique<FordSync2MediaHubSdReader>() : nullptr;
    });
    Port(kUsbPort).SetRestoreFactory([](uint32_t kind) -> std::unique_ptr<UsbDevice> {
        return kind == UsbMassStorageDevice::kStateKind
            ? std::make_unique<UsbMassStorageDevice>() : nullptr;
    });
}

void FordSync2MediaHub::SetMedia(int port, std::unique_ptr<UsbDevice> device) {
    Port(port).Detach();
    if (device) Port(port).Attach(std::move(device));
}
