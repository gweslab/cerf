#include "../../core/cerf_emulator.h"
#include "../../core/service.h"
#include "../../boards/board_context.h"
#include "../../peripherals/usb/usb_hub.h"
#include "../../peripherals/usb/usb_mass_storage_device.h"
#include "../../socs/imx51/imx51_usboh3.h"
#include "../../storage/disk_image.h"

#include <memory>

namespace {

class FordSync2UsbSdBridge : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoard() == Board::FordSyncGen2;
    }

    void OnReady() override {
        if (!disk_.Open("D:\\Repositories\\cerf\\sdimg\\sdcard_a4.img", 0)) return;

        auto msc = std::make_unique<UsbMassStorageDevice>(disk_);
        auto hub = std::make_unique<UsbHub>(2);
        hub->Port(0).Attach(std::move(msc));
        emu_.Get<Imx51Usboh3>().OtgHostRootPort().Attach(std::move(hub));
    }

private:
    DiskImage disk_;
};

}

REGISTER_SERVICE(FordSync2UsbSdBridge);
