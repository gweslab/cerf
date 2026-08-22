#include "usb_device.h"

namespace {

/* USB 2.0 Spec Figure 9-4 (p254): D0 Self Powered, D1 Remote Wakeup. */
uint16_t DeviceStatusBits() { return 0u; }

}

bool UsbDevice::HandleSetup(const SetupPacket& setup,
                            std::vector<uint8_t>& data_stage) {
    const uint8_t type   = setup.bmRequestType & kReqTypeMask;
    const uint8_t recip  = setup.bmRequestType & kReqRecipMask;
    const bool    dev2host = (setup.bmRequestType & kReqDirDeviceToHost) != 0u;

    if (type != kReqTypeStandard) {
        return HandleClassRequest(setup, data_stage);
    }

    switch (setup.bRequest) {
    case kReqGetDescriptor: {
        if (!dev2host) return false;
        const uint8_t desc_type  = static_cast<uint8_t>(setup.wValue >> 8);
        const uint8_t desc_index = static_cast<uint8_t>(setup.wValue & 0xFFu);
        std::vector<uint8_t> full;
        if (!GetDescriptor(desc_type, desc_index, setup.wIndex, full)) return false;
        const size_t n = full.size() < setup.wLength ? full.size() : setup.wLength;
        data_stage.assign(full.begin(), full.begin() + static_cast<long>(n));
        return true;
    }
    case kReqSetAddress:
        if (dev2host || setup.wValue > 127u) return false;
        address_ = static_cast<uint8_t>(setup.wValue);
        return true;
    case kReqSetConfiguration:
        if (dev2host || setup.wValue > ConfigurationCount()) return false;
        configuration_ = static_cast<uint8_t>(setup.wValue);
        return true;
    case kReqGetConfiguration:
        if (!dev2host) return false;
        data_stage.assign(1u, configuration_);
        return true;
    case kReqGetStatus: {
        if (!dev2host) return false;
        uint16_t status = 0u;
        if (recip == kReqRecipDevice) {
            status = DeviceStatusBits();
        } else if (recip == kReqRecipEndpoint) {
            const uint8_t ep = static_cast<uint8_t>(setup.wIndex & 0x0Fu);
            status = IsEndpointStalled(ep) ? 1u : 0u;
        }
        data_stage = {static_cast<uint8_t>(status & 0xFFu),
                      static_cast<uint8_t>(status >> 8)};
        return true;
    }
    case kReqClearFeature:
        if (dev2host) return false;
        if (recip == kReqRecipEndpoint && setup.wValue == kFeatureEndpointHalt) {
            SetEndpointStalled(static_cast<uint8_t>(setup.wIndex & 0x0Fu), false);
            return true;
        }
        return false;
    case kReqGetInterface:
        if (!dev2host) return false;
        data_stage.assign(1u, 0u);
        return true;
    case kReqSetInterface:
        return !dev2host && setup.wValue == 0u;
    default:
        return false;
    }
}
