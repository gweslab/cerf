#include "usb_state.h"
#include "usb_device.h"

#include "../../core/byte_order.h"

#include <algorithm>
#include <cstring>

namespace {

/* USB 2.0 Spec Figure 9-4 (p254): D0 Self Powered, D1 Remote Wakeup. */
uint16_t DeviceStatusBits() { return 0u; }

constexpr size_t kSetupOffRequestType = 0u;
constexpr size_t kSetupOffRequest     = 1u;
constexpr size_t kSetupOffValue       = 2u;
constexpr size_t kSetupOffIndex       = 4u;
constexpr size_t kSetupOffLength      = 6u;

}

UsbDevice::SetupPacket UsbDevice::SetupPacket::Decode(const uint8_t* raw) {
    SetupPacket s{};
    s.bmRequestType = raw[kSetupOffRequestType];
    s.bRequest      = raw[kSetupOffRequest];
    s.wValue        = cerf::le::U16(raw, kSetupOffValue);
    s.wIndex        = cerf::le::U16(raw, kSetupOffIndex);
    s.wLength       = cerf::le::U16(raw, kSetupOffLength);
    return s;
}

void UsbDevice::SetupPacket::Encode(uint8_t* out) const {
    out[kSetupOffRequestType] = bmRequestType;
    out[kSetupOffRequest]     = bRequest;
    cerf::le::Put16(out + kSetupOffValue,  wValue);
    cerf::le::Put16(out + kSetupOffIndex,  wIndex);
    cerf::le::Put16(out + kSetupOffLength, wLength);
}

std::vector<uint8_t> UsbDevice::StandardDeviceDescriptor(uint8_t device_class, uint8_t subclass,
                                                         uint8_t protocol, uint16_t id_vendor,
                                                         uint16_t id_product, uint16_t bcd_device) {
    std::vector<uint8_t> d = {
        uint8_t(kDevDescSize), kDescDevice,
        0x00u, 0x02u,
        device_class, subclass, protocol,
        64u,
        0u, 0u, 0u, 0u, 0u, 0u,
        0u, 0u, 0u,
        1u,
    };
    cerf::le::Put16(d.data() + kDevDescOffIdVendor,  id_vendor);
    cerf::le::Put16(d.data() + kDevDescOffIdProduct, id_product);
    cerf::le::Put16(d.data() + kDevDescOffBcdDevice, bcd_device);
    return d;
}

/* USB 2.0 5.3.2.2: one outstanding request per device's default control pipe. */
bool UsbDevice::BeginControlTransfer(const SetupPacket& setup) {
    FinishControlTransfer();
    if (!HandleSetup(setup, control_reply_)) {
        FinishControlTransfer();
        return false;
    }
    if (control_reply_.size() > setup.wLength) control_reply_.resize(setup.wLength);
    return true;
}

uint32_t UsbDevice::ReadControlReply(uint8_t* dst, uint32_t max) {
    const auto count = std::min(max, static_cast<uint32_t>(control_reply_.size()) - control_reply_offset_);
    if (count) std::memcpy(dst, control_reply_.data() + control_reply_offset_, count);
    control_reply_offset_ += count;
    return count;
}

void UsbDevice::FinishControlTransfer() {
    control_reply_.clear();
    control_reply_offset_ = 0;
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
        data_stage.clear();
        cerf::le::Append16(data_stage, status);
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

void UsbDevice::SaveState(StateWriter& w) {
    w.Write(address_); w.Write(configuration_);
    for (bool stalled : stalled_) w.Write<uint8_t>(stalled ? 1 : 0);
    UsbState::WriteBuffer(w, control_reply_);
    w.Write(control_reply_offset_);
}
void UsbDevice::RestoreState(StateReader& r) {
    r.Read(address_); r.Read(configuration_);
    UsbState::Require(r.Ok() && address_ <= 127 && configuration_ <= ConfigurationCount(),
                      "invalid USB address/configuration");
    for (auto& stalled : stalled_) {
        uint8_t value = 0; r.Read(value);
        UsbState::Require(r.Ok() && value <= 1, "invalid endpoint state");
        stalled = value != 0;
    }
    UsbState::ReadBuffer(r, control_reply_, 65535);
    r.Read(control_reply_offset_);
    UsbState::Require(r.Ok() && control_reply_offset_ <= control_reply_.size(), "invalid control reply");
}
