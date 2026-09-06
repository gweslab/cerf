#include "usb_state.h"
#include "usb_hub.h"

#include "../../state/state_stream.h"

namespace {

/* USB 2.0 Spec 11.23.1 (p408): Full-/Low-speed Operating Hub Device
   Descriptor template. */
constexpr uint8_t  kHubClassCode  = 0x09u;
constexpr uint16_t kHubIdVendor   = 0x0424u;
constexpr uint16_t kHubIdProduct  = 0x2640u;
constexpr uint16_t kHubBcdDevice  = 0x08A2u;

/* USB 2.0 Spec 11.23.2.1 Table 11-13 (p417): Hub Descriptor. */
constexpr uint8_t kHubDescriptorType = 0x29u;

/* USB 2.0 Spec 11.23.1 (p408): a single-TT hub sets bDeviceProtocol=1 with
   the interface descriptor's bInterfaceProtocol left at 0. */
constexpr uint8_t kHubDeviceProtocolSingleTt = 1u;

}

UsbHub::UsbHub(int num_ports) {
    for (int i = 0; i < num_ports; ++i) {
        ports_.emplace_back(*this, i);
    }
    port_status_.assign(static_cast<size_t>(num_ports), 0u);
    port_change_.assign(static_cast<size_t>(num_ports), 0u);
}

std::vector<uint8_t> UsbHub::BuildDeviceDescriptor() const {
    return {
        18u, kDescDevice,
        0x00u, 0x02u,
        kHubClassCode, 0u, kHubDeviceProtocolSingleTt,
        64u,
        static_cast<uint8_t>(kHubIdVendor & 0xFFu), static_cast<uint8_t>(kHubIdVendor >> 8),
        static_cast<uint8_t>(kHubIdProduct & 0xFFu), static_cast<uint8_t>(kHubIdProduct >> 8),
        static_cast<uint8_t>(kHubBcdDevice & 0xFFu), static_cast<uint8_t>(kHubBcdDevice >> 8),
        0u, 0u, 0u,
        1u,
    };
}

std::vector<uint8_t> UsbHub::BuildConfigurationDescriptor() const {
    std::vector<uint8_t> d = {
        9u, kDescConfiguration, 25u, 0u, 1u, 1u, 0u, 0xE0u, 0u,
        9u, 4u, 0u, 0u, 1u, kHubClassCode, 0u, 0u, 0u,
        7u, 5u, 0x81u, 0x03u, 8u, 0u, 0xFFu,
    };
    return d;
}

std::vector<uint8_t> UsbHub::BuildHubDescriptor() const {
    const uint8_t n = static_cast<uint8_t>(NumPorts());
    const uint8_t bitmap_bytes = static_cast<uint8_t>((n + 1u + 7u) / 8u);
    std::vector<uint8_t> d = {
        static_cast<uint8_t>(7u + 2u * bitmap_bytes), kHubDescriptorType, n,
        0x04u, 0x00u,
        50u, 0u,
    };
    for (int i = 0; i < 2 * bitmap_bytes; ++i) d.push_back(0u);
    return d;
}

bool UsbHub::GetDescriptor(uint8_t type, uint8_t index, uint16_t /*lang_id*/,
                           std::vector<uint8_t>& out) {
    (void)index;
    if (type == kDescDevice) {
        out = BuildDeviceDescriptor();
        return true;
    }
    if (type == kDescConfiguration) {
        out = BuildConfigurationDescriptor();
        return true;
    }
    if (type == kHubDescriptorType) {
        out = BuildHubDescriptor();
        return true;
    }
    return false;
}

bool UsbHub::HandleClassRequest(const SetupPacket& setup,
                                std::vector<uint8_t>& data_stage) {
    const uint8_t recip = setup.bmRequestType & kReqRecipMask;

    if (setup.bRequest == kHubReqGetDescriptor) {
        return GetDescriptor(kHubDescriptorType, 0u, 0u, data_stage);
    }
    if (setup.bRequest == kHubReqGetStatus && recip == 3u) {
        const int port = static_cast<int>(setup.wIndex) - 1;
        if (port < 0 || port >= NumPorts()) return false;
        const uint16_t status = port_status_[static_cast<size_t>(port)];
        const uint16_t change = port_change_[static_cast<size_t>(port)];
        data_stage = {static_cast<uint8_t>(status & 0xFFu), static_cast<uint8_t>(status >> 8),
                      static_cast<uint8_t>(change & 0xFFu), static_cast<uint8_t>(change >> 8)};
        return true;
    }
    if (setup.bRequest == kHubReqSetFeature && recip == 3u) {
        const int port = static_cast<int>(setup.wIndex) - 1;
        if (port < 0 || port >= NumPorts()) return false;
        auto& status = port_status_[static_cast<size_t>(port)];
        if (setup.wValue == kFeaturePortPower) {
            status |= kPortStatusPower;
            return true;
        }
        if (setup.wValue == kFeaturePortReset) {
            /* USB 2.0 Spec 11.8.2 (p343-344): "Upon exit from the reset
               process, the hub must set the PORT_HIGH_SPEED status bit
               according to the detected speed." */
            status |= kPortStatusEnable | kPortStatusHighSpeed;
            status &= ~kPortStatusReset;
            port_change_[static_cast<size_t>(port)] |= kPortChangeReset;
            if (UsbDevice* dev = ports_[static_cast<size_t>(port)].Device()) {
                dev->ResetToDefault();
            }
            return true;
        }
        return true;
    }
    if (setup.bRequest == kHubReqClearFeature && recip == 3u) {
        const int port = static_cast<int>(setup.wIndex) - 1;
        if (port < 0 || port >= NumPorts()) return false;
        auto& status = port_status_[static_cast<size_t>(port)];
        auto& change = port_change_[static_cast<size_t>(port)];
        if (setup.wValue == kFeaturePortPower)      status &= ~kPortStatusPower;
        else if (setup.wValue == kFeaturePortEnable) status &= ~kPortStatusEnable;
        else if (setup.wValue == kFeatureCPortConnection) change &= ~kPortChangeConnection;
        else if (setup.wValue == kFeatureCPortReset)      change &= ~kPortChangeReset;
        return true;
    }
    return false;
}

uint32_t UsbHub::OnBulkIn(uint8_t /*ep*/, uint8_t* dst, uint32_t max) {
    uint8_t bitmap = 0u;
    for (size_t i = 0; i < port_change_.size(); ++i) {
        if (port_change_[i] != 0u) bitmap |= static_cast<uint8_t>(1u << (i + 1u));
    }
    /* USB 2.0 11.12.1: no status change means NAK, not a zero-length packet. */
    if (bitmap == 0u) return kNak;
    if (max == 0u) return 0u;
    dst[0] = bitmap;
    return 1u;
}

void UsbHub::OnPortConnectChanged(int port_index) {
    if (port_index < 0 || port_index >= NumPorts()) return;
    auto& status = port_status_[static_cast<size_t>(port_index)];
    auto& change = port_change_[static_cast<size_t>(port_index)];
    if (ports_[static_cast<size_t>(port_index)].IsConnected()) {
        status |= kPortStatusConnection;
    } else {
        status &= ~(kPortStatusConnection | kPortStatusEnable);
    }
    change |= kPortChangeConnection;
}

UsbDevice* UsbHub::FindByAddress(uint8_t addr) {
    if (address_ == addr) return this;
    for (auto& p : ports_) {
        if (UsbDevice* dev = p.Device()) {
            if (UsbDevice* found = dev->FindByAddress(addr)) return found;
        }
    }
    return nullptr;
}

void UsbHub::SaveState(StateWriter& w) {
    UsbDevice::SaveState(w);
    w.Write<uint32_t>(static_cast<uint32_t>(ports_.size()));
    for (auto v : port_status_) w.Write(v);
    for (auto v : port_change_) w.Write(v);
    for (auto& p : ports_) p.SaveState(w);
}

void UsbHub::RestoreState(StateReader& r) {
    UsbDevice::RestoreState(r);
    uint32_t ports = 0; r.Read(ports);
    UsbState::Require(r.Ok() && ports == ports_.size(), "hub topology mismatch");
    for (auto& v : port_status_) r.Read(v);
    for (auto& v : port_change_) r.Read(v);
    for (auto& p : ports_) p.RestoreState(r);
}

void UsbHub::PostRestore() {
    for (auto& p : ports_) p.PostRestore();
}
