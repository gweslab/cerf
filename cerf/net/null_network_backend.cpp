#include "null_network_backend.h"
#include "../core/cerf_emulator.h"
#include "../core/device_config.h"
#include "../core/log.h"

bool NullNetworkBackend::ShouldRegister() {
    return !emu_.Get<DeviceConfig>().network_enabled;
}

void NullNetworkBackend::SendFrame(const uint8_t* /*frame*/, std::size_t len) {
    if (!tx_logged_once_) {
        LOG(Net, "NullNetworkBackend: dropping TX frame (network_enabled=0). "
                 "Suppressing further drop logs. first_len=%zu\n", len);
        tx_logged_once_ = true;
    }
}

cerf::inet::MacAddress NullNetworkBackend::GuestMacAddress() const {
    if (guest_mac_ == cerf::inet::MacAddress{}) {
        const_cast<NullNetworkBackend*>(this)->guest_mac_ = ConfiguredGuestMac();
    }
    return guest_mac_;
}

REGISTER_SERVICE_AS(NullNetworkBackend, NetworkBackend);
