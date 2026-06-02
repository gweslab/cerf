#define _CRT_SECURE_NO_WARNINGS
#include "null_network_backend.h"
#include "../core/cerf_emulator.h"
#include "../core/device_config.h"
#include "../core/log.h"
#include <cstdio>
#include <cstdlib>

bool NullNetworkBackend::ShouldRegister() {
    return !emu_.Get<DeviceConfig>().network_enabled;
}

static std::array<uint8_t, 6> ParseMac(const std::string& s) {
    std::array<uint8_t, 6> out{};
    unsigned bytes[6] = {};
    int n = std::sscanf(s.c_str(),
                        "%02X:%02X:%02X:%02X:%02X:%02X",
                        &bytes[0], &bytes[1], &bytes[2],
                        &bytes[3], &bytes[4], &bytes[5]);
    if (n != 6) {
        LOG(Caution, "FATAL: malformed network_mac='%s' (need XX:XX:XX:XX:XX:XX)\n", s.c_str());
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    for (int i = 0; i < 6; i++) out[i] = (uint8_t)bytes[i];
    return out;
}

void NullNetworkBackend::SendFrame(const uint8_t* /*frame*/, std::size_t len) {
    if (!tx_logged_once_) {
        LOG(Net, "NullNetworkBackend: dropping TX frame (network_enabled=0). "
                 "Suppressing further drop logs. first_len=%zu\n", len);
        tx_logged_once_ = true;
    }
}

void NullNetworkBackend::SetReceiveCallback(RxFn cb) {
    /* Store but never invoke — there is no host RX in the null backend. */
    rx_cb_ = std::move(cb);
}

std::array<uint8_t, 6> NullNetworkBackend::GuestMacAddress() const {
    if (guest_mac_ == std::array<uint8_t, 6>{}) {
        const_cast<NullNetworkBackend*>(this)->guest_mac_ =
            ParseMac(emu_.Get<DeviceConfig>().network_mac);
    }
    return guest_mac_;
}

std::array<uint8_t, 6> NullNetworkBackend::HostGatewayMacAddress() const {
    /* libslirp's convention — kept identical so consumer code is impl-agnostic. */
    return {0x52, 0x55, 0x0A, 0x00, 0x02, 0x02};
}

REGISTER_SERVICE_AS(NullNetworkBackend, NetworkBackend);
