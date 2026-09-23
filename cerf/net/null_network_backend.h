#pragma once

#include "network_backend.h"

class NullNetworkBackend : public NetworkBackend {
public:
    using NetworkBackend::NetworkBackend;

    bool ShouldRegister() override;

    void SendFrame(const uint8_t* frame, std::size_t len) override;
    cerf::inet::MacAddress GuestMacAddress() const override;

private:
    cerf::inet::MacAddress guest_mac_{};
    bool tx_logged_once_ = false;
};
