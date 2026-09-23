#pragma once

#include "../core/service.h"
#include "mac_address.h"
#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <mutex>
#include <string>

class NetworkBackend : public Service {
public:
    using Service::Service;

    using RxFn = std::function<void(const uint8_t* frame, std::size_t len)>;

    enum class ReceiverKind {
        Ethernet,
        PointToPoint,
    };

    virtual void SendFrame(const uint8_t* frame, std::size_t len) = 0;

    cerf::inet::MacAddress AttachReceiver(const std::string& id, ReceiverKind kind,
                                          RxFn cb);
    void DetachReceiver(const std::string& id);

    cerf::inet::MacAddress MacForReceiver(const std::string& id, ReceiverKind kind);

    static constexpr cerf::inet::MacAddress kHostGatewayMac{0x52, 0x55, 0x0A, 0x00, 0x02, 0x02};

    virtual cerf::inet::MacAddress GuestMacAddress() const = 0;
    cerf::inet::MacAddress HostGatewayMacAddress() const { return kHostGatewayMac; }

protected:
    void DispatchFrame(const uint8_t* frame, std::size_t len);
    cerf::inet::MacAddress ConfiguredGuestMac() const;

private:
    struct Receiver {
        cerf::inet::MacAddress mac{};
        RxFn                   cb;
    };

    cerf::inet::MacAddress MacForReceiverLocked(const std::string& id,
                                                ReceiverKind kind);

    std::mutex                     rx_mutex_;
    std::map<std::string, uint8_t> ordinals_;
    std::map<std::string, Receiver> receivers_;
    bool                           configured_mac_taken_ = false;
    uint8_t                        next_ordinal_ = 1;
};
