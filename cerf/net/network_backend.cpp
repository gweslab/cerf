#include "network_backend.h"

#include "mac_address.h"

#include "../core/cerf_emulator.h"
#include "../core/device_config.h"
#include "../core/fatal.h"
#include "../core/log.h"

#include <cstring>

cerf::inet::MacAddress NetworkBackend::ConfiguredGuestMac() const {
    const std::string& s = emu_.Get<DeviceConfig>().network_mac;
    cerf::inet::MacAddress out{};
    if (!cerf::inet::ParseMac(s, out)) {
        LOG(Caution, "FATAL: malformed network_mac='%s' (need XX:XX:XX:XX:XX:XX)\n",
                s.c_str());
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    return out;
}

cerf::inet::MacAddress NetworkBackend::MacForReceiver(const std::string& id,
                                                      ReceiverKind kind) {
    std::lock_guard<std::mutex> lk(rx_mutex_);
    return MacForReceiverLocked(id, kind);
}

cerf::inet::MacAddress NetworkBackend::MacForReceiverLocked(const std::string& id,
                                                            ReceiverKind kind) {
    auto it = ordinals_.find(id);
    if (it == ordinals_.end()) {
        if (kind == ReceiverKind::Ethernet && !configured_mac_taken_) {
            configured_mac_taken_ = true;
            it = ordinals_.emplace(id, uint8_t{0}).first;
        } else {
            if (next_ordinal_ == 0xFFu) {
                emu_.Get<Fatal>().Die(
                    "[NET] receiver ordinal space exhausted adding '%s'", id.c_str());
            }
            it = ordinals_.emplace(id, next_ordinal_++).first;
        }
    }
    cerf::inet::MacAddress mac = GuestMacAddress();
    mac[5] = static_cast<uint8_t>(mac[5] + it->second);
    return mac;
}

cerf::inet::MacAddress NetworkBackend::AttachReceiver(const std::string& id,
                                                      ReceiverKind kind, RxFn cb) {
    std::lock_guard<std::mutex> lk(rx_mutex_);
    const cerf::inet::MacAddress mac = MacForReceiverLocked(id, kind);

    Receiver& r = receivers_[id];
    r.mac = mac;
    r.cb  = std::move(cb);

    LOG(Net, "receiver '%s' attached as %s\n", id.c_str(), cerf::inet::FormatMac(mac.data()).s);
    return mac;
}

void NetworkBackend::DetachReceiver(const std::string& id) {
    std::lock_guard<std::mutex> lk(rx_mutex_);
    receivers_.erase(id);
}

void NetworkBackend::DispatchFrame(const uint8_t* frame, std::size_t len) {
    if (len < 6u) return;

    std::lock_guard<std::mutex> lk(rx_mutex_);

    for (auto& entry : receivers_) {
        Receiver& r = entry.second;
        if (r.cb && std::memcmp(frame, r.mac.data(), 6) == 0) {
            r.cb(frame, len);
            return;
        }
    }

    for (auto& entry : receivers_) {
        Receiver& r = entry.second;
        if (r.cb) r.cb(frame, len);
    }
}
