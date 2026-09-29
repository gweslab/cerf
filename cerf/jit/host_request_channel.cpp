#include "host_request_channel.h"

#include <utility>

void HostRequestChannel::RegisterListener(std::function<void()> fn) {
    listeners_.push_back(std::move(fn));
}

void HostRequestChannel::ServiceRequests() {
    for (auto& fn : listeners_) fn();
}
