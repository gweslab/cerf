#pragma once

#include "host_virtual_keys.h"

#include <cerfcore/core/service.h>

#include <cstdint>
#include <string>
#include <vector>

namespace cerffrontend {

class HostKeyBinding : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    static constexpr uint8_t kDefaultVk = kVkRControl;

    static std::vector<uint8_t> OrDefault(std::vector<uint8_t> vks);

    void OnReady() override;

    const std::vector<uint8_t>& Vks() const { return vks_; }
    int                         IndexOf(uint32_t vk) const;
    uint32_t                    AllMembersDownMask() const { return (1u << vks_.size()) - 1u; }
    virtual bool                AllMembersDownNow() const = 0;

    const std::string& Label() const { return label_; }
    std::string        LabelWith(const char* suffix) const;

private:
    std::vector<uint8_t> vks_;
    std::string          label_;
};

}
