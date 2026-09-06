#pragma once

#include "../core/service.h"

#define NOMINMAX
#include <windows.h>

#include <cstdint>
#include <string>
#include <vector>

class HostKeyBinding : public Service {
public:
    using Service::Service;

    void OnReady() override;

    const std::vector<uint8_t>& Vks() const { return vks_; }

    int IndexOf(uint32_t vk) const;

    uint32_t AllMembersDownMask() const { return (1u << vks_.size()) - 1u; }

    bool AllMembersDownNow() const;

    std::wstring Label() const { return label_; }
    std::wstring LabelWith(const wchar_t* suffix) const;

private:
    std::vector<uint8_t> vks_;
    std::wstring         label_;
};
