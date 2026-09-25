#pragma once

#include "../../core/service.h"

#include <cstdint>
#include <string>
#include <vector>

class Vr4121DramDecode : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;

    void Begin(uint16_t cnt1, uint16_t cnt3, uint16_t ramsize);
    void Check(uint16_t cnt1, uint16_t cnt3, uint16_t ramsize) const;
    std::string Mismatch(uint16_t cnt1, uint16_t cnt3, uint16_t ramsize) const;

private:
    struct Chip {
        uint32_t bank  = 0;
        uint32_t base  = 0;
        uint32_t bytes = 0;
    };

    static uint64_t Signature(uint16_t cnt1, uint16_t cnt3, uint16_t ramsize);
    uint32_t SizeCodeBytes(bool dbus32, uint32_t code) const;
    uint32_t BankCapacity(bool dbus32, uint32_t bank, uint16_t cnt1, uint16_t ramsize,
                          std::string& why) const;

    std::vector<Chip> chips_;
    uint64_t          signature_ = 0;
};
