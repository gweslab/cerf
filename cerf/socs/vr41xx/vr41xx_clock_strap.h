#pragma once

#include <cstddef>
#include <cstdint>

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/service.h"

constexpr uint64_t kVr41xxClkxHz = 18432000u;

class Vr41xxClockStrap : public Service {
public:
    using Service::Service;

    virtual uint32_t Clksel() const = 0;

    template <typename Row, size_t N>
    const Row& StrapRow(const Row (&rows)[N]) const {
        const uint32_t clksel = Clksel();
        if (clksel >= N || rows[clksel].clksp == 0u) {
            emu_.Get<Fatal>().Die("Vr41xxClockStrap: CLKSEL %u is RFU on this chip", clksel);
        }
        return rows[clksel];
    }
};
