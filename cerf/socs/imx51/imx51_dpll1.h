#pragma once

#include "imx51_dpll.h"

class Imx51Dpll1 final : public Imx51Dpll {
public:
    using Imx51Dpll::Imx51Dpll;
    uint32_t MmioBase() const override { return 0x83F80000u; }
};
