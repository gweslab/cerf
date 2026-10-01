#pragma once

#include "imx51_dpll.h"

class Imx51Dpll2 final : public Imx51Dpll {
public:
    using Imx51Dpll::Imx51Dpll;
    uint32_t MmioBase() const override { return 0x83F84000u; }
};
