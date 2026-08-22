#pragma once

#include "../../peripherals/peripheral_base.h"

#include <cstdint>
#include <mutex>

/* Intel PXA27x Developer's Manual 280000-001 Section 18.6 Table 18-14:
   keypad interface registers, 0x4150_0000..0x415F_FFFC. */
class Pxa27xKeypad : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return 0x41500000u; }
    uint32_t MmioSize() const override { return 0x00100000u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override;

    /* Intel PXA27x Developer's Manual 280000-001 Section 18.4.1: eight scan
       outputs and eight sense inputs support up to 64 keys. */
    void SetMatrixKey(uint32_t row, uint32_t col, bool pressed);

private:
    /* Intel PXA27x Developer's Manual 280000-001 Table 18-14. */
    static constexpr uint32_t kKpc      = 0x00u;
    static constexpr uint32_t kKpdk     = 0x08u;
    static constexpr uint32_t kKprec    = 0x10u;
    static constexpr uint32_t kKpmk     = 0x18u;
    static constexpr uint32_t kKpas     = 0x20u;
    static constexpr uint32_t kKpasmkp0 = 0x28u;
    static constexpr uint32_t kKpasmkp1 = 0x30u;
    static constexpr uint32_t kKpasmkp2 = 0x38u;
    static constexpr uint32_t kKpasmkp3 = 0x40u;
    static constexpr uint32_t kKpkdi    = 0x48u;

    uint32_t ReadRegLocked (uint32_t off);
    void     WriteRegLocked(uint32_t off, uint32_t value);

    bool     MatrixIrqPendingLocked() const;
    void     RunAutomaticScanLocked();
    uint32_t SenseRowsLocked() const;
    void     PublishIrq(bool pending);

    static bool IsKnown(uint32_t off);

    mutable std::mutex state_mtx_;

    /* Intel PXA27x Developer's Manual 280000-001 Table 18-3 reset column. */
    uint32_t kpc_   = 0;
    /* Intel PXA27x Developer's Manual 280000-001 Table 18-5 reset column. */
    uint32_t kprec_ = 0;
    /* Intel PXA27x Developer's Manual 280000-001 Table 18-13: Interval field
       defaults to 100 ms upon reset. */
    uint32_t kpkdi_ = 0x0064u;
    /* Intel PXA27x Developer's Manual 280000-001 Table 18-7 reset column:
       RP and CP reset to 0b1111 (data invalid). */
    uint32_t kpas_  = 0x000000FFu;
    /* Intel PXA27x Developer's Manual 280000-001 Tables 18-9..18-12 reset column. */
    uint32_t kpasmkp_[4] = {};

    /* Intel PXA27x Developer's Manual 280000-001 Table 18-6 bit 31 MKP,
       Table 18-3 bit 22 MI, bit 5 DI - each reset when read. */
    bool mkp_ = false;
    bool mi_  = false;
    bool di_  = false;

    /* Intel PXA27x Developer's Manual 280000-001 Section 18.5.1: with IMKP set,
       a new scan is initiated only once all keys are released. */
    bool imkp_latched_ = false;

    uint8_t matrix_col_rows_[8] = {};
};
