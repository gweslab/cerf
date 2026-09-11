#pragma once

#include "../../core/service.h"

#include <array>
#include <cstdint>

class Iop13xxAtuState : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;

    struct MemoryWindow {
        uint32_t bar;
        uint32_t wtvr;
    };

    static constexpr uint32_t kMemoryWindowCount = 4u;
    static constexpr uint16_t kAtucmdMemorySpaceEnable = 0x0002u;
    static constexpr uint16_t kAtucmdBusMasterEnable = 0x0004u;
    static constexpr uint32_t kAtucrOutboundEnable = 0x00000002u;
    static constexpr uint32_t kOutboundWindowEnable = 0x80000000u;
    static constexpr uint32_t kOutboundWindowSectionMask = 0x0000000Fu;

    uint16_t Atucmd() const { return atucmd_; }
    uint16_t Atusr() const { return atusr_; }
    uint32_t Atucr() const { return atucr_; }
    uint32_t Atuisr() const { return atuisr_; }
    uint32_t Atuimr() const { return atuimr_; }

    void SetAtucmd(uint16_t v) { atucmd_ = v; }
    void ClearAtusrBits(uint16_t mask) { atusr_ = static_cast<uint16_t>(atusr_ & ~mask); }
    void SetAtucr(uint32_t v) { atucr_ = v; }
    void ClearAtuisrBits(uint32_t mask) { atuisr_ &= ~mask; }
    void SetAtuimr(uint32_t v) { atuimr_ = v; }

    uint32_t Oiobar() const { return oiobar_; }
    uint32_t Oiowtvr() const { return oiowtvr_; }
    void SetOiobar(uint32_t v) { oiobar_ = v; }
    void SetOiowtvr(uint32_t v) { oiowtvr_ = v; }

    const MemoryWindow& Oum(uint32_t idx) const { return oum_[idx]; }
    void SetOumbar(uint32_t idx, uint32_t v) { oum_[idx].bar = v; }
    void SetOumwtvr(uint32_t idx, uint32_t v) { oum_[idx].wtvr = v; }

    bool OutboundGloballyEnabled() const;
    bool BusMasterEnabled() const;
    bool OutboundMemoryWindowEnabled(uint32_t idx) const;

    bool CpuPhysToPciMemBus(uint64_t cpu_pa, uint32_t size, uint64_t& pci_bus_addr) const;

    void SaveCoreState(class StateWriter& w) const;
    void RestoreCoreState(class StateReader& r);
    void SaveOutboundState(class StateWriter& w) const;
    void RestoreOutboundState(class StateReader& r);

private:
    void Reset();
    static bool RangeFitsLow32(uint64_t addr, uint32_t size);

    /* Intel 81341/81342 Developer's Manual 315037-002US, tables 27, 28 and
       63: ATUCMD and ATUCR reset to zero; ATUSR advertises medium DEVSEL,
       66 MHz and capabilities support. */
    uint16_t atucmd_ = 0x0000u;
    uint16_t atusr_ = 0x0230u;
    uint32_t atucr_ = 0x00000000u;
    uint32_t atuisr_ = 0;
    uint32_t atuimr_ = 0;

    uint32_t oiobar_ = 0x0FFFB000u;
    uint32_t oiowtvr_ = 0x00000000u;
    std::array<MemoryWindow, kMemoryWindowCount> oum_{{
        {0x80000001u, 0x00000000u},
        {0x80000002u, 0x00000000u},
        {0x00000003u, 0x00000000u},
        {0x00000004u, 0x00000000u},
    }};
};
