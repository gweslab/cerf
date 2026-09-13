#pragma once

#include "../../core/service.h"
#include "../../core/steady_time.h"

#include <array>
#include <cstdint>
#include <unordered_map>

class StateReader;
class StateWriter;

class SiemensMp377Ertec400Model final : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;

    static bool IsNrtDmacCommand(uint32_t offset);
    static bool IsNrtDmacAddress(uint32_t offset);
    static bool IsReadableRegister(uint32_t offset);
    static bool IsWritableRegister(uint32_t offset);
    static bool IsWriteOnlyRegister(uint32_t offset);

    void BeginAccess() {}
    bool GetWord(uint32_t offset, uint32_t& value) const;
    void SetWord(uint32_t offset, uint32_t value);

    bool ConsumePrimaryReadback(uint32_t& value);
    bool ConsumeSecondaryReadback(uint32_t& value);
    uint32_t FreeRunningCounter10ns() const;
    uint32_t IrtStartTime() const { return irt_start_time_; }
    uint32_t SwitchPortControl() const { return switch_port_control_; }
    uint32_t CyclicCounterLow() const { return cyclic_counter_low_; }
    uint32_t CyclicCounterHigh() const { return cyclic_counter_high_; }
    uint32_t CyclicCounterIncrement() const { return cyclic_counter_increment_; }
    uint32_t CyclicControl() const { return cyclic_control_; }
    uint32_t MulticastPortMask() const { return multicast_port_mask_; }
    uint32_t DefaultRead(uint32_t offset) const;

    void Reset();
    void PublishSwitchReady(uint32_t status);
    void ApplySwitchControl(uint32_t value);
    void CompletePrimaryCommand(uint32_t value);
    void CompleteSecondaryCommand(uint32_t value);
    void WriteMdioControl(uint32_t value);
    void WriteIrtStartTime(uint32_t value);
    void WriteIrtStartCommand(uint32_t value);
    void WriteSwitchPortControl(uint32_t value);
    void WriteCyclicCounterLow(uint32_t value);
    void WriteCyclicCounterHigh(uint32_t value);
    void WriteCyclicCounterIncrement(uint32_t value);
    void WriteCyclicControl(uint32_t value);
    void WriteMulticastPortMask(uint32_t value);

    void SaveState(StateWriter& writer) const;
    void RestoreState(StateReader& reader);

private:
    static uint32_t CanonicalKey(uint32_t offset);
    uint32_t MdioDefault(uint32_t reg) const;
    uint32_t ReadMdio(uint32_t reg) const;
    void WriteMdio(uint32_t reg, uint32_t value);
    std::unordered_map<uint32_t, uint32_t> words_;
    uint32_t mdio_control_ = 0;
    uint32_t last_mdio_register_ = 0x02u;
    std::array<uint32_t, 32> mdio_phy_regs_{};
    std::array<uint8_t, 32> mdio_phy_written_{};
    uint32_t switch_control_ = 0;
    uint32_t switch_status_ = 0x0000FFFFu;
    uint32_t counter_base_10ns_ = 0;
    uint64_t counter_epoch_us_ = 0;
    uint32_t primary_readback_ = 0;
    uint32_t secondary_readback_ = 0;
    bool primary_readback_pending_ = false;
    bool secondary_readback_pending_ = false;
    uint32_t irt_start_time_ = 0;
    uint32_t switch_port_control_ = 0;
    uint32_t cyclic_counter_low_ = 0;
    uint32_t cyclic_counter_high_ = 0;
    uint32_t cyclic_counter_increment_ = 0;
    uint32_t cyclic_control_ = 0;
    uint32_t multicast_port_mask_ = 0;
};
