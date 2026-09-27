#pragma once

#include "../../core/service.h"

#include <cstdint>
#include <mutex>

class StateWriter;
class StateReader;

class Pm8058Irq : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;

    /* Linux drivers/mfd/pm8058-core.c: NUM_BLOCKS 32, IRQS_PER_BLOCK 8. The
       four master status registers each cover eight blocks. */
    static constexpr uint32_t kBlocks       = 32u;
    static constexpr uint32_t kIrqsPerBlock = 8u;
    static constexpr uint32_t kIrqs         = kBlocks * kIrqsPerBlock;
    static constexpr uint32_t kMasters      = 4u;

    uint8_t ReadRoot() const;
    uint8_t ReadMaster(uint32_t master) const;
    uint8_t ReadItStatus() const;
    uint8_t ReadRtStatus() const;
    uint8_t ReadBlockSelect() const;
    uint8_t ReadConfig() const;

    void WriteBlockSelect(uint8_t value);
    void WriteConfig(uint8_t value);

    void SetSourceLevel(uint32_t irq, bool high);
    void GuardLineShape(uint32_t irq);
    void GuardUnmodeledSource(uint32_t irq);
    void RepublishOutput();

    void SaveState(StateWriter& w);
    void RestoreState(StateReader& r);

private:
    uint8_t ReadRootLocked() const;
    uint8_t ReadMasterLocked(uint32_t master) const;
    bool    OutputAssertedLocked() const;
    bool GuardAdmits(uint32_t block, uint32_t bit, uint8_t cfg) const;
    void MarkGuarded(uint8_t (&set)[kBlocks], uint32_t irq);
    void Republish();
    void Reset();

    mutable std::mutex mtx_;

    uint8_t rt_[kBlocks]                 = {};
    uint8_t latched_[kBlocks]            = {};
    uint8_t cfg_[kBlocks][kIrqsPerBlock] = {};
    uint8_t blk_sel_                     = 0;
    uint8_t config_shadow_               = 0;
    uint8_t shape_guard_[kBlocks]        = {};
    uint8_t unmodeled_[kBlocks]          = {};
};
