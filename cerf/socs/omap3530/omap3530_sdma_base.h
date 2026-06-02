#pragma once

#include "../../peripherals/peripheral_base.h"

#include <cstdint>
#include <mutex>
#include <vector>

class Omap3530SdmaBase : public Peripheral {
public:
    using Peripheral::Peripheral;

    void OnReady() override;

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void RaiseSyncEvent(uint32_t source);

protected:
    virtual uint32_t ChannelCount() const = 0;
    /* Return the MPU INTC source for sdma_irq_Lj, or -1 if that line
       isn't routed (Camera DMA wires only L0 to IRQ_CAM0; L1..L3
       routing is internal to the ISP IRQCTRL we don't emulate). */
    virtual int      IrqForLine(int j) const = 0;

private:
    struct Channel {
        uint32_t ccr       = 0;
        uint32_t clnk_ctrl = 0;
        uint32_t cicr      = 0;
        uint32_t csr       = 0;
        uint32_t csdp      = 0;
        uint32_t cen       = 0;
        uint32_t cfn       = 0;
        uint32_t cssa      = 0;
        uint32_t cdsa      = 0;
        uint32_t csei      = 0;
        uint32_t csfi      = 0;
        uint32_t cdei      = 0;
        uint32_t cdfi      = 0;
        uint32_t csac      = 0;
        uint32_t cdac      = 0;
        uint32_t ccen      = 0;
        uint32_t ccfn      = 0;
        uint32_t color     = 0;
        bool     active    = false;
    };

    void RunSwTransfer(int ch);
    void ExecuteSyncUnit(int ch);
    bool TransferOneElement(int ch);
    uint32_t StepAddress(uint32_t cur, uint32_t amode,
                         int32_t ei, int32_t fi,
                         uint32_t es, bool end_of_frame) const;
    void RaiseChannelFault(int ch, uint32_t csr_fault_bits);
    void OnChannelComplete(int ch);
    void StartChain(int ch);
    void UpdateIrqLines();

    uint32_t irqstatus_l_[4]   = {0, 0, 0, 0};
    uint32_t irqenable_l_[4]   = {0, 0, 0, 0};
    uint32_t sysstatus_        = 1u;
    uint32_t ocp_sysconfig_    = 0;
    uint32_t gcr_              = 0x10u;
    std::vector<Channel> channels_;
    bool     irq_line_high_[4] = {false, false, false, false};

    mutable std::recursive_mutex state_mu_;
};
