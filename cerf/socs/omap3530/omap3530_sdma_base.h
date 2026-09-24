#pragma once

#include "../../peripherals/peripheral_base.h"

#include "../../state/state_stream.h"

#include <cstdint>
#include <functional>
#include <mutex>
#include <utility>
#include <vector>

class Omap3530SdmaBase : public Peripheral {
public:
    using Peripheral::Peripheral;

    void OnReady() override;

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void RaiseSyncEvent(uint32_t source);

    /* Channel config snapshot offered to sinks at the enable edge. A sink that
       claims the channel becomes its data mover; the sync-event transfer engine
       then skips it and the owner drives interrupts via SignalChannelFrame. */
    struct ChannelStart {
        int      channel;
        uint32_t sync_source;   /* ExtractSyncSource(CCR).                  */
        uint32_t src_pa;        /* CSSA - source physical address.          */
        uint32_t dst_pa;        /* CDSA - destination physical address.     */
        uint32_t elem_count;    /* CEN  - elements per frame.               */
        uint32_t frame_count;   /* CFN  - frames per block.                 */
        uint32_t element_size;  /* bytes per element (from CSDP DATATYPE).  */
    };
    using ChannelClaim = std::function<bool(const ChannelStart&)>;
    using ChannelStop  = std::function<void(int channel)>;
    /* A claim returning true takes ownership of the channel; stop fires when a
       claimed channel is disabled. Stops are broadcast to all sinks; a sink
       ignores channels it did not claim. */
    void RegisterChannelSink(ChannelClaim claim, ChannelStop stop);

    /* Raise a paced frame interrupt for a claimed channel: advances CSAC to the
       source address now being consumed (the driver reads CSAC to pick the page
       to refill), sets CSR.FRAME (plus CSR.BLOCK|LAST at a block boundary), and
       re-evaluates the IRQ lines. Called once per page after host playback. */
    void SignalChannelFrame(int channel, bool block_boundary,
                            uint32_t src_counter_pa);

    void SaveState(StateWriter& w) override {
        std::lock_guard<std::recursive_mutex> lk(state_mu_);
        w.WriteBytes("irqstatus_l", irqstatus_l_, sizeof(irqstatus_l_));
        w.WriteBytes("irqenable_l", irqenable_l_, sizeof(irqenable_l_));
        w.Write("sysstatus", sysstatus_);
        w.Write("ocp_sysconfig", ocp_sysconfig_);
        w.Write("gcr", gcr_);
        static_assert(StateVisitCoversAllBytes<Channel>(
                          [](Channel& c, StateFieldBytes& f) { VisitChannel(c, f); }),
                      "VisitChannel must name or skip every field of Channel");
        StateWriteField field(w);
        for (Channel& c : channels_) VisitChannel(c, field);
        w.WriteBytes("irq_line_high", irq_line_high_, sizeof(irq_line_high_));
    }
    void RestoreState(StateReader& r) override {
        std::lock_guard<std::recursive_mutex> lk(state_mu_);
        r.ReadBytes("irqstatus_l", irqstatus_l_, sizeof(irqstatus_l_));
        r.ReadBytes("irqenable_l", irqenable_l_, sizeof(irqenable_l_));
        r.Read("sysstatus", sysstatus_);
        r.Read("ocp_sysconfig", ocp_sysconfig_);
        r.Read("gcr", gcr_);
        StateReadField field(r);
        for (Channel& c : channels_) VisitChannel(c, field);
        r.ReadBytes("irq_line_high", irq_line_high_, sizeof(irq_line_high_));
    }

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
        uint8_t  pad[3]    = {};
    };

    template <typename F>
    static constexpr void VisitChannel(Channel& c, F& field) {
        field("ccr", c.ccr);
        field("clnk_ctrl", c.clnk_ctrl);
        field("cicr", c.cicr);
        field("csr", c.csr);
        field("csdp", c.csdp);
        field("cen", c.cen);
        field("cfn", c.cfn);
        field("cssa", c.cssa);
        field("cdsa", c.cdsa);
        field("csei", c.csei);
        field("csfi", c.csfi);
        field("cdei", c.cdei);
        field("cdfi", c.cdfi);
        field("csac", c.csac);
        field("cdac", c.cdac);
        field("ccen", c.ccen);
        field("ccfn", c.ccfn);
        field("color", c.color);
        field("active", c.active);
        field.Skip(c.pad);
    }

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
    bool OfferChannelToSinks(int ch);

    uint32_t irqstatus_l_[4]   = {0, 0, 0, 0};
    uint32_t irqenable_l_[4]   = {0, 0, 0, 0};
    uint32_t sysstatus_        = 1u;
    uint32_t ocp_sysconfig_    = 0;
    uint32_t gcr_              = 0x10u;
    std::vector<Channel> channels_;
    bool     irq_line_high_[4] = {false, false, false, false};

    std::vector<uint8_t> claimed_;   /* per-channel: owned by a sink, not serialized. */
    std::vector<std::pair<ChannelClaim, ChannelStop>> sinks_;

    mutable std::recursive_mutex state_mu_;
};
