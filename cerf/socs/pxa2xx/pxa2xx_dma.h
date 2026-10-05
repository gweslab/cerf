#pragma once

#include "../../jit/guest_cycle_clock.h"
#include "../../peripherals/peripheral_base.h"
#include "pxa2xx_dma_channel.h"

#include <cstdint>
#include <mutex>

class EmulatedMemory;
class IrqController;
class Pxa2xxDmaPort;
class StateReader;
class StateWriter;

class Pxa2xxDma : public Peripheral {
public:
    using Peripheral::Peripheral;

    void RegisterPort(uint32_t request, Pxa2xxDmaPort* port);
    void RegisterUnmodelledRequest(uint32_t request, const char* name);
    void OnPortChange();

protected:
    static constexpr uint32_t kMaxChannels = 32u;
    static constexpr uint32_t kMaxRequests = 75u;

    static constexpr uint32_t RUN = 1u << 31, NODESCFETCH = 1u << 30, STOPIRQEN = 1u << 29;
    static constexpr uint32_t REQPEND = 1u << 8;
    static constexpr uint32_t ENDINTR = 1u << 2, STARTINTR = 1u << 1, BUSERRINTR = 1u << 0;
    static constexpr uint32_t INCSRCADDR = 1u << 31, INCTRGADDR = 1u << 30;
    static constexpr uint32_t FLOWSRC = 1u << 29, FLOWTRG = 1u << 28;
    static constexpr uint32_t STARTIRQEN = 1u << 22, ENDIRQEN = 1u << 21;
    static constexpr uint32_t kDcmdLengthMask = 0x1FFFu;
    static constexpr uint32_t DDADR_STOP = 1u << 0;
    static constexpr uint32_t kIntcDmaBit = 25u;

    enum class Reg : uint32_t { Ddadr, Dsadr, Dtadr, Dcmd };

    void AttachChannels(uint32_t count);

    virtual uint32_t DrcmrOf(uint32_t request) const = 0;
    virtual uint32_t DescriptorAddressLocked(uint32_t ch) const { return ddadr_[ch] & ~0xFu; }
    virtual uint32_t DescriptorDdadrMask() const = 0;
    virtual uint32_t DescriptorDcmdMask() const  = 0;
    virtual bool     ChannelIrq(uint32_t ch) const = 0;

    void     RunEdgeLocked(uint32_t ch, bool was_run);
    bool     PortBoundLocked(uint32_t ch) const { return stream_[ch].Port() != nullptr; }
    /* Intel PXA255 Developer's Manual section 5.1.4.3 (page 5-8): software that writes RUN back to a
       stopped channel "must read the DCSRx and check to see if DCSRx[RUN] and DCSRx[STOPSTATE] are
       both set". */
    bool     ChannelStoppedLocked(uint32_t ch) const { return (dcsr_[ch] & RUN) == 0u || stopped_run_[ch]; }
    /* Intel PXA255 Developer's Manual section 5.3.7 (page 5-23): DCMDx "is read only in Descriptor
       Fetch Mode"; Table 5-7 (page 5-18) NODESCFETCH "If this bit is set to a 0, the channel is in
       Descriptor Fetch Mode"; Intel PXA27x Developer's Manual section 5.5.3 (page 5-33). */
    bool     DescriptorFetchModeLocked(uint32_t ch) const { return (dcsr_[ch] & NODESCFETCH) == 0u; }
    bool     RequestPendingLocked(uint32_t ch);
    uint32_t ChannelRegLocked(uint32_t ch, Reg reg);
    void     RequireMappingStableLocked(uint32_t request, uint32_t value);
    void     UpdateIrqLocked();
    void     ResetChannelsLocked();
    void     SaveChannels(StateWriter& w);
    void     RestoreChannels(StateReader& r);
    void     PostRestoreChannelsLocked();

    std::mutex state_mutex_;
    uint32_t   channels_ = 0;
    uint32_t   dcsr_[kMaxChannels]  = {};
    uint32_t   ddadr_[kMaxChannels] = {};
    uint32_t   dsadr_[kMaxChannels] = {};
    uint32_t   dtadr_[kMaxChannels] = {};
    uint32_t   dcmd_[kMaxChannels]  = {};
    bool       stopped_run_[kMaxChannels] = {};

private:
    static constexpr uint8_t kNoRequest = 0xFFu;

    uint32_t MappedRequestLocked(uint32_t ch);
    void     StartPortLocked(uint32_t ch, uint32_t request);
    void     LoadDescriptorLocked(uint32_t ch, uint64_t at);
    void     ValidateDescriptorLocked(uint32_t ch, uint32_t desc);
    void     EvaluateLocked(uint32_t ch, uint64_t now);
    void     CompleteLocked(uint32_t ch, uint64_t at);
    void     StopPortLocked(uint32_t ch, uint64_t at, bool end_of_chain);
    uint32_t MovedBytesLocked(uint32_t ch) const;
    void     WriteReceivedLocked(uint32_t ch);
    void     ArmDoneLocked(uint32_t ch);
    void     OnDoneEvent(uint32_t ch);

    GuestCycleClock*        clock_ = nullptr;
    EmulatedMemory*         mem_   = nullptr;
    IrqController*          intc_  = nullptr;
    GuestCycleClock::Event* done_ev_[kMaxChannels] = {};
    Pxa2xxDmaChannel        stream_[kMaxChannels];
    uint8_t                 bound_request_[kMaxChannels] = {};
    Pxa2xxDmaPort*          ports_[kMaxRequests] = {};
    const char*             unmodelled_[kMaxRequests] = {};
};
