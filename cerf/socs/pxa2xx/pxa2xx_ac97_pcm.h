#pragma once

#include "../../core/service.h"
#include "../../host/paced_wave_out.h"
#include "../dma_burst_fifo.h"
#include "pxa2xx_ac97_link.h"
#include "pxa2xx_dma_port.h"
#include "pxa2xx_frame_slot_law.h"

#include <cstdint>
#include <vector>

class Ac97Codec;
class EmulatedMemory;
class GuestCycleClock;
class Pxa2xxDma;
class StateReader;
class StateWriter;

class Pxa2xxAc97Pcm : public Service, public Pxa2xxAc97LinkListener {
public:
    using Service::Service;

    bool ShouldRegister() override;
    void OnReady() override;
    void OnShutdown() override;

    static constexpr uint32_t kFifoe = 1u << 4;
    static constexpr uint32_t kFsr   = 1u << 2;

    uint32_t OutStatus(uint64_t now);
    void     ClearOutStatus(uint64_t now, uint32_t mask);
    void     WriteData(uint64_t now, uint32_t value);

    void Save(StateWriter& w);
    void Restore(StateReader& r);

    void OnLinkRun(uint64_t cycle) override;
    void OnLinkStop(uint64_t cycle) override;
    void OnFifoReset(uint64_t cycle, bool cold) override;
    void OnCodecWrite(uint64_t cycle) override;
    void OnLinkEvent() override;

private:
    class OutPort : public Pxa2xxDmaPort {
    public:
        explicit OutPort(Pxa2xxAc97Pcm& pcm) : pcm_(pcm) {}

        bool     Receive() const override { return false; }
        uint32_t FifoAddress() const override;
        void     Settle(uint64_t now) override { pcm_.Settle(now); }
        bool     RequestAsserted() const override { return pcm_.TxRequest(); }
        void     SetService(uint64_t now, uint32_t burst_words, uint64_t supply_words) override;
        uint64_t Moved() const override { return pcm_.tx_.Moved(); }
        bool     CycleOfMoved(uint64_t words, uint64_t& cycle) override { return pcm_.TxCycleOfMoved(words, cycle); }
        void     TransmitBlock(uint32_t pa, uint32_t bytes) override;
        void     ReceiveBlock(uint32_t pa, uint32_t bytes) override;
        void     Stopped(uint64_t now, bool end_of_chain) override;

    private:
        Pxa2xxAc97Pcm& pcm_;
    };

    void     Settle(uint64_t now);
    void     SettleTo(uint64_t now);
    bool     TxRequest() const;
    void     CheckPrimed(uint64_t now);
    uint32_t OutRate();
    void     RequireCodec(const char* access);
    bool     TxCycleOfMoved(uint64_t words, uint64_t& cycle);
    void     QueueHost(const void* bytes, uint32_t length);

    Pxa2xxAc97Link*  link_  = nullptr;
    Ac97Codec*       codec_ = nullptr;
    GuestCycleClock* clock_ = nullptr;
    EmulatedMemory*  mem_   = nullptr;
    Pxa2xxDma*       dma_   = nullptr;

    OutPort out_port_{*this};

    DmaBurstFifo       tx_;
    Pxa2xxFrameSlotLaw out_law_{Pxa2xxAc97Link::kFrameRateHz};
    bool     primed_      = false;
    uint64_t prime_frame_ = 0;
    uint64_t out_frames_  = 0;
    bool     out_error_   = false;

    PacedWaveOut         host_;
    bool                 host_active_ = false;
    uint32_t             host_rate_   = 0;
    std::vector<uint8_t> block_;
};
