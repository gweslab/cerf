#pragma once

#include "../../core/service.h"

#include <cstdint>

class Sa1111Intc;
class Sa1111SacL3;
class Sa1111SacRxFifo;
class Sa1111SacTxStream;

class Sa1111SacRequestLines : public Service {
public:
    using Service::Service;

    /* SA-1111 Developer's Manual Table 11-1: 36 AudTFSR "Audio Transmit FIFO empty/under
       threshold", 37 AudRFSR "Audio Receive FIFO full/over threshold", 38 AudTUR "Audio
       Transmit FIFO under-run interrupt", 39 AudROR "Audio Receive FIFO overrun", 40 AudDTS
       "Audio L3/ACLink Data Sent interrupt". */
    static constexpr uint8_t  kSrcTfsr = 36u;
    static constexpr uint8_t  kSrcRfsr = 37u;
    static constexpr uint8_t  kSrcTur  = 38u;
    static constexpr uint8_t  kSrcRor  = 39u;
    static constexpr uint8_t  kSrcDts  = 40u;
    static constexpr uint64_t kSourceMask = (1ull << kSrcTfsr) | (1ull << kSrcRfsr) |
                                            (1ull << kSrcTur) | (1ull << kSrcRor) |
                                            (1ull << kSrcDts);

    /* Transmit Done A = source 32, Done B = source 34 (Table 11-1). */
    static constexpr uint8_t kSrcDoneA = 32u;
    static constexpr uint8_t kSrcDoneB = 34u;

    bool ShouldRegister() override;
    void OnReady() override;

    void PublishDone(bool done_a, bool done_b, uint8_t completed);
    void BaselineDone(bool done_a, bool done_b);
    void Publish(uint64_t now, bool enabled, uint32_t tx_threshold, uint32_t rx_threshold);
    void Baseline(uint64_t now, bool enabled, uint32_t tx_threshold, uint32_t rx_threshold);

private:
    struct Levels {
        bool     tfs      = false;
        uint64_t requests = 0;
        bool     rfs      = false;
        bool     tur      = false;
        bool     ror      = false;
        bool     dts      = false;
    };

    Levels Sample(uint64_t now, bool enabled, uint32_t tx_threshold,
                  uint32_t rx_threshold) const;
    void   DriveDone(uint8_t source, bool level, bool& published, bool completed);

    Sa1111Intc*        intc_   = nullptr;
    Sa1111SacTxStream* stream_ = nullptr;
    Sa1111SacRxFifo*   rx_     = nullptr;
    Sa1111SacL3*       l3_     = nullptr;
    Levels             pub_;
    bool               done_a_ = false;
    bool               done_b_ = false;
};
