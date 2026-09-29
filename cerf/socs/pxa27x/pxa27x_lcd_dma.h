#pragma once

#include "../../core/service.h"

#include <cstdint>
#include <mutex>

class StateReader;
class StateWriter;

class Pxa27xLcdDma : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;

    struct Fetch {
        bool     loaded   = false;
        bool     sof      = false;
        bool     branched = false;
        uint32_t frame_id = 0;
    };

    static bool Decodes(uint32_t off);

    uint32_t Read (uint32_t off);
    void     Write(uint32_t off, uint32_t value);

    Fetch    FetchChannel0();
    bool     Channel0EndOfFrame() const;
    uint32_t Channel0FrameId() const;
    bool     Halted() const;

    uint32_t SrcPa(uint32_t channel) const;
    uint32_t Length(uint32_t channel) const;
    bool     IsPalette(uint32_t channel) const;
    void     RequireWholeFrame(uint32_t bpp_code, uint64_t w, uint64_t h) const;

    void Reset();
    void SaveState(StateWriter& w);
    void RestoreState(StateReader& r);

private:
    static constexpr uint32_t kChannels = 7u;

    template <typename F> void VisitRegs(F& f);
    uint32_t* SlotLocked(uint32_t off);

    mutable std::mutex mtx_;

    bool dma_halted_ = false;

    /* Intel PXA27x Developer's Manual 280000-001 Table 7-54 FDADR0/1/2/3/4/5/6,
       Table 7-61 FSADR, Table 7-62 FIDR, Table 7-63 LDCMD, Table 7-55 FBR. */
    uint32_t fdadr_[kChannels] = {};
    uint32_t fsadr_[kChannels] = {};
    uint32_t fidr_ [kChannels] = {};
    uint32_t ldcmd_[kChannels] = {};
    uint32_t fbr_  [kChannels] = {};
};
