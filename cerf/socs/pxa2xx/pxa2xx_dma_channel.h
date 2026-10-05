#pragma once

#include <cstdint>

class Pxa2xxDmaPort;
class StateReader;
class StateWriter;

class Pxa2xxDmaChannel {
public:
    void Bind(Pxa2xxDmaPort* port);
    void Unbind();

    Pxa2xxDmaPort* Port() const { return port_; }
    bool     Active() const { return active_; }
    uint32_t Burst() const { return burst_; }

    void     Begin(uint32_t words, uint32_t burst);
    void     Finish();
    void     Stop();
    uint64_t Remaining() const;
    uint32_t WordsMoved() const;
    uint32_t Written() const { return written_; }
    void     MarkWritten() { written_ = WordsMoved(); }
    bool     DoneCycle(uint64_t& cycle) const;

    void Save(StateWriter& w) const;
    void Restore(StateReader& r);

private:
    Pxa2xxDmaPort* port_    = nullptr;
    bool           active_  = false;
    bool           chained_ = false;
    uint32_t       burst_   = 0;
    uint32_t       written_ = 0;
    uint64_t       origin_  = 0;
    uint64_t       end_     = 0;
};
