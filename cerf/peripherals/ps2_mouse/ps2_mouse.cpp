#include "ps2_mouse.h"

#include "../../state/state_stream.h"

namespace {

uint8_t ClampDelta(int v) {
    if (v >  127) return static_cast<uint8_t>(127);
    if (v < -127) return static_cast<uint8_t>(-127);
    return static_cast<uint8_t>(v);
}

}  /* namespace */

void Ps2Mouse::WriteCommand(uint8_t cmd) {
    /* Command ACKs/responses are read by polling during driver init; only the
       motion stream (after 0xF4) is interrupt-driven, so commands never raise
       the IRQ - doing so mid-handshake perturbs the driver's polled reset. */
    std::lock_guard<std::mutex> lk(mtx_);
    if (expect_param_) {            /* sample-rate / resolution argument */
        expect_param_ = false;
        PushLocked(0xFA);
        return;
    }
    if (cmd == 0xFF) {
        /* Reset flushes the output buffer + restores defaults before the BAT
           response (real PS/2 mouse). Without the flush, bytes left in out_
           across a system reset sit ahead of the 0xFA ACK and the driver's
           reset handshake never syncs (it retries 0xFF forever). */
        out_.clear();
        expect_param_ = false;
        reporting_    = false;
        PushLocked(0xFA);             /* ACK  */
        PushLocked(0xAA);             /* BAT passed */
        PushLocked(0x00);             /* device ID 0 = standard mouse */
        return;
    }
    PushLocked(0xFA);              /* ACK */
    switch (cmd) {
        case 0xF2: PushLocked(0x00); break;                    /* get device ID: standard mouse = 0 */
        case 0xF3: case 0xE8: expect_param_ = true; break;     /* set sample rate / resolution */
        case 0xE9: PushLocked(0x00); PushLocked(0x02); PushLocked(0x64); break;  /* status request */
        case 0xF4: reporting_ = true;  break;  /* enable data reporting */
        case 0xF5: reporting_ = false; break;  /* disable data reporting */
        case 0xF6: reporting_ = false; break;  /* set defaults: disables reporting */
        default: break;            /* scaling / mode: ACK only */
    }
}

bool Ps2Mouse::HasData() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return !out_.empty();
}

uint8_t Ps2Mouse::ReadData() {
    bool raise;
    uint8_t b;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (out_.empty()) return 0;
        b = out_.front();
        out_.pop_front();
        /* 8042 output buffer holds one byte: reading it loads the next, which
           re-sets OBF and raises the IRQ again. The driver reads exactly one
           byte per interrupt (glidepad.dll sub_12B1EFC), so without the
           per-byte re-raise it only ever sees the first byte of each packet. */
        raise = reporting_ && !out_.empty();
    }
    if (raise) RaiseData();
    return b;
}

void Ps2Mouse::QueueMotion(int dx, int dy, uint32_t button_mask) {
    bool raise;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (!reporting_) return;   /* disabled mouse streams nothing (PS/2 default) */
        const bool was_empty = out_.empty();
        uint8_t b0 = 0x08u;        /* always-1 sync bit */
        if (button_mask & kButtonLeft)  b0 |= 0x01u;
        if (button_mask & kButtonRight) b0 |= 0x02u;
        PushLocked(b0);
        PushLocked(ClampDelta(dx));
        PushLocked(ClampDelta(-dy));   /* PS/2 Y is inverted vs screen */
        raise = was_empty;
    }
    if (raise) RaiseData();
}

void Ps2Mouse::SaveState(StateWriter& w) const {
    std::lock_guard<std::mutex> lk(mtx_);
    w.Write<uint8_t>("reporting", reporting_ ? 1u : 0u);
    w.Write<uint8_t>("expect_param", expect_param_ ? 1u : 0u);
}

void Ps2Mouse::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(mtx_);
    uint8_t rep = 0, ep = 0;
    r.Read("reporting", rep); r.Read("expect_param", ep);
    reporting_ = (rep != 0);
    expect_param_ = (ep != 0);
    out_.clear();   /* no host motion survives a restore; drop queued bytes */
}

void Ps2Mouse::Reset() {
    std::lock_guard<std::mutex> lk(mtx_);
    out_.clear();
    expect_param_ = false;
    reporting_    = false;
}

void Ps2Mouse::RaiseData() {
    if (on_data_) on_data_();          /* IRQ raised outside the queue lock */
}
