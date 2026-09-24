#include "ps2_keyboard.h"

#include "../../state/state_stream.h"

void Ps2Keyboard::WriteCommand(uint8_t cmd) {
    /* Command ACKs/responses are read by polling during driver init; only the
       scancode stream is interrupt-driven, so commands never raise the IRQ. */
    std::lock_guard<std::mutex> lk(mtx_);
    if (expect_param_) {            /* scancode-set / LED / typematic argument */
        expect_param_ = false;
        PushLocked(0xFA);
        return;
    }
    if (cmd == 0xFF) {             /* reset: ACK then BAT-OK (ps2port KeyboardReset) */
        out_.clear();
        expect_param_ = false;
        reporting_    = true;
        PushLocked(0xFA);             /* ACK */
        PushLocked(0xAA);             /* BAT passed */
        return;
    }
    PushLocked(0xFA);              /* ACK */
    switch (cmd) {
        case 0xF0: case 0xED: case 0xF3: expect_param_ = true; break;  /* set scancode set / LEDs / typematic */
        case 0xF2: PushLocked(0xAB); PushLocked(0x83); break;          /* read ID: MF2 keyboard */
        case 0xF4: reporting_ = true;  break;  /* enable scanning */
        case 0xF5: out_.clear(); reporting_ = false; break;  /* disable scanning */
        case 0xF6: reporting_ = true;  break;  /* set defaults (scanning stays on) */
        default: break;            /* echo/other: ACK only */
    }
}

bool Ps2Keyboard::HasData() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return !out_.empty();
}

uint8_t Ps2Keyboard::ReadData() {
    bool raise;
    uint8_t b;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (out_.empty()) return 0;
        b = out_.front();
        out_.pop_front();
        /* 8042 output buffer holds one byte: reading it loads the next, which
           re-sets OBF and raises the IRQ again so the ISR drains a multi-byte
           sequence (e.g. an extended-key 0xE0/0xF0 pair) one byte per interrupt. */
        raise = reporting_ && !out_.empty();
    }
    if (raise) RaiseData();
    return b;
}

void Ps2Keyboard::QueueScancodes(const uint8_t* bytes, size_t n) {
    bool raise;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        if (!reporting_) return;   /* scanning disabled: drop the key (PS/2 default) */
        const bool was_empty = out_.empty();
        for (size_t i = 0; i < n; ++i) PushLocked(bytes[i]);
        raise = was_empty && n != 0;
    }
    if (raise) RaiseData();
}

void Ps2Keyboard::SaveState(StateWriter& w) const {
    std::lock_guard<std::mutex> lk(mtx_);
    w.Write<uint8_t>("reporting", reporting_ ? 1u : 0u);
    w.Write<uint8_t>("expect_param", expect_param_ ? 1u : 0u);
}

void Ps2Keyboard::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(mtx_);
    uint8_t rep = 0, ep = 0;
    r.Read("reporting", rep); r.Read("expect_param", ep);
    reporting_    = (rep != 0);
    expect_param_ = (ep != 0);
    out_.clear();   /* no host keystrokes survive a restore; drop queued bytes */
}

void Ps2Keyboard::Reset() {
    std::lock_guard<std::mutex> lk(mtx_);
    out_.clear();
    expect_param_ = false;
    reporting_    = true;
}

void Ps2Keyboard::RaiseData() {
    if (on_data_) on_data_();          /* IRQ raised outside the queue lock */
}
