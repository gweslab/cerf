#pragma once

#include <cstdint>

class CerfEmulator;
class StateReader;
class StateWriter;

class DisplayModeLatch {
public:
    bool Publish(CerfEmulator& emu, bool display_enabled, uint32_t width, uint32_t height);

    void SaveState(StateWriter& w) const;
    void RestoreState(StateReader& r);

private:
    bool published_ = false;
    uint32_t width_ = 0;
    uint32_t height_ = 0;
};
