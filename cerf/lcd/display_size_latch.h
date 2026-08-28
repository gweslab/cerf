#pragma once

class CerfEmulator;
class StateReader;
class StateWriter;

class DisplaySizeLatch {
public:
    bool PublishOnce(CerfEmulator& emu, bool display_enabled);

    void SaveState(StateWriter& w) const;
    void RestoreState(StateReader& r);

private:
    bool published_ = false;
};
