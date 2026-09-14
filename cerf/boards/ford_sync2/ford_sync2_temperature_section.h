#pragma once

#include "../../host/host_widget.h"
#include <cstdint>
#include <string>
#include <vector>

class CerfEmulator;
class StateWriter;
class StateReader;

class TemperatureSection : public HostMenuSection {
public:
    explicit TemperatureSection(CerfEmulator& emu) : emu_(emu) {}

    std::wstring Label() const override;
    std::vector<WidgetMenuItem> BuildItems() override;
    bool PollDirty() override;
    void SaveState(StateWriter& w) const override;
    void RestoreState(StateReader& r) override;

private:
    CerfEmulator& emu_;
    uint64_t last_revision_ = UINT64_MAX;
    bool imperial_ = false;
};
