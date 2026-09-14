#pragma once
#include "../../core/service.h"
#include <cstdint>
#include <mutex>
#include <optional>

class StateWriter;
class StateReader;

class FordSync2AmbientTemperature : public Service {
public:
    using Service::Service;
    struct Snapshot {
        bool available = false;
        std::optional<int16_t> half_celsius;
        uint64_t revision = 0;
    };
    bool ShouldRegister() override;
    Snapshot Read() const;
    void Set(std::optional<int16_t> half_celsius);
    void Clear();
    void SaveState(StateWriter& w) const;
    void RestoreState(StateReader& r);
private:
    mutable std::mutex mutex_;
    Snapshot state_;
};
