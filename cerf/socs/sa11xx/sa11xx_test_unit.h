#pragma once

#include "../../core/service.h"

#include <cstdint>
#include <functional>
#include <vector>

class StateReader;
class StateWriter;

class Sa11xxTestUnit : public Service {
public:
    using Service::Service;

    enum class Mbgnt { Arbiter, Low, High, Undetermined };

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t Read() const { return tucr_; }
    void     Write(uint32_t value);

    Mbgnt MbgntPin() const;
    bool  Gp27Clock3686400() const;

    void RegisterChangeListener(std::function<void()> fn);

    void Save(StateWriter& w) const;
    void Restore(StateReader& r);

private:
    void NotifyChange();

    std::vector<std::function<void()>> listeners_;
    uint32_t tucr_ = 0;
};
