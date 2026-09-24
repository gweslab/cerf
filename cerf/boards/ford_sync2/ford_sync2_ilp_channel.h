#pragma once
#include "../../core/service.h"
#include <atomic>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>
#include <string>

class StateWriter;
class StateReader;

class FordSync2IlpChannel : public Service {
public:
    using Service::Service;
    static constexpr uint8_t kCid = 28;
    struct Write { uint32_t id; uint64_t value; };
    enum class Result { Accepted, Invalid, Unavailable, Unsupported };
    struct Device {
        std::string key;
        std::function<void(bool)> refresh;
        std::function<void(uint32_t)> watchdog;
        std::function<bool(uint32_t)> owns;
        std::function<Result(const std::vector<Write>&)> apply;
        std::function<void(StateWriter&)> save;
        std::function<void(StateReader&)> restore;
        std::function<void()> reset;
    };
    void RegisterDevice(Device device);
    struct ParseError { const char* reason = nullptr; std::size_t offset = 0; uint32_t id = 0; };
    struct Counters { uint64_t accepted, unsupported, invalid, unavailable, malformed, received, sent; };
    bool ShouldRegister() override;
    static bool DecodeSet(const uint8_t* data, std::size_t n,
                          std::vector<Write>& writes, ParseError& error);
    void HandleInbound(const uint8_t* data, std::size_t n);
    void OnWatchdogPet();
    void ApplyHostChange(const std::function<void()>& change);
    Counters ReadCounters() const;
    void SaveState(StateWriter& w) const;
    void RestoreState(StateReader& r);

private:
    void Refresh(bool force = false);
    std::vector<Device> devices_;
    void Send(const uint8_t* data, std::size_t n);
    void Complete(uint8_t type, uint16_t tid, bool accepted);
    void HandleSet(const uint8_t* data, std::size_t n, uint16_t tid);
    void PublishPending(bool cyclic = false);
    uint8_t tx_seq_ = 0;
    uint32_t watchdog_pets_ = 0;
    std::atomic<uint64_t> accepted_{0}, unsupported_{0}, invalid_{0}, unavailable_{0}, malformed_{0};
    std::atomic<uint64_t> received_{0}, sent_{0};
    unsigned logged_writes_ = 0;
};
