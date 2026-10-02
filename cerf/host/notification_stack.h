#pragma once

#include "../core/service.h"

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

enum class NotificationKind : uint8_t { Warning, Error };

enum class NotificationId : uint32_t {
    EmulatorPaused = 1,
    SavingState    = 2,
    LoadingState   = 3,
    GuestSleeping  = 4,
};

struct NotificationCard {
    uint32_t         id;
    NotificationKind kind;
    std::wstring     text;
};

class NotificationStack : public Service {
public:
    using Service::Service;

    void Show(NotificationId id, NotificationKind kind, std::wstring text);
    void Close(NotificationId id);
    void PostError(std::wstring text);
    void Dismiss(uint32_t id);

    uint64_t Generation() const { return gen_.load(std::memory_order_acquire); }
    uint64_t Snapshot(std::vector<NotificationCard>& out) const;

private:
    void Remove(uint32_t id, const char* how);

    static constexpr uint32_t kFirstErrorId = 0x100u;

    mutable std::mutex            mtx_;
    std::vector<NotificationCard> cards_;
    uint32_t                      next_error_id_ = kFirstErrorId;
    std::atomic<uint64_t>         gen_{0};
};
