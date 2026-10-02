#include "notification_stack.h"

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "../core/string_utils.h"

#include <algorithm>

REGISTER_SERVICE(NotificationStack);

void NotificationStack::Show(NotificationId id, NotificationKind kind, std::wstring text) {
    const uint32_t key = static_cast<uint32_t>(id);
    LOG(Cerf, "[NOTIFY] show id=%u '%s'\n", key, WideToUtf8(text).c_str());
    std::lock_guard<std::mutex> lk(mtx_);
    auto it = std::find_if(cards_.begin(), cards_.end(),
                           [key](const NotificationCard& c) { return c.id == key; });
    if (it != cards_.end()) {
        it->kind = kind;
        it->text = std::move(text);
    } else {
        cards_.push_back({key, kind, std::move(text)});
    }
    gen_.fetch_add(1, std::memory_order_acq_rel);
}

void NotificationStack::PostError(std::wstring text) {
    std::lock_guard<std::mutex> lk(mtx_);
    const uint32_t key = next_error_id_++;
    LOG(Cerf, "[NOTIFY] error id=%u '%s'\n", key, WideToUtf8(text).c_str());
    cards_.push_back({key, NotificationKind::Error, std::move(text)});
    gen_.fetch_add(1, std::memory_order_acq_rel);
}

void NotificationStack::Close(NotificationId id) {
    std::lock_guard<std::mutex> lk(mtx_);
    Remove(static_cast<uint32_t>(id), "closed");
}

void NotificationStack::Dismiss(uint32_t id) {
    std::lock_guard<std::mutex> lk(mtx_);
    Remove(id, "dismissed");
}

void NotificationStack::Remove(uint32_t id, const char* how) {
    auto it = std::find_if(cards_.begin(), cards_.end(),
                           [id](const NotificationCard& c) { return c.id == id; });
    if (it == cards_.end()) return;
    cards_.erase(it);
    LOG(Cerf, "[NOTIFY] %s id=%u\n", how, id);
    gen_.fetch_add(1, std::memory_order_acq_rel);
}

uint64_t NotificationStack::Snapshot(std::vector<NotificationCard>& out) const {
    std::lock_guard<std::mutex> lk(mtx_);
    out = cards_;
    return gen_.load(std::memory_order_acquire);
}
