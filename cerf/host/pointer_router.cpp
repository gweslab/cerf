#include "pointer_router.h"

#include "../core/cerf_emulator.h"
#include "pointer_input.h"
#include "pointer_source.h"
#include "relative_mouse_input.h"
#include "touch_input.h"

REGISTER_SERVICE(PointerRouter);

void PointerRouter::OnReady() {
    if (auto* p = emu_.TryGet<PointerInput>())       Register(p);
    if (auto* r = emu_.TryGet<RelativeMouseInput>()) Register(r);
    if (auto* t = emu_.TryGet<TouchInput>())         Register(t);
}

void PointerRouter::SelectAutoLocked() {
    PointerSource* best_ready = nullptr;
    PointerSource* best_any   = nullptr;
    for (auto* s : sources_) {
        if (!best_any || s->SourcePriority() > best_any->SourcePriority())
            best_any = s;
        if (!s->SourceReady()) continue;
        if (!best_ready || s->SourcePriority() > best_ready->SourcePriority())
            best_ready = s;
    }
    active_ = best_ready ? best_ready : best_any;
}

void PointerRouter::Register(PointerSource* src) {
    std::lock_guard<std::mutex> lk(mtx_);
    for (auto* s : sources_) if (s == src) return;
    sources_.push_back(src);
    if (!user_picked_) SelectAutoLocked();
}

std::vector<PointerSource*> PointerRouter::Sources() {
    std::lock_guard<std::mutex> lk(mtx_);
    return sources_;
}

PointerSource* PointerRouter::Active() {
    std::lock_guard<std::mutex> lk(mtx_);
    return active_;
}

void PointerRouter::SetActive(PointerSource* src) {
    std::lock_guard<std::mutex> lk(mtx_);
    for (auto* s : sources_)
        if (s == src) { active_ = src; user_picked_ = true; return; }
}

void PointerRouter::RestoreActiveByName(const std::wstring& name) {
    std::lock_guard<std::mutex> lk(mtx_);
    for (auto* s : sources_)
        if (s->SourceName() == name) { active_ = s; return; }
}

void PointerRouter::CycleNext() {
    std::lock_guard<std::mutex> lk(mtx_);
    if (sources_.size() < 2) return;
    user_picked_ = true;
    for (size_t i = 0; i < sources_.size(); ++i) {
        if (sources_[i] == active_) {
            active_ = sources_[(i + 1) % sources_.size()];
            return;
        }
    }
    active_ = sources_.front();
}

void PointerRouter::ReevaluateAuto() {
    std::lock_guard<std::mutex> lk(mtx_);
    if (!user_picked_) SelectAutoLocked();
}

bool PointerRouter::UserPicked() const {
    std::lock_guard<std::mutex> lk(mtx_);
    return user_picked_;
}

void PointerRouter::RestoreUserPicked(bool picked) {
    std::lock_guard<std::mutex> lk(mtx_);
    user_picked_ = picked;
}

void PointerRouter::RearmAutoSelect() {
    std::lock_guard<std::mutex> lk(mtx_);
    user_picked_ = false;
    SelectAutoLocked();
}
