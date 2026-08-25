#include "pointer_router.h"

#include "../core/cerf_emulator.h"
#include "../core/log.h"
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

void PointerRouter::NoteActiveLocked(PointerSource* before) {
    if (active_ == before) return;
    LOG(GuestAdditions, "pointer source -> \"%ls\" priority %d ready %u user-picked %u\n",
        active_ ? active_->SourceName().c_str() : L"(none)",
        active_ ? active_->SourcePriority() : -1,
        (active_ && active_->SourceReady()) ? 1u : 0u,
        user_picked_ ? 1u : 0u);
}

void PointerRouter::Register(PointerSource* src) {
    std::lock_guard<std::mutex> lk(mtx_);
    for (auto* s : sources_) if (s == src) return;
    PointerSource* before = active_;
    sources_.push_back(src);
    if (!user_picked_) SelectAutoLocked();
    NoteActiveLocked(before);
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
    PointerSource* before = active_;
    for (auto* s : sources_)
        if (s == src) { active_ = src; user_picked_ = true; break; }
    NoteActiveLocked(before);
}

void PointerRouter::RestoreActiveByName(const std::wstring& name) {
    std::lock_guard<std::mutex> lk(mtx_);
    PointerSource* before = active_;
    for (auto* s : sources_)
        if (s->SourceName() == name) { active_ = s; break; }
    NoteActiveLocked(before);
}

void PointerRouter::CycleNext() {
    std::lock_guard<std::mutex> lk(mtx_);
    if (sources_.size() < 2) return;
    PointerSource* before = active_;
    user_picked_ = true;
    active_ = sources_.front();
    for (size_t i = 0; i < sources_.size(); ++i) {
        if (sources_[i] == before) {
            active_ = sources_[(i + 1) % sources_.size()];
            break;
        }
    }
    NoteActiveLocked(before);
}

void PointerRouter::ReevaluateAuto() {
    std::lock_guard<std::mutex> lk(mtx_);
    if (user_picked_) return;
    PointerSource* before = active_;
    SelectAutoLocked();
    NoteActiveLocked(before);
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
    PointerSource* before = active_;
    user_picked_ = false;
    SelectAutoLocked();
    NoteActiveLocked(before);
}
