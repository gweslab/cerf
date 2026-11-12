#include "press_pacing.h"

void PressPacing::Push(int code, KeyEdge edge, bool paced) { pending_.push_back(Pending{code, edge, paced}); }

int64_t PressPacing::HeadDue() const {
    const Pending& head = pending_.front();
    if (head.edge != KeyEdge::kUp) return 0;
    const auto press = held_.find(head.code);
    if (press == held_.end() || !press->second.paced) return 0;
    return press->second.at_ms + kMinPressMs;
}

bool PressPacing::PopReady(int64_t now_ms) {
    if (pending_.empty() || HeadDue() > now_ms) return false;
    const Pending head = pending_.front();
    pending_.pop_front();
    if (head.edge == KeyEdge::kUp) held_.erase(head.code);
    else if (head.edge == KeyEdge::kDown && !held_.contains(head.code)) held_[head.code] = Press{now_ms, head.paced};
    return true;
}

void PressPacing::Clear() {
    pending_.clear();
    held_.clear();
}
