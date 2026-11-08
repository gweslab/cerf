#include "external_display_sources.h"

#include <cerfcore/core/cerf_emulator.h>

#include <utility>

REGISTER_SERVICE(ExternalDisplaySources);

int ExternalDisplaySources::Add(cerfcore::FrameSource& source, std::function<void()> on_eject) {
    std::lock_guard<std::mutex> lock(mutex_);
    const int id = next_id_++;
    entries_.emplace(id, Entry{&source, std::move(on_eject)});
    return id;
}

void ExternalDisplaySources::Remove(int id) {
    std::lock_guard<std::mutex> lock(mutex_);
    entries_.erase(id);
}

bool ExternalDisplaySources::UseSource(int id, const std::function<void(cerfcore::FrameSource&)>& use) {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto entry = entries_.find(id);
    if (entry == entries_.end()) return false;
    use(*entry->second.source);
    return true;
}

void ExternalDisplaySources::Eject(int id) {
    std::function<void()> eject;
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto entry = entries_.find(id);
        if (entry == entries_.end()) return;
        eject = entry->second.on_eject;
    }
    eject();
}
