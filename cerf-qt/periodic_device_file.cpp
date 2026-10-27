#include "periodic_device_file.h"

#include <cerfcore/core/log.h>
#include <cerfcore/platform/host_error.h>
#include <cerfcore/platform/host_file.h>

#include <cstdint>
#include <utility>

namespace cerffrontend {

void PeriodicDeviceFile::Start(std::string path, std::chrono::seconds interval, std::function<void()> tick) {
    path_     = std::move(path);
    interval_ = interval;
    tick_     = std::move(tick);
    thread_   = std::thread([this] { Loop(); });
}

void PeriodicDeviceFile::Stop(bool delete_file) {
    RequestStop();
    Finish(delete_file);
}

void PeriodicDeviceFile::RequestStop() {
    stop_.store(true, std::memory_order_release);
    std::lock_guard<std::mutex> lock(mutex_);
    cv_.notify_all();
}

void PeriodicDeviceFile::Finish(bool delete_file) {
    if (thread_.joinable()) thread_.join();
    if (!delete_file || path_.empty()) return;
    uint32_t error = 0;
    if (cerfcore::host_platform::DeleteHostFile(path_, error) == cerfcore::host_platform::DeleteResult::kFailed)
        LOG(Caution, "%s: %s not deleted: %s\n", owner_, path_.c_str(),
            cerfcore::host_platform::ErrorText(error).c_str());
}

void PeriodicDeviceFile::Loop() {
    std::unique_lock<std::mutex> lock(mutex_);
    while (!Stopping()) {
        lock.unlock();
        tick_();
        lock.lock();
        if (Stopping()) break;
        cv_.wait_for(lock, interval_);
    }
}

}
