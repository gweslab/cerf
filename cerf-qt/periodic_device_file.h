#pragma once

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <functional>
#include <mutex>
#include <string>
#include <thread>

namespace cerffrontend {

class PeriodicDeviceFile {
public:
    explicit PeriodicDeviceFile(const char* owner) : owner_(owner) {}

    PeriodicDeviceFile(const PeriodicDeviceFile&)            = delete;
    PeriodicDeviceFile& operator=(const PeriodicDeviceFile&) = delete;

    void Start(std::string path, std::chrono::seconds interval, std::function<void()> tick);
    void RequestStop();
    void Finish(bool delete_file);
    void Stop(bool delete_file);

    bool               Stopping() const { return stop_.load(std::memory_order_acquire); }
    const std::string& Path() const { return path_; }

private:
    void Loop();

    const char*             owner_;
    std::string             path_;
    std::chrono::seconds    interval_{0};
    std::function<void()>   tick_;
    std::thread             thread_;
    std::mutex              mutex_;
    std::condition_variable cv_;
    std::atomic<bool>       stop_{false};
};

}
