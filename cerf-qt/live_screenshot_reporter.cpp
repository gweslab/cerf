#include "device_status_files.h"
#include "frontend_window.h"
#include "image_exporter.h"
#include "periodic_device_file.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/cerf_paths.h>
#include <cerfcore/core/device_config.h>
#include <cerfcore/core/instance_threads.h>
#include <cerfcore/core/run_timeout.h>
#include <cerfcore/core/service.h>

#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <string>
#include <vector>

namespace cerffrontend {

namespace {

constexpr auto kInterval    = std::chrono::seconds(5);
constexpr auto kCaptureWait = std::chrono::seconds(3);

class LiveScreenshotReporter : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void OnReady() override {
        const std::string name = emu_.Get<cerfcore::DeviceConfig>().device_name;
        if (name.empty()) return;
        window_   = &emu_.Get<FrontendWindow>();
        exporter_ = &emu_.Get<ImageExporter>();
        worker_.Start(emu_.Get<cerfcore::InstanceThreads>(), cerfcore::GetDeviceDir(name) + kLiveScreenshotFileName,
                      kInterval, [this] { Tick(); });
    }

    void OnShutdown() override { Stop(); }

private:
    void Stop() {
        worker_.RequestStop();
        {
            std::lock_guard<std::mutex> lock(capture_mutex_);
            capture_cv_.notify_all();
        }
        worker_.Finish(!cerfcore::RunTimeout::IsActive());
    }

    void Tick() {
        uint64_t serial = 0;
        {
            std::lock_guard<std::mutex> lock(capture_mutex_);
            serial    = ++capture_serial_;
            captured_ = false;
        }
        window_->RunOnUiThread([this, serial] {
            std::vector<uint32_t> pixels;
            uint32_t              w = 0, h = 0;
            const bool captured = window_->CaptureGuestSurface(pixels, w, h);
            std::lock_guard<std::mutex> lock(capture_mutex_);
            if (serial != capture_serial_) return;
            pixels_       = std::move(pixels);
            w_            = w;
            h_            = h;
            captured_     = captured;
            capture_done_ = serial;
            capture_cv_.notify_all();
        });
        std::unique_lock<std::mutex> lock(capture_mutex_);
        const bool done = capture_cv_.wait_for(lock, kCaptureWait,
                                               [&] { return capture_done_ == serial || worker_.Stopping(); });
        if (!done || worker_.Stopping() || !captured_) return;
        const std::vector<uint32_t> pixels = std::move(pixels_);
        const uint32_t              w      = w_;
        const uint32_t              h      = h_;
        lock.unlock();
        exporter_->WritePng(pixels, w, h, worker_.Path());
    }

    FrontendWindow*         window_   = nullptr;
    ImageExporter*          exporter_ = nullptr;
    std::mutex              capture_mutex_;
    std::condition_variable capture_cv_;
    uint64_t                capture_serial_ = 0;
    uint64_t                capture_done_   = 0;
    bool                    captured_       = false;
    std::vector<uint32_t>   pixels_;
    uint32_t                w_ = 0;
    uint32_t                h_ = 0;
    PeriodicDeviceFile      worker_{"LiveScreenshotReporter"};
};

}

REGISTER_SERVICE(LiveScreenshotReporter);

}
