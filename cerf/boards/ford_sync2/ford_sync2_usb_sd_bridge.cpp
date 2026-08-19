#include "../../core/cerf_emulator.h"
#include "../../core/service.h"
#include "../../boards/board_context.h"
#include "../../peripherals/usb/usb_hub.h"
#include "../../peripherals/usb/usb_mass_storage_device.h"
#include "../../socs/imx51/imx51_usboh3.h"
#include "../../state/emulation_freeze.h"
#include "../../storage/disk_image.h"

#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>

namespace {

/* Real Ford SYNC2 unit MsgLog: "OTG High Speed : USB debounce timer started
   (17000 ms)", immediately preceded by SetPortPower:0 / hub port Force
   Detach. Only the reattach after this interval enumerates the SD reader. */
constexpr auto kDebounceInterval = std::chrono::milliseconds(17000);
constexpr auto kReattachGap = std::chrono::milliseconds(100);

class FordSync2UsbSdBridge : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoard() == Board::FordSyncGen2;
    }

    void OnReady() override {
        if (!disk_.Open("D:\\Repositories\\cerf\\sdimg\\sdcard_a4.img", 0)) return;

        auto msc = std::make_unique<UsbMassStorageDevice>(disk_);
        auto hub = std::make_unique<UsbHub>(2);
        hub_ = hub.get();
        hub_->Port(0).Attach(std::move(msc));
        emu_.Get<Imx51Usboh3>().OtgHostRootPort().Attach(std::move(hub));

        debounce_thread_ = std::thread([this] { DebounceLoop(); });
    }

    void OnShutdown() override { StopDebounceThread(); }
    ~FordSync2UsbSdBridge() override { StopDebounceThread(); }

private:
    void DebounceLoop() {
        auto& usboh3 = emu_.Get<Imx51Usboh3>();
        std::unique_lock<std::mutex> lk(mtx_);
        while (!stop_ && !usboh3.HostPortReported()) {
            cv_.wait_for(lk, std::chrono::milliseconds(200), [&] { return stop_; });
        }
        if (stop_) return;
        cv_.wait_for(lk, kDebounceInterval, [&] { return stop_; });
        if (stop_) return;
        lk.unlock();
        {
            auto& freeze = emu_.Get<EmulationFreeze>();
            auto frozen = freeze.WorkerSection();
            hub_->Port(0).BeginForceDetach();
        }
        lk.lock();
        cv_.wait_for(lk, kReattachGap, [&] { return stop_; });
        if (stop_) return;
        lk.unlock();
        auto& freeze = emu_.Get<EmulationFreeze>();
        auto frozen = freeze.WorkerSection();
        hub_->Port(0).EndForceDetach();
    }

    void StopDebounceThread() {
        {
            std::lock_guard<std::mutex> lk(mtx_);
            stop_ = true;
        }
        cv_.notify_all();
        if (debounce_thread_.joinable()) debounce_thread_.join();
    }

    DiskImage                disk_;
    UsbHub*                  hub_ = nullptr;
    std::thread              debounce_thread_;
    std::mutex                mtx_;
    std::condition_variable  cv_;
    bool                      stop_ = false;
};

}

REGISTER_SERVICE(FordSync2UsbSdBridge);
