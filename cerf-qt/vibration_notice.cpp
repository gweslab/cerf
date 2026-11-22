#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/notification_stack.h>
#include <cerfcore/host/vibration_outputs.h>

#include <chrono>
#include <mutex>
#include <set>

namespace cerffrontend {

namespace {

constexpr char                      kVibratingText[] = "The device vibrates";
constexpr std::chrono::milliseconds kLinger{2000};

class VibrationNotice final : public cerfcore::VibrationOutputs {
public:
    using cerfcore::VibrationOutputs::VibrationOutputs;

    void SetVibrating(const cerfcore::MachineVibrator& vibrator, bool vibrating) override {
        std::lock_guard<std::mutex> lk(mtx_);
        if (vibrating) vibrating_.insert(&vibrator);
        else           vibrating_.erase(&vibrator);
        auto& stack = emu_.Get<cerfcore::NotificationStack>();
        if (vibrating_.empty()) stack.CloseAfter(cerfcore::NotificationId::DeviceVibrating, kLinger);
        else stack.Show(cerfcore::NotificationId::DeviceVibrating, cerfcore::NotificationKind::Warning, kVibratingText);
    }

private:
    std::mutex                                 mtx_;
    std::set<const cerfcore::MachineVibrator*> vibrating_;
};

}

REGISTER_SERVICE_AS(VibrationNotice, cerfcore::VibrationOutputs);

}
