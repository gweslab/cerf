#define NOMINMAX

#include "emulation_pause.h"

#include "../core/cerf_emulator.h"
#include "../jit/jit_runner.h"
#include "notification_stack.h"

#include <windows.h>

REGISTER_SERVICE(EmulationPause);

bool EmulationPause::UserCanToggle() const {
    return !state_operation_.load(std::memory_order_acquire) &&
           emu_.Get<JitRunner>().Started();
}

void EmulationPause::Toggle() {
    std::lock_guard<std::mutex> lk(mtx_);
    if (!UserCanToggle()) return;
    const bool user = !user_.load(std::memory_order_acquire);
    Apply(user, false);
    ShowUserCard(user);
}

void EmulationPause::BeginStateOperation() {
    std::lock_guard<std::mutex> lk(mtx_);
    Apply(user_.load(std::memory_order_acquire), true);
}

void EmulationPause::EndStateOperation(bool release_user_pause) {
    std::lock_guard<std::mutex> lk(mtx_);
    const bool was_user = user_.load(std::memory_order_acquire);
    const bool user     = was_user && !release_user_pause;
    Apply(user, false);
    if (was_user && !user) ShowUserCard(false);
}

void EmulationPause::Apply(bool user, bool state_operation) {
    const bool was = IsPaused();
    const bool now = user || state_operation;
    if (now && !was) pause_tick_ms_.store(GetTickCount64(), std::memory_order_release);
    user_.store(user, std::memory_order_release);
    state_operation_.store(state_operation, std::memory_order_release);
    if (now == was) return;
    auto& runner = emu_.Get<JitRunner>();
    if (now) runner.Pause();
    else     runner.Resume();
}

void EmulationPause::ShowUserCard(bool shown) {
    auto& stack = emu_.Get<NotificationStack>();
    if (shown) {
        stack.Show(NotificationId::EmulatorPaused, NotificationKind::Warning,
                   L"The emulator is paused\nResume it in Actions menu");
    } else {
        stack.Close(NotificationId::EmulatorPaused);
    }
}

uint64_t EmulationPause::AnimationTickMs() const {
    return IsPaused() ? pause_tick_ms_.load(std::memory_order_acquire)
                      : GetTickCount64();
}
