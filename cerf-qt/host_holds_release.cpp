#include "host_holds_release.h"

#include "frontend_window.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/state/hibernation.h>

#include <utility>

namespace cerffrontend {

REGISTER_SERVICE(HostHoldsRelease);

void HostHoldsRelease::OnReady() {
    emu_.Get<cerfcore::Hibernation>().RegisterPostRestoreListener(
        [this] { emu_.Get<FrontendWindow>().RunOnUiThread([this] { ReleaseAll(); }); });
}

void HostHoldsRelease::Add(std::function<void()> release) {
    std::lock_guard<std::mutex> lk(mtx_);
    releases_.Add(std::move(release));
}

void HostHoldsRelease::ReleaseAll() {
    cerfcore::CallbackList<> releases;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        releases = releases_;
    }
    releases.Call();
}

}
