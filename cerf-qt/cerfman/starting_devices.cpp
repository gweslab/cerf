#include "starting_devices.h"

#include "device_run_state.h"
#include "local_manifest_store.h"
#include "manager_operations.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QTimer>

#include <chrono>

REGISTER_SERVICE(StartingDevices);

namespace {

constexpr std::chrono::milliseconds kStatusWait{5000};

}

void StartingDevices::Mark(const QString& name) {
    started_[name].start();
    QTimer::singleShot(kStatusWait, &context_, [this] { emit emu_.Get<ManagerOperations>().devicesChanged(); });
}

bool StartingDevices::Pending(const QString& name) const {
    const auto started = started_.constFind(name);
    return started != started_.constEnd() && !started->hasExpired(kStatusWait.count()) &&
           !ReadRunningStatus(LocalManifestStore::DevicePath(name));
}
