#pragma once

#include "service.h"
#include "device_config.h"
#include "cerf_emulator.h"

#include <atomic>
#include <cstdint>
#include <mutex>
#include <string>

/* Thread-safe shared state for guest-additions folder sharing. The host UI
   (FolderShareWidget, UI thread) writes it; the FolderSharing peripheral and
   server (JIT thread) read it. Generation bumps on every change so the guest's
   polling orchestrator can detect mount/unmount edges. */
class FolderShareConfig : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override {
        return emu_.Get<DeviceConfig>().guest_additions;
    }

    void OnReady() override;

    void ApplyFromConfig();

    bool         Enabled()    const { return enabled_.load(std::memory_order_relaxed); }
    uint32_t     Generation() const { return generation_.load(std::memory_order_relaxed); }
    std::wstring HostRoot()   const { std::lock_guard<std::mutex> lk(mtx_); return host_root_; }
    std::wstring MountPoint() const { std::lock_guard<std::mutex> lk(mtx_); return mount_point_; }

    void Set(bool enabled, std::wstring host_root, std::wstring mount_point) {
        {
            std::lock_guard<std::mutex> lk(mtx_);
            host_root_ = std::move(host_root);
            mount_point_ = std::move(mount_point);
            enabled_.store(enabled && !host_root_.empty(), std::memory_order_relaxed);
        }
        generation_.fetch_add(1, std::memory_order_relaxed);
    }

private:
    mutable std::mutex    mtx_;
    std::atomic<bool>     enabled_{false};
    std::atomic<uint32_t> generation_{0};
    std::wstring          host_root_;
    std::wstring          mount_point_;
};
