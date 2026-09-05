#pragma once

#include "ford_sync2_media_hub_sd_reader.h"
#include "../../peripherals/usb/usb_hub.h"
#include <algorithm>
#include <array>

// Board topology and timing, independent of the host UI. Access while quiesced.
class FordSync2UsbMediaHub final : public UsbHub {
public:
    FordSync2UsbMediaHub() : UsbHub(2) {
        for (int i = 0; i < 2; ++i) {
            Port(i).SetRestoreFactory([i](uint32_t kind) -> std::unique_ptr<UsbDevice> {
                if (i == 0 && kind == 3) return std::make_unique<FordSync2MediaHubSdReader>();
                if (i == 1 && kind == 2) return std::make_unique<UsbMassStorageDevice>();
                return {};
            });
        }
    }
    uint32_t StateKind() const override { return 4; }

    void SetMedia(int port, std::unique_ptr<UsbDevice> device, bool startup = false) {
        Port(port).Detach();
        gap_ms_[port] = 0;
        if (port == 0) { boot_stage_ = 0; boot_remaining_ms_ = 0; }
        if (!device) return;
        Port(port).Attach(std::move(device));
        if (startup) {
            if (port == 0) boot_stage_ = 1; // wait until host reports its port
        } else {
            // Let the guest observe a disconnect before enumerating replacement media.
            Port(port).BeginForceDetach();
            gap_ms_[port] = 100;
        }
    }

    void Tick(uint32_t elapsed_ms, bool host_ready) override {
        for (int i = 0; i < 2; ++i) {
            if (!gap_ms_[i]) continue;
            gap_ms_[i] -= (std::min)(gap_ms_[i], elapsed_ms);
            if (!gap_ms_[i]) Port(i).EndForceDetach();
        }
        if (boot_stage_ == 1 && host_ready) {
            // Real unit MsgLog: USB debounce timer 17000 ms, followed by reattach.
            boot_stage_ = 2; boot_remaining_ms_ = 17000;
        } else if (boot_stage_ >= 2) {
            boot_remaining_ms_ -= (std::min)(boot_remaining_ms_, elapsed_ms);
            if (!boot_remaining_ms_) {
                if (boot_stage_ == 2) {
                    Port(0).BeginForceDetach();
                    boot_stage_ = 3; boot_remaining_ms_ = 100;
                } else {
                    Port(0).EndForceDetach(); boot_stage_ = 0;
                }
            }
        }
    }
    void SaveState(StateWriter& w) override {
        UsbHub::SaveState(w);
        w.Write(boot_stage_); w.Write(boot_remaining_ms_);
        for (auto gap : gap_ms_) w.Write(gap);
    }
    void RestoreState(StateReader& r) override {
        UsbHub::RestoreState(r);
        r.Read(boot_stage_); r.Read(boot_remaining_ms_);
        for (auto& gap : gap_ms_) r.Read(gap);
        UsbState::Require(r.Ok() && boot_stage_ <= 3 && boot_remaining_ms_ <= 17000 &&
            gap_ms_[0] <= 100 && gap_ms_[1] <= 100 &&
            (boot_stage_ == 0 || Port(0).Device()), "invalid Media Hub timer");
        UsbState::Require((boot_stage_ >= 2 || boot_remaining_ms_ == 0) &&
            (boot_stage_ != 3 || boot_remaining_ms_ <= 100) &&
            (boot_stage_ == 0 || gap_ms_[0] == 0), "inconsistent Media Hub timer");
        for (int i = 0; i < 2; ++i) {
            const bool disconnected = gap_ms_[i] != 0 || (i == 0 && boot_stage_ == 3);
            UsbState::Require(!disconnected || Port(i).Device(), "timer without media");
            UsbState::Require(!Port(i).Device() || Port(i).IsConnected() != disconnected,
                "timer disagrees with media connection");
        }
    }
private:
    uint8_t boot_stage_ = 0;
    uint32_t boot_remaining_ms_ = 0;
    std::array<uint32_t, 2> gap_ms_{};
};
