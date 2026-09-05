#pragma once

#include "usb_device.h"

#include <cstdint>
#include <memory>
#include <functional>

class StateWriter;
class StateReader;

class UsbHostPortHost {
public:
    virtual ~UsbHostPortHost() = default;
    virtual void OnPortConnectChanged(int port_index) = 0;
};

class UsbHostPort {
public:
    using Factory = std::function<std::unique_ptr<UsbDevice>(uint32_t)>;
    UsbHostPort(UsbHostPortHost& host, int port_index)
        : host_(host), port_index_(port_index) {}

    void Attach(std::unique_ptr<UsbDevice> device);
    void Detach();
    void ForceReattachCycle();
    void BeginForceDetach();
    void EndForceDetach();
    void SetRestoreFactory(Factory factory) { factory_ = std::move(factory); }

    bool       IsConnected() const { return device_ != nullptr && !force_detached_; }
    UsbDevice* Device() const { return device_.get(); }

    void SaveState(StateWriter& w);
    void RestoreState(StateReader& r);
    void PostRestore();

private:
    UsbHostPortHost&          host_;
    int                       port_index_;
    std::unique_ptr<UsbDevice> device_;
    bool                      force_detached_ = false;
    Factory                   factory_;
};
