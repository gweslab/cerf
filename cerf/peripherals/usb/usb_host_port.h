#pragma once

#include "usb_device.h"

#include <cstdint>
#include <memory>

class StateWriter;
class StateReader;

class UsbHostPortHost {
public:
    virtual ~UsbHostPortHost() = default;
    virtual void OnPortConnectChanged(int port_index) = 0;
};

class UsbHostPort {
public:
    UsbHostPort(UsbHostPortHost& host, int port_index)
        : host_(host), port_index_(port_index) {}

    void Attach(std::unique_ptr<UsbDevice> device);
    void Detach();

    bool       IsConnected() const { return device_ != nullptr; }
    UsbDevice* Device() const { return device_.get(); }

    void SaveState(StateWriter& w);
    void RestoreState(StateReader& r);
    void PostRestore();

private:
    UsbHostPortHost&          host_;
    int                       port_index_;
    std::unique_ptr<UsbDevice> device_;
};
