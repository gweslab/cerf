#include "usb_host_port.h"

#include "../../state/state_stream.h"

void UsbHostPort::Attach(std::unique_ptr<UsbDevice> device) {
    device_ = std::move(device);
    host_.OnPortConnectChanged(port_index_);
}

void UsbHostPort::Detach() {
    if (!device_) return;
    device_.reset();
    host_.OnPortConnectChanged(port_index_);
}

void UsbHostPort::ForceReattachCycle() {
    if (!device_) return;
    force_detached_ = true;
    host_.OnPortConnectChanged(port_index_);
    force_detached_ = false;
    host_.OnPortConnectChanged(port_index_);
}

void UsbHostPort::BeginForceDetach() {
    if (!device_ || force_detached_) return;
    force_detached_ = true;
    host_.OnPortConnectChanged(port_index_);
}

void UsbHostPort::EndForceDetach() {
    if (!device_ || !force_detached_) return;
    force_detached_ = false;
    host_.OnPortConnectChanged(port_index_);
}

void UsbHostPort::SaveState(StateWriter& w) {
    const bool connected = IsConnected();
    w.Write(connected);
    if (connected) device_->SaveState(w);
}

void UsbHostPort::RestoreState(StateReader& r) {
    bool connected = false;
    r.Read(connected);
    if (connected && device_) device_->RestoreState(r);
}

void UsbHostPort::PostRestore() {
    if (device_) device_->PostRestore();
}
