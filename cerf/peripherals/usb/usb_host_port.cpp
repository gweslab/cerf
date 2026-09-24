#include "usb_host_port.h"

#include "../../state/state_stream.h"
#include "usb_state.h"

void UsbHostPort::Attach(std::unique_ptr<UsbDevice> device) {
    device_ = std::move(device);
    host_.OnPortConnectChanged(port_index_);
}

void UsbHostPort::Detach() {
    if (!device_) return;
    device_.reset();
    host_.OnPortConnectChanged(port_index_);
}

void UsbHostPort::SaveState(StateWriter& w) {
    w.BeginFrame(device_ ? device_->StateKind() : 0);
    if (device_) device_->SaveState(w);
    w.EndFrame();
}

void UsbHostPort::RestoreState(StateReader& r) {
    const uint32_t kind = r.EnterFrame();
    device_.reset();
    std::unique_ptr<UsbDevice> restored;
    if (kind) {
        UsbState::Require(r, static_cast<bool>(factory_), "no device factory");
        restored = factory_(kind);
        UsbState::Require(r, restored != nullptr, "unsupported device kind");
        restored->RestoreState(r);
    }
    r.LeaveFrame();
    device_ = std::move(restored);
}

void UsbHostPort::PostRestore() {
    if (device_) device_->PostRestore();
}
