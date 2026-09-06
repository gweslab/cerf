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
    w.Write<uint32_t>(device_ ? device_->StateKind() : 0);
    const uint64_t length_pos = w.BytesWritten();
    w.Write<uint64_t>(0);
    const uint64_t start = w.BytesWritten();
    if (device_) device_->SaveState(w);
    const uint64_t length = w.BytesWritten() - start;
    w.PatchAt(length_pos, &length, sizeof(length));
}

void UsbHostPort::RestoreState(StateReader& r) {
    uint32_t kind = 0; uint64_t length = 0;
    r.Read(kind); r.Read(length);
    const auto start = r.Position();
    UsbState::Require(r.Ok() && start <= r.FileSize() &&
                      length <= r.FileSize() - start, "invalid device frame");
    device_.reset();
    std::unique_ptr<UsbDevice> restored;
    if (kind) {
        UsbState::Require(static_cast<bool>(factory_), "no device factory");
        restored = factory_(kind);
        UsbState::Require(restored != nullptr, "unsupported device kind");
        restored->RestoreState(r);
    } else {
        UsbState::Require(length == 0, "invalid empty port");
    }
    UsbState::Require(r.Ok() && r.Position() == start + length, "device frame mismatch");
    device_ = std::move(restored);
}

void UsbHostPort::PostRestore() {
    if (device_) device_->PostRestore();
}
