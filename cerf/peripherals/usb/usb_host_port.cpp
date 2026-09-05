#include "usb_host_port.h"

#include "../../state/state_stream.h"
#include "usb_state.h"

void UsbHostPort::Attach(std::unique_ptr<UsbDevice> device) {
    device_ = std::move(device);
    force_detached_ = false;
    host_.OnPortConnectChanged(port_index_);
}

void UsbHostPort::Detach() {
    if (!device_) return;
    device_.reset();
    force_detached_ = false;
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
    w.Write<uint32_t>(device_ ? device_->StateKind() : 0);
    w.Write<uint8_t>(force_detached_ ? 1 : 0);
    const uint64_t length_pos = w.BytesWritten();
    w.Write<uint64_t>(0);
    const uint64_t start = w.BytesWritten();
    if (device_) device_->SaveState(w);
    const uint64_t length = w.BytesWritten() - start;
    w.PatchAt(length_pos, &length, sizeof(length));
}

void UsbHostPort::RestoreState(StateReader& r) {
    uint32_t kind = 0; uint8_t detached = 0; uint64_t length = 0;
    r.Read(kind); r.Read(detached); r.Read(length);
    const auto start = r.Position();
    UsbState::Require(r.Ok() && detached <= 1 && start <= r.FileSize() &&
                      length <= r.FileSize() - start, "invalid device frame");
    // Recreate even a same-kind device: its saved image/CID may differ.
    // Release the old exclusive writable file binding before reopening saved media.
    device_.reset();
    std::unique_ptr<UsbDevice> restored;
    if (kind) {
        UsbState::Require(static_cast<bool>(factory_), "no device factory");
        restored = factory_(kind);
        UsbState::Require(restored != nullptr, "unsupported device kind");
        restored->RestoreState(r);
    } else {
        UsbState::Require(length == 0 && detached == 0, "invalid empty port");
    }
    UsbState::Require(r.Ok() && r.Position() == start + length, "device frame mismatch");
    device_ = std::move(restored);
    force_detached_ = detached != 0;
}

void UsbHostPort::PostRestore() {
    if (device_) device_->PostRestore();
}
