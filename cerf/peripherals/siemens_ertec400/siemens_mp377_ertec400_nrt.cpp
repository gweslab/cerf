#define NOMINMAX

#include "siemens_mp377_ertec400_nrt.h"

#include "siemens_mp377_ertec400.h"

#include "../../boards/board_context.h"
#include "../../boards/siemens_mp377/siemens_mp377_id.h"
#include "../../core/cerf_emulator.h"
#include "../../cpu/emulated_memory.h"
#include "../../core/byte_order.h"
#include "../../net/ipv4_packet.h"
#include "../../net/network_backend.h"
#include "../../socs/irq_controller.h"
#include "../../state/emulation_freeze.h"
#include "../../state/state_stream.h"
#include "../../socs/guest_cpu_reset.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <mutex>
#include <vector>

namespace {

constexpr uint32_t kDmaPhysicalBase = 0x0F800000u;
constexpr uint32_t kDescriptorOwned = 0x20000000u;
constexpr uint32_t kDescriptorLengthMask = 0x000007FFu;
constexpr uint32_t kReceiveStatusMask = 0x18000000u;
constexpr uint32_t kReceivePortMask = 0x00003000u;
constexpr uint32_t kReceiveErrorBit = 0x00008000u;
constexpr uint32_t kLinkChangeEvent = siemens_mp377::kErtecIrqLinkChangeHiBit;
constexpr uint32_t kMaximumDescriptors = 1024u;
constexpr std::size_t kMaximumFrameLength = cerf::inet::kEthMaxFrameSize;
constexpr std::size_t kDescriptorSize = 16u;
constexpr std::size_t kDescOffControl = 0u;
constexpr std::size_t kDescOffNext    = 4u;
constexpr std::size_t kDescOffBuffer  = 12u;

/* siemens_mp377_v1040 eddertec400.dll EDDDeviceOpen,
   sub_28EB77C/sub_28EB7C0. */
uint64_t AsicAddressToPhysical(uint32_t address) {
    if ((address & 0xE0000000u) == 0x20000000u)
        return static_cast<uint64_t>(kDmaPhysicalBase) + (address & 0x1FFFFFFFu);
    if ((address & 0xC0000000u) == 0xC0000000u) return address & 0x0FFFFFFFu;
    return address;
}

using cerf::le::Put32;
using cerf::le::U32;

} // namespace

struct SiemensMp377Ertec400Nrt::Impl {
    explicit Impl(CerfEmulator& emulator) : emu(emulator) {}

    CerfEmulator& emu;
    mutable std::mutex mutex;
    std::array<uint32_t, 4> tx_base{};
    std::array<uint32_t, 4> rx_base{};
    std::array<uint32_t, 4> tx_cursor{};
    std::array<uint32_t, 4> rx_cursor{};
    std::array<bool, 4> rx_armed{};
    uint32_t interrupt_status_high = 0;
    uint32_t interrupt_mask_high = 0;
    bool interrupt_asserted = false;
    bool link_event_sent = false;
    bool receive_callback_installed = false;

    uint8_t* Span(uint32_t asic_address, std::size_t size) {
        if (size == 0u) return nullptr;
        const uint64_t physical = AsicAddressToPhysical(asic_address);
        const uint64_t last = physical + size - 1u;
        if (last > 0xFFFFFFFFull) return nullptr;
        auto& memory = emu.Get<EmulatedMemory>();
        uint8_t* first = memory.TryTranslateWrite(static_cast<uint32_t>(physical));
        uint8_t* final = memory.TryTranslateWrite(static_cast<uint32_t>(last));
        if (!first || !final) return nullptr;
        const uintptr_t expected = reinterpret_cast<uintptr_t>(first) + size - 1u;
        return reinterpret_cast<uintptr_t>(final) == expected ? first : nullptr;
    }

    void UpdateIrqLocked() {
        const bool pending = (interrupt_status_high & interrupt_mask_high) != 0u;
        if (pending && !interrupt_asserted) {
            interrupt_asserted = true;
            emu.Get<IrqController>().AssertIrq(siemens_mp377::kErtecIrqSource);
        } else if (!pending && interrupt_asserted) {
            interrupt_asserted = false;
            emu.Get<IrqController>().DeAssertIrq(siemens_mp377::kErtecIrqSource);
        }
    }

    void RaiseEventLocked(uint32_t bits) {
        interrupt_status_high |= bits;
        UpdateIrqLocked();
    }

    std::vector<std::vector<uint8_t>> TransmitLocked(uint32_t channel) {
        std::vector<std::vector<uint8_t>> frames;
        uint32_t cursor = tx_cursor[channel] ? tx_cursor[channel] : tx_base[channel];
        for (uint32_t count = 0; count < kMaximumDescriptors && cursor; ++count) {
            uint8_t* descriptor = Span(cursor, kDescriptorSize);
            if (!descriptor) break;
            uint32_t control = U32(descriptor + kDescOffControl);
            if ((control & kDescriptorOwned) == 0u) break;

            const uint32_t length = control & kDescriptorLengthMask;
            const uint32_t next = U32(descriptor + kDescOffNext);
            const uint32_t buffer_address = U32(descriptor + kDescOffBuffer);
            if (length == 0u || length > kMaximumFrameLength) break;
            uint8_t* source = Span(buffer_address, length);
            if (!source) break;

            frames.emplace_back(source, source + length);
            control &= ~kDescriptorOwned;
            control &= ~kReceiveStatusMask;
            Put32(descriptor + kDescOffControl, control);
            cursor = next;
            tx_cursor[channel] = cursor;
        }
        if (!frames.empty()) RaiseEventLocked(1u << (channel * 2u));
        return frames;
    }

    void Receive(const uint8_t* frame, std::size_t length) {
        if (!frame || length < cerf::inet::kEthHeaderSize) return;
        length = std::min(length, kMaximumFrameLength);

        std::lock_guard<std::mutex> lock(mutex);
        for (uint32_t channel = 0; channel < rx_armed.size(); ++channel) {
            if (!rx_armed[channel] || !rx_base[channel]) continue;
            uint32_t cursor = rx_cursor[channel] ? rx_cursor[channel] : rx_base[channel];
            uint8_t* descriptor = Span(cursor, kDescriptorSize);
            if (!descriptor) continue;

            uint32_t control = U32(descriptor + kDescOffControl);
            if ((control & kDescriptorOwned) == 0u) continue;
            const uint32_t next = U32(descriptor + kDescOffNext);
            uint8_t* destination = Span(U32(descriptor + kDescOffBuffer), length);
            if (!destination) continue;

            std::memcpy(destination, frame, length);
            control &=
                ~(kDescriptorOwned | kDescriptorLengthMask | kReceiveStatusMask | kReceivePortMask | kReceiveErrorBit);
            control |= static_cast<uint32_t>(length);
            Put32(descriptor + kDescOffControl, control);
            rx_cursor[channel] = next;
            RaiseEventLocked(1u << (channel * 2u + 1u));
            return;
        }
    }
};

SiemensMp377Ertec400Nrt::SiemensMp377Ertec400Nrt(CerfEmulator& emu) : Service(emu), impl_(std::make_unique<Impl>(emu)) {
}

SiemensMp377Ertec400Nrt::~SiemensMp377Ertec400Nrt() = default;

bool SiemensMp377Ertec400Nrt::ShouldRegister() {
    auto* board = emu_.TryGet<BoardContext>();
    return board && board->GetBoardId() == BoardId::SiemensMp377;
}

void SiemensMp377Ertec400Nrt::OnReady() {
    Reset();
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        if (!emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) Reset();
    });
    emu_.Get<NetworkBackend>().AttachReceiver(
        "siemens-mp377-ertec400", NetworkBackend::ReceiverKind::Ethernet,
        [this](const uint8_t* frame, std::size_t length) {
            auto frozen = emu_.Get<EmulationFreeze>().WorkerSection();
            impl_->Receive(frame, length);
        });
    impl_->receive_callback_installed = true;
}

void SiemensMp377Ertec400Nrt::OnShutdown() {
    if (!impl_->receive_callback_installed) return;
    emu_.Get<NetworkBackend>().DetachReceiver("siemens-mp377-ertec400");
    impl_->receive_callback_installed = false;
}

void SiemensMp377Ertec400Nrt::Reset() {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->tx_base.fill(0);
    impl_->rx_base.fill(0);
    impl_->tx_cursor.fill(0);
    impl_->rx_cursor.fill(0);
    impl_->rx_armed.fill(false);
    impl_->interrupt_status_high = 0;
    impl_->interrupt_mask_high = 0;
    impl_->link_event_sent = false;
    impl_->UpdateIrqLocked();
}

void SiemensMp377Ertec400Nrt::ConfigureRingAddress(uint32_t channel, bool receive, uint32_t asic_address) {
    if (channel >= impl_->tx_base.size()) return;
    std::lock_guard<std::mutex> lock(impl_->mutex);
    auto& bases = receive ? impl_->rx_base : impl_->tx_base;
    auto& cursors = receive ? impl_->rx_cursor : impl_->tx_cursor;
    bases[channel] = asic_address;
    cursors[channel] = asic_address;
}

void SiemensMp377Ertec400Nrt::ExecuteCommand(uint32_t channel, uint32_t command) {
    if (channel >= impl_->tx_base.size()) return;
    std::vector<std::vector<uint8_t>> frames;
    {
        std::lock_guard<std::mutex> lock(impl_->mutex);
        if (command == 6u) {
            impl_->tx_cursor[channel] = impl_->tx_base[channel];
            impl_->rx_cursor[channel] = impl_->rx_base[channel];
            impl_->rx_armed[channel] = false;
        } else if (command == 5u) {
            impl_->rx_armed[channel] = true;
            if (!impl_->link_event_sent) {
                impl_->link_event_sent = true;
                impl_->RaiseEventLocked(kLinkChangeEvent);
            }
        } else if (command == 3u) {
            frames = impl_->TransmitLocked(channel);
        }
    }
    for (const auto& frame : frames)
        emu_.Get<NetworkBackend>().SendFrame(frame.data(), frame.size());
}

uint32_t SiemensMp377Ertec400Nrt::InterruptStatusHigh() const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    return impl_->interrupt_status_high;
}

void SiemensMp377Ertec400Nrt::AcknowledgeInterrupt() {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->interrupt_status_high = 0;
    impl_->UpdateIrqLocked();
}

void SiemensMp377Ertec400Nrt::SetInterruptMaskHigh(uint32_t mask) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->interrupt_mask_high = mask;
    impl_->UpdateIrqLocked();
}

void SiemensMp377Ertec400Nrt::SaveState(StateWriter& writer) const {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    for (uint32_t value : impl_->tx_base)
        writer.Write("tx_base", value);
    for (uint32_t value : impl_->rx_base)
        writer.Write("rx_base", value);
    for (uint32_t value : impl_->tx_cursor)
        writer.Write("tx_cursor", value);
    for (uint32_t value : impl_->rx_cursor)
        writer.Write("rx_cursor", value);
    for (bool value : impl_->rx_armed)
        writer.Write("rx_armed", static_cast<uint32_t>(value));
    writer.Write("interrupt_status_high", impl_->interrupt_status_high);
    writer.Write("interrupt_mask_high", impl_->interrupt_mask_high);
    writer.Write("link_event_sent", static_cast<uint32_t>(impl_->link_event_sent));
}

void SiemensMp377Ertec400Nrt::RestoreState(StateReader& reader) {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    for (uint32_t& value : impl_->tx_base)
        reader.Read("tx_base", value);
    for (uint32_t& value : impl_->rx_base)
        reader.Read("rx_base", value);
    for (uint32_t& value : impl_->tx_cursor)
        reader.Read("tx_cursor", value);
    for (uint32_t& value : impl_->rx_cursor)
        reader.Read("rx_cursor", value);
    for (auto&& value : impl_->rx_armed) {
        uint32_t stored = 0;
        reader.Read("rx_armed", stored);
        value = stored != 0u;
    }
    reader.Read("interrupt_status_high", impl_->interrupt_status_high);
    reader.Read("interrupt_mask_high", impl_->interrupt_mask_high);
    uint32_t link_event_sent = 0;
    reader.Read("link_event_sent", link_event_sent);
    impl_->link_event_sent = link_event_sent != 0u;
    impl_->interrupt_asserted = false;
}

void SiemensMp377Ertec400Nrt::PostRestore() {
    std::lock_guard<std::mutex> lock(impl_->mutex);
    impl_->UpdateIrqLocked();
}

REGISTER_SERVICE(SiemensMp377Ertec400Nrt);
