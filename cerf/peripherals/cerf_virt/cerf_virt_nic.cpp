#include "cerf_virt_addr_map.h"
#include "cerf_virt_nic_regs.h"
#include "cerf_virt_nic_stage.h"

#include "../peripheral_base.h"
#include "../peripheral_dispatcher.h"
#include "../../boards/board_context.h"
#include "../../host/host_auto_resize.h"
#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../net/mac_address.h"
#include "../../net/network_backend.h"
#include "../../state/state_stream.h"

#include <array>
#include <atomic>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <vector>

namespace {

const uint32_t kMaxFrame = CerfVirt::kNicSlotSize - CerfVirt::kNicSlotPayloadOff;

class CerfVirtNic : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        return emu_.Get<DeviceConfig>().guest_additions;
    }

    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);

        nic_enabled_ = emu_.Get<DeviceConfig>().network_enabled;
        if (!nic_enabled_) {
            LOG(Net, "[GA-NIC] networking disabled: regs PA 0x%08X reports no channel\n",
                MmioBase());
            return;
        }

        guest_mac_ = emu_.Get<NetworkBackend>().AttachReceiver(
            "ga-nic", NetworkBackend::ReceiverKind::Ethernet,
            [this](const uint8_t* frame, std::size_t len) { OnRxFrame(frame, len); });
        rx_installed_ = true;

        LOG(Net, "[GA-NIC] ready: MAC=%s regs PA 0x%08X\n",
            cerf::inet::FormatMac(guest_mac_.data()).s, MmioBase());
    }

    void OnShutdown() override { DetachRx(); }

    uint32_t MmioBase() const override {
        return emu_.Get<BoardContext>().GuestAdditionsWindowBase() +
               CerfVirt::kNicRegsOffset;
    }
    uint32_t MmioSize() const override { return CerfVirt::kNicRegsSize; }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        if (!nic_enabled_) {
            if (off == CerfVirt::kNicRegMagic) return 0u;
            emu_.Get<Fatal>().Die(
                "[GA-NIC] read of register offset 0x%X with networking disabled", off);
            return 0u;
        }
        switch (off) {
        case CerfVirt::kNicRegMagic:      return CerfVirt::kNicMagic;
        case CerfVirt::kNicRegMacWord0: {
            std::lock_guard<std::mutex> lk(mu_);
            return cerf::le::U32(guest_mac_.data(), 0);
        }
        case CerfVirt::kNicRegMacWord1: {
            std::lock_guard<std::mutex> lk(mu_);
            return cerf::le::U16(guest_mac_.data(), 4);
        }
        case CerfVirt::kNicRegLinkUp:     return 1u;
        case CerfVirt::kNicRegMaxFrame:   return kMaxFrame;
        case CerfVirt::kNicRegTxWriteSeq: return tx_write_seq_.load(std::memory_order_acquire);
        case CerfVirt::kNicRegTxReadSeq:  return tx_read_seq_.load(std::memory_order_acquire);
        case CerfVirt::kNicRegRxWriteSeq: return rx_write_seq_.load(std::memory_order_acquire);
        case CerfVirt::kNicRegRxReadSeq:  return rx_read_seq_.load(std::memory_order_acquire);
        case CerfVirt::kNicRegRxDropped:  return rx_dropped_.load(std::memory_order_relaxed);
        default:
            emu_.Get<Fatal>().Die("[GA-NIC] read of undefined register offset 0x%X", off);
            return 0u;
        }
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - MmioBase();
        if (!nic_enabled_) {
            emu_.Get<Fatal>().Die(
                "[GA-NIC] write 0x%08X to offset 0x%X with networking disabled",
                value, off);
            return;
        }
        switch (off) {
        case CerfVirt::kNicRegTxWriteSeq: {
            std::vector<std::vector<uint8_t>> batch;
            {
                std::lock_guard<std::mutex> lk(mu_);
                CollectTxLocked(value, batch);
            }
            NetworkBackend& net = emu_.Get<NetworkBackend>();
            if (!batch.empty()) emu_.Get<HostAutoResize>().MarkTx();
            for (auto& f : batch) net.SendFrame(f.data(), f.size());
            break;
        }
        case CerfVirt::kNicRegRxReadSeq:
            rx_read_seq_.store(value, std::memory_order_release);
            break;
        default:
            emu_.Get<Fatal>().Die("[GA-NIC] write 0x%08X to undefined register offset 0x%X",
                                  value, off);
        }
    }

    void SaveState(StateWriter& w) override {
        w.Write<uint32_t>(tx_write_seq_.load());
        w.Write<uint32_t>(tx_read_seq_.load());
        w.Write<uint32_t>(rx_write_seq_.load());
        w.Write<uint32_t>(rx_read_seq_.load());
        w.Write<uint32_t>(rx_dropped_.load());
        for (uint8_t b : guest_mac_) w.Write<uint8_t>(b);
    }

    void RestoreState(StateReader& r) override {
        uint32_t v;
        r.Read(v); tx_write_seq_.store(v);
        r.Read(v); tx_read_seq_.store(v);
        r.Read(v); rx_write_seq_.store(v);
        r.Read(v); rx_read_seq_.store(v);
        r.Read(v); rx_dropped_.store(v);
        for (auto& b : guest_mac_) { uint8_t x; r.Read(x); b = x; }
    }

private:
    void DetachRx() {
        if (!rx_installed_) return;
        emu_.Get<NetworkBackend>().DetachReceiver("ga-nic");
        rx_installed_ = false;
    }

    void CollectTxLocked(uint32_t new_write_seq,
                         std::vector<std::vector<uint8_t>>& out) {
        uint32_t read_seq = tx_read_seq_.load(std::memory_order_relaxed);
        const uint32_t pending = new_write_seq - read_seq;
        if (pending > CerfVirt::kNicTxSlots) {
            emu_.Get<Fatal>().Die("[GA-NIC] TX ring overrun: write_seq=%u read_seq=%u slots=%u",
                                  new_write_seq, read_seq, CerfVirt::kNicTxSlots);
            return;
        }

        CerfVirtNicStage& stage = emu_.Get<CerfVirtNicStage>();
        out.reserve(pending);

        while (read_seq != new_write_seq) {
            const uint8_t* slot = stage.TxSlot(read_seq);
            const uint32_t len = cerf::le::U32(slot, CerfVirt::kNicSlotLenOff);
            if (len == 0u || len > kMaxFrame) {
                emu_.Get<Fatal>().Die("[GA-NIC] TX slot %u declares len=%u (max %u)",
                                      read_seq % CerfVirt::kNicTxSlots, len, kMaxFrame);
                return;
            }
            const uint8_t* payload = slot + CerfVirt::kNicSlotPayloadOff;
            out.push_back(std::vector<uint8_t>(payload, payload + len));
            ++read_seq;
        }

        tx_read_seq_.store(read_seq, std::memory_order_release);
        tx_write_seq_.store(new_write_seq, std::memory_order_release);
    }

    void OnRxFrame(const uint8_t* frame, std::size_t len) {
        if (len > kMaxFrame) {
            emu_.Get<Fatal>().Die("[GA-NIC] RX frame len=%u exceeds slot capacity %u",
                                  static_cast<unsigned>(len), kMaxFrame);
            return;
        }

        std::lock_guard<std::mutex> lk(mu_);
        const uint32_t write_seq = rx_write_seq_.load(std::memory_order_relaxed);
        const uint32_t read_seq  = rx_read_seq_.load(std::memory_order_acquire);
        if (write_seq - read_seq >= CerfVirt::kNicRxSlots) {
            rx_dropped_.fetch_add(1u, std::memory_order_relaxed);
            return;
        }

        uint8_t* slot = emu_.Get<CerfVirtNicStage>().RxSlot(write_seq);
        std::memcpy(slot + CerfVirt::kNicSlotPayloadOff, frame, len);
        cerf::le::Put32(slot + CerfVirt::kNicSlotLenOff, static_cast<uint32_t>(len));

        rx_write_seq_.store(write_seq + 1u, std::memory_order_release);

        emu_.Get<HostAutoResize>().MarkRx();
    }

    std::mutex mu_;
    cerf::inet::MacAddress guest_mac_{};
    bool nic_enabled_ = false;
    bool rx_installed_ = false;

    std::atomic<uint32_t> tx_write_seq_{0};
    std::atomic<uint32_t> tx_read_seq_{0};
    std::atomic<uint32_t> rx_write_seq_{0};
    std::atomic<uint32_t> rx_read_seq_{0};
    std::atomic<uint32_t> rx_dropped_{0};
};

}

REGISTER_SERVICE(CerfVirtNic);
