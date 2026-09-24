#include "../../peripherals/pci/pci_host_bridge.h"
#include "../../peripherals/pci/pci_device.h"

#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "../../cpu/vr5500/vr5500_id.h"
#include "../../state/state_stream.h"

#include <cstdint>
#include <vector>


namespace {

constexpr uint32_t kPciMemBase = 0x08000000u;    /* PCIW0 & PCI_INIT_ADDR_MASK */

constexpr uint32_t kPciInitTypeMask = 7u << 1;   /* PCI_INIT_TYPE_MASK */
constexpr uint32_t kPciInitTypeCfg  = 5u << 1;   /* PCI_INIT_TYPE_CFG  */

constexpr uint32_t kOffPciw0     = 0x60u;
constexpr uint32_t kOffPciInit00 = 0x2F0u;

class Vrc5477Pci : public PciHostBridge {
public:
    using PciHostBridge::PciHostBridge;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Vr5500;
    }

    void RegisterPciDevice(PciDevice* dev) override { devices_.push_back(dev); }

    uint32_t CtrlReadReg(uint32_t off) override {
        if (off == kOffPciInit00) return pciinit00_;
        if (off == kOffPciw0)     return pciw0_;
        return 0;
    }
    void CtrlWriteReg(uint32_t off, uint32_t v) override {
        if (off == kOffPciInit00)      pciinit00_ = v;
        else if (off == kOffPciw0)     pciw0_ = v;
    }

    uint32_t WindowRead(uint32_t addr, unsigned size) override {
        if (IsConfigCycle()) {
            PciDevice* d = nullptr; uint32_t reg = 0;
            if (!DecodeConfig(addr, &d, &reg)) return cerf::ByteWidthMask(size);
            return Extract(d->ConfigRead(reg & ~3u), addr, size);
        }
        for (PciDevice* d : devices_)
            if (d->MemClaims(addr)) return d->MemRead(addr, size);
        return cerf::ByteWidthMask(size);
    }
    void WindowWrite(uint32_t addr, uint32_t v, unsigned size) override {
        if (IsConfigCycle()) {
            PciDevice* d = nullptr; uint32_t reg = 0;
            if (!DecodeConfig(addr, &d, &reg)) return;
            if (size >= 4) { d->ConfigWrite(reg & ~3u, v); return; }
            d->ConfigWrite(reg & ~3u, Merge(d->ConfigRead(reg & ~3u), v, reg, size));
            return;
        }
        for (PciDevice* d : devices_)
            if (d->MemClaims(addr)) { d->MemWrite(addr, v, size); return; }
    }

    uint32_t WindowIoRead(uint32_t pci_io, unsigned size) override {
        for (PciDevice* d : devices_)
            if (d->IoClaims(pci_io)) return d->IoRead(pci_io, size);
        return cerf::ByteWidthMask(size);
    }
    void WindowIoWrite(uint32_t pci_io, uint32_t v, unsigned size) override {
        for (PciDevice* d : devices_)
            if (d->IoClaims(pci_io)) { d->IoWrite(pci_io, v, size); return; }
    }

    void SaveState(StateWriter& w) override {
        w.Write("pciinit00", pciinit00_);
        w.Write("pciw0", pciw0_);
        w.Write<uint32_t>("devices_count", static_cast<uint32_t>(devices_.size()));
        for (PciDevice* d : devices_) {
            w.Write<uint16_t>("pci_dev_fnc", static_cast<uint16_t>((d->PciDev() << 8) | d->PciFnc()));
            d->SaveState(w);
        }
    }
    void RestoreState(StateReader& r) override {
        r.Read("pciinit00", pciinit00_);
        r.Read("pciw0", pciw0_);
        uint32_t n = 0;
        r.Read("devices_count", n);
        if (n != devices_.size())
            r.Reject("Vrc5477Pci: %u devices, this build has %zu", n, devices_.size());
        for (uint32_t i = 0; i < n; ++i) {
            uint16_t tag = 0;
            r.Read("pci_dev_fnc", tag);
            const uint8_t dev = static_cast<uint8_t>(tag >> 8);
            const uint8_t fnc = static_cast<uint8_t>(tag & 0xFFu);
            size_t match = devices_.size();
            for (size_t k = 0; k < devices_.size(); ++k)
                if (devices_[k]->PciDev() == dev && devices_[k]->PciFnc() == fnc) { match = k; break; }
            if (match == devices_.size())
                r.Reject("Vrc5477Pci: no device dev=%u fnc=%u in this build", dev, fnc);
            devices_[match]->RestoreState(r);
        }
    }

    void PostRestore() override {
        for (PciDevice* d : devices_) d->PostRestore();
    }

private:
    bool IsConfigCycle() const { return (pciinit00_ & kPciInitTypeMask) == kPciInitTypeCfg; }

    bool DecodeConfig(uint32_t addr, PciDevice** out_dev, uint32_t* out_reg) {
        const uint32_t off    = addr - kPciMemBase;
        const uint32_t devsel = off & ~0x7FFu;        /* bits >=11 hold 1<<(dev+10) */
        const uint32_t fnc    = (off >> 8) & 7u;
        for (uint32_t dev = 1; dev <= 21; ++dev) {
            if (devsel != (1u << (dev + 10))) continue;
            for (PciDevice* d : devices_)
                if (d->PciDev() == dev && d->PciFnc() == fnc) {
                    *out_dev = d; *out_reg = off & 0xFFu; return true;
                }
            return false;                              /* valid slot, no device = absent */
        }
        return false;
    }

    static uint32_t Extract(uint32_t dword, uint32_t addr, unsigned size) {
        return (dword >> ((addr & 3u) * 8u)) & cerf::ByteWidthMask(size);
    }
    static uint32_t Merge(uint32_t dword, uint32_t v, uint32_t reg, unsigned size) {
        const unsigned shift = (reg & 3u) * 8u;
        const uint32_t mask  = cerf::ByteWidthMask(size) << shift;
        return (dword & ~mask) | ((v << shift) & mask);
    }

    std::vector<PciDevice*> devices_;
    uint32_t pciinit00_ = 0;
    uint32_t pciw0_     = 0;
};

REGISTER_SERVICE_AS(Vrc5477Pci, PciHostBridge);

}  /* namespace */
