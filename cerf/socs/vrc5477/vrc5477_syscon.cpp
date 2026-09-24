#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "../../cpu/vr5500/vr5500_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../peripherals/pci/pci_host_bridge.h"
#include "../../state/state_stream.h"
#include "vrc5477_intc.h"

#include <cstdint>
#include <cstring>


namespace {

constexpr uint32_t kBlockBase = 0x1FA00000u;
constexpr uint32_t kBlockSize = 0x800u;       /* low system-controller register block */

constexpr uint32_t kIntcLo = 0x400u;          /* INTC sub-block, delegated to Vrc5477Intc */
constexpr uint32_t kIntcHi = 0x490u;

/* PCI host-bridge control registers delegated to the PciHostBridge (it needs them
   to decode config-vs-memory window cycles): PCIW0 @0x60, PCIINIT00 @0x2F0. */
constexpr uint32_t kPciW0    = 0x60u;
constexpr uint32_t kPciInit00 = 0x2F0u;

/* Active sub-blocks that generate interrupts/transfers loud-fatal here until each
   has its own full peripheral: store/readback would silently stub them (no IRQ,
   no DMA) and hang the guest with no diagnostic. */
bool IsActiveBlock(uint32_t off, const char** which) {
    if (off >= 0x1D0u && off < 0x200u) { *which = "SPT/WDT timer"; return true; }
    if (off >= 0x300u && off < 0x3C0u) { *which = "DMA";           return true; }
    return false;
}

class Vrc5477SysCon : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Vr5500;
    }
    void OnReady() override { emu_.Get<PeripheralDispatcher>().Register(this); }

    uint32_t MmioBase() const override { return kBlockBase; }
    uint32_t MmioSize() const override { return kBlockSize; }

    uint8_t  ReadByte (uint32_t addr) override            { return Read<uint8_t>(addr); }
    uint16_t ReadHalf (uint32_t addr) override            { return Read<uint16_t>(addr); }
    uint32_t ReadWord (uint32_t addr) override            { return Read<uint32_t>(addr); }
    void WriteByte(uint32_t addr, uint8_t  v) override    { Write<uint8_t>(addr, v); }
    void WriteHalf(uint32_t addr, uint16_t v) override    { Write<uint16_t>(addr, v); }
    void WriteWord(uint32_t addr, uint32_t v) override    { Write<uint32_t>(addr, v); }

    void SaveState(StateWriter& w) override {
        w.WriteBytes("regs", regs_, sizeof(regs_));
        emu_.Get<Vrc5477Intc>().SaveState(w);
    }
    void RestoreState(StateReader& r) override {
        r.ReadBytes("regs", regs_, sizeof(regs_));
        emu_.Get<Vrc5477Intc>().RestoreState(r);
    }
    void PostRestore() override { emu_.Get<Vrc5477Intc>().Renotify(); }

private:
    template <typename T> T Read(uint32_t addr) {
        const uint32_t off = addr - kBlockBase;
        if (off >= kIntcLo && off < kIntcHi) {
            if constexpr (sizeof(T) == 4) {
                return static_cast<T>(emu_.Get<Vrc5477Intc>().ReadReg(off - kIntcLo));
            } else {
                HaltUnsupportedAccess("INTC sub-word read", addr, 0);
            }
        }
        if (off == kPciW0 || off == kPciInit00) {
            if constexpr (sizeof(T) == 4) {
                return static_cast<T>(emu_.Get<PciHostBridge>().CtrlReadReg(off));
            } else {
                HaltUnsupportedAccess("PCI ctrl sub-word read", addr, 0);
            }
        }
        const char* which = nullptr;
        if (IsActiveBlock(off, &which)) {
            LOG(Caution, "Vrc5477SysCon: %s read off=0x%03X not implemented "
                "(must be a full peripheral)\n", which, off);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        T v{};
        std::memcpy(&v, &regs_[off], sizeof(T));
        return v;
    }
    template <typename T> void Write(uint32_t addr, T v) {
        const uint32_t off = addr - kBlockBase;
        if (off >= kIntcLo && off < kIntcHi) {
            if constexpr (sizeof(T) == 4) {
                emu_.Get<Vrc5477Intc>().WriteReg(off - kIntcLo, static_cast<uint32_t>(v));
                return;
            } else {
                HaltUnsupportedAccess("INTC sub-word write", addr, v);
            }
        }
        if (off == kPciW0 || off == kPciInit00) {
            if constexpr (sizeof(T) == 4) {
                emu_.Get<PciHostBridge>().CtrlWriteReg(off, static_cast<uint32_t>(v));
                return;
            } else {
                HaltUnsupportedAccess("PCI ctrl sub-word write", addr, v);
            }
        }
        const char* which = nullptr;
        if (IsActiveBlock(off, &which)) {
            LOG(Caution, "Vrc5477SysCon: %s write off=0x%03X val=0x%08X not "
                "implemented (must be a full peripheral)\n", which, off,
                static_cast<uint32_t>(v));
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        std::memcpy(&regs_[off], &v, sizeof(T));
    }

    uint8_t regs_[kBlockSize] = {};
};

}  /* namespace */

REGISTER_SERVICE(Vrc5477SysCon);
