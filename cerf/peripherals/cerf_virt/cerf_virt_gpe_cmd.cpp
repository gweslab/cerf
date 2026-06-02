#include "cerf_virt_gpe_cmd.h"
#include "cerf_virt_blt_descriptor.h"
#include "cerf_virt_grad_descriptor.h"
#include "cerf_virt_blitter.h"
#include "cerf_virt_addr_map.h"

#include "../peripheral_base.h"
#include "../peripheral_dispatcher.h"
#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../core/log.h"
#include "../../jit/arm_mmu.h"

#include <cstring>

namespace {

class CerfVirtGpeCmd : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        return emu_.Get<DeviceConfig>().guest_additions;
    }

    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
        std::memset(regs_, 0, sizeof(regs_));
        regs_[CerfVirt::kGpeCmdStatus / 4] = CerfVirt::kGpeStatusIdle;
    }

    uint32_t MmioBase() const override { return CerfVirt::kGpeCmdBase; }
    uint32_t MmioSize() const override { return CerfVirt::kGpeCmdSize; }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - MmioBase();
        if (off >= sizeof(regs_)) return 0u;
        return regs_[off / 4];
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t off = addr - MmioBase();
        if (off == CerfVirt::kGpeCmdKick)     { ExecuteCmd();     return; }
        if (off == CerfVirt::kGpeCmdGradKick) { ExecuteGradCmd(); return; }
        if (off >= sizeof(regs_)) return;
        if (off == CerfVirt::kGpeCmdStatus) return;
        regs_[off / 4] = value;
    }

private:
    /* Copy a descriptor out of guest memory in the issuing process context;
       it may straddle a page, so resolve per page through the live MMU. */
    bool ReadBlob(uint32_t va, void* out, uint32_t total) {
        ArmMmu& mmu = emu_.Get<ArmMmu>();
        uint8_t* d = reinterpret_cast<uint8_t*>(out);
        uint32_t done = 0;
        while (done < total) {
            uint8_t* p = mmu.PeekVaToHost(va + done);
            if (!p) return false;
            const uint32_t page_left = 0x1000u - ((va + done) & 0x0FFFu);
            const uint32_t n = (total - done) < page_left ? (total - done) : page_left;
            std::memcpy(d + done, p, n);
            done += n;
        }
        return true;
    }

    void ExecuteCmd() {
        regs_[CerfVirt::kGpeCmdStatus / 4] = CerfVirt::kGpeStatusBusy;
        const uint32_t desc_va = regs_[CerfVirt::kGpeCmdDescVa / 4];

        CerfVirt::CerfBltDescriptor d;
        if (!ReadBlob(desc_va, &d, (uint32_t)sizeof(d))) {
            LOG(Periph, "[CerfVirtGpeCmd] descriptor VA 0x%08X unreadable\n", desc_va);
            regs_[CerfVirt::kGpeCmdStatus / 4] = CerfVirt::kGpeStatusError;
            return;
        }
        const bool ok = emu_.Get<CerfVirt::CerfVirtBlitter>().Execute(d);
        regs_[CerfVirt::kGpeCmdStatus / 4] =
            ok ? CerfVirt::kGpeStatusDone : CerfVirt::kGpeStatusError;
    }

    void ExecuteGradCmd() {
        regs_[CerfVirt::kGpeCmdStatus / 4] = CerfVirt::kGpeStatusBusy;
        const uint32_t desc_va = regs_[CerfVirt::kGpeCmdDescVa / 4];

        CerfVirt::CerfGradDescriptor g;
        if (!ReadBlob(desc_va, &g, (uint32_t)sizeof(g))) {
            LOG(Periph, "[CerfVirtGpeCmd] gradient VA 0x%08X unreadable\n", desc_va);
            regs_[CerfVirt::kGpeCmdStatus / 4] = CerfVirt::kGpeStatusError;
            return;
        }
        const bool ok = emu_.Get<CerfVirt::CerfVirtBlitter>().ExecuteGradient(g);
        regs_[CerfVirt::kGpeCmdStatus / 4] =
            ok ? CerfVirt::kGpeStatusDone : CerfVirt::kGpeStatusError;
    }

    uint32_t regs_[4];
};

REGISTER_SERVICE(CerfVirtGpeCmd);

}  /* namespace */
