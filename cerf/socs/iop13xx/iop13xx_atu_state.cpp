#include "iop13xx_atu_state.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"

REGISTER_SERVICE(Iop13xxAtuState);

bool Iop13xxAtuState::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSoc() == SocFamily::IOP13xx;
}

void Iop13xxAtuState::OnReady() {
    Reset();
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        if (!emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) Reset();
    });
}

void Iop13xxAtuState::Reset() {
    atucmd_ = 0x0000u;
    atusr_ = 0x0230u;
    atucr_ = 0x00000000u;
    atuisr_ = 0u;
    atuimr_ = 0u;
    oiobar_ = 0x0FFFB000u;
    oiowtvr_ = 0u;
    oum_ = {{{0x80000001u, 0u}, {0x80000002u, 0u}, {0x00000003u, 0u}, {0x00000004u, 0u}}};
}

bool Iop13xxAtuState::OutboundGloballyEnabled() const {
    return (atucr_ & kAtucrOutboundEnable) != 0;
}

bool Iop13xxAtuState::BusMasterEnabled() const {
    return (atucmd_ & kAtucmdBusMasterEnable) != 0;
}

bool Iop13xxAtuState::OutboundMemoryWindowEnabled(uint32_t idx) const {
    return idx < kMemoryWindowCount && (oum_[idx].bar & kOutboundWindowEnable) != 0;
}

bool Iop13xxAtuState::RangeFitsLow32(uint64_t addr, uint32_t size) {
    if (size == 0) return false;
    const uint64_t low = addr & 0xFFFFFFFFull;
    return low + static_cast<uint64_t>(size) - 1ull <= 0xFFFFFFFFull;
}

bool Iop13xxAtuState::CpuPhysToPciMemBus(uint64_t cpu_pa, uint32_t size, uint64_t& pci_bus_addr) const {
    if (!RangeFitsLow32(cpu_pa, size)) return false;
    if (!OutboundGloballyEnabled() || ((atucmd_ & kAtucmdMemorySpaceEnable) == 0) || !BusMasterEnabled())
        return false;

    const uint32_t section = static_cast<uint32_t>((cpu_pa >> 32) & 0xFu);
    for (uint32_t i = 0; i < kMemoryWindowCount; ++i) {
        const auto& w = oum_[i];
        if (!OutboundMemoryWindowEnabled(i)) continue;
        if ((w.bar & kOutboundWindowSectionMask) != section) continue;
        pci_bus_addr = (static_cast<uint64_t>(w.wtvr) << 32) | static_cast<uint32_t>(cpu_pa);
        return true;
    }
    return false;
}

void Iop13xxAtuState::SaveCoreState(StateWriter& w) const {
    w.Write(atucmd_);
    w.Write(atusr_);
    w.Write(atucr_);
    w.Write(atuisr_);
    w.Write(atuimr_);
}

void Iop13xxAtuState::RestoreCoreState(StateReader& r) {
    r.Read(atucmd_);
    r.Read(atusr_);
    r.Read(atucr_);
    r.Read(atuisr_);
    r.Read(atuimr_);
}

void Iop13xxAtuState::SaveOutboundState(StateWriter& w) const {
    w.Write(oiobar_);
    w.Write(oiowtvr_);
    for (const auto& win : oum_) {
        w.Write(win.bar);
        w.Write(win.wtvr);
    }
}

void Iop13xxAtuState::RestoreOutboundState(StateReader& r) {
    r.Read(oiobar_);
    r.Read(oiowtvr_);
    for (auto& win : oum_) {
        r.Read(win.bar);
        r.Read(win.wtvr);
    }
}
