#include "amd_command_set_flash.h"

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "../cpu/emulated_memory.h"
#include "../host/host_widget_registry.h"
#include "../peripherals/peripheral_dispatcher.h"
#include "../state/state_stream.h"

#include <cstring>

namespace {
/* AMD command-set unlock/command-cycle address decode: word A10:A0 = byte 0xFFE. */
constexpr uint32_t kCmdAddrMask = 0xFFEu;
}

void AmdCommandSetFlash::OnReady() {
    (void)emu_.Get<EmulatedMemory>().Translate(MmioBase());
    emu_.Get<PeripheralDispatcher>().Register(this);
    emu_.Get<HostWidgetRegistry>().Register(this);
    LOG(Boot, "AmdCommandSetFlash: %ls at PA 0x%08X size 0x%X "
              "(EmulatedMemory-backed; FSM-write only)\n",
        WidgetName().c_str(), MmioBase(), MmioSize());
}

uint8_t  AmdCommandSetFlash::ReadByte(uint32_t addr) {
    return emu_.Get<EmulatedMemory>().ReadByte(addr);
}
uint16_t AmdCommandSetFlash::ReadHalf(uint32_t addr) {
    return emu_.Get<EmulatedMemory>().ReadHalf(addr);
}
uint32_t AmdCommandSetFlash::ReadWord(uint32_t addr) {
    return emu_.Get<EmulatedMemory>().ReadWord(addr);
}

void AmdCommandSetFlash::WriteByte(uint32_t addr, uint8_t value) {
    HaltUnsupportedAccess("WriteByte", addr, value);
}
void AmdCommandSetFlash::WriteWord(uint32_t addr, uint32_t value) {
    HaltUnsupportedAccess("WriteWord", addr, value);
}
void AmdCommandSetFlash::WriteHalf(uint32_t addr, uint16_t value) {
    MarkTx();
    DoWriteHalf(addr - MmioBase(), value);
}

void AmdCommandSetFlash::EnterAutoSelect() {
    auto& mem = emu_.Get<EmulatedMemory>();
    cached_word0_ = mem.ReadWord(MmioBase());
    mem.WriteWord(MmioBase(), AutoSelectIdent());
}
void AmdCommandSetFlash::LeaveAutoSelect() {
    emu_.Get<EmulatedMemory>().WriteWord(MmioBase(), cached_word0_);
}

void AmdCommandSetFlash::DoWriteHalf(uint32_t io_addr, uint16_t value) {
    auto& mem = emu_.Get<EmulatedMemory>();
    const uint8_t  lb = (uint8_t)(value & 0xFFu);
    const uint32_t a1 = UnlockAddr1();
    const uint32_t a2 = UnlockAddr2();

    /* Unlock cycles match on word A10:A0 (byte 0xFFE); the P177 driver re-unlocks
       per 64 KB LU at PROGRAM-TARGET+0xAAA (amdflash.c sub_83047970). S29GL256P
       002-00886 Note 5: A16+ don't-care for command cycles. */
    const uint32_t cmd_io = io_addr & kCmdAddrMask;
    const uint32_t cmd_a1 = a1      & kCmdAddrMask;
    const uint32_t cmd_a2 = a2      & kCmdAddrMask;

    switch (st_) {
    case St::Read:
        if (bypass_) {
            /* Unlock-bypass (P177 amdflash.c sub_83047970): 0xA0 then data
               programs one word; 0x90 then 0x00 exits bypass. */
            if (lb == 0xA0u) { st_ = St::BypassProgram; return; }
            if (lb == 0x90u) { st_ = St::BypassExit;    return; }
            return;
        }
        if (lb == 0xAAu && cmd_io == cmd_a1) st_ = St::Unlock1;
        return;

    case St::Unlock1:
        st_ = (lb == 0x55u && cmd_io == cmd_a2) ? St::Unlock2 : St::Read;
        return;

    case St::Unlock2:
        if (cmd_io == cmd_a1) {
            switch (lb) {
            case 0x90u: EnterAutoSelect(); st_ = St::AutoSelect; return;
            case 0xA0u: st_ = St::Program;                       return;
            case 0x80u: st_ = St::EraseSetup;                    return;
            case 0x20u: bypass_ = true; st_ = St::Read;          return;
            case 0xF0u: st_ = St::Read;                          return;
            }
        }
        st_ = St::Read;
        return;

    case St::Program:
        mem.WriteHalf(MmioBase() + io_addr, value);
        st_ = St::Read;
        return;

    case St::EraseSetup:
        st_ = (lb == 0xAAu && cmd_io == cmd_a1) ? St::EraseUnlock1 : St::Read;
        return;

    case St::EraseUnlock1:
        st_ = (lb == 0x55u && cmd_io == cmd_a2) ? St::EraseUnlock2 : St::Read;
        return;

    case St::EraseUnlock2:
        if (lb == 0x30u) {            /* sector erase confirm */
            const uint32_t sz   = SectorSize(io_addr);
            const uint32_t base = io_addr & ~(sz - 1u);
            std::memset(mem.Translate(MmioBase() + base), 0xFF, sz);
        } else if (lb == 0x10u) {     /* chip erase confirm */
            std::memset(mem.Translate(MmioBase()), 0xFF, MmioSize());
        }
        st_ = St::Read;
        return;

    case St::AutoSelect:
        if (lb == 0xF0u) { LeaveAutoSelect(); st_ = St::Read; }
        return;

    case St::BypassProgram:
        mem.WriteHalf(MmioBase() + io_addr, value);
        st_ = St::Read;               /* bypass_ stays set */
        return;

    case St::BypassExit:
        if (lb == 0x00u) bypass_ = false;
        st_ = St::Read;
        return;
    }
}

void AmdCommandSetFlash::SaveState(StateWriter& w) {
    w.Write("st", (uint8_t)st_);
    w.Write("bypass", (uint8_t)(bypass_ ? 1u : 0u));
    w.Write("cached_word0", cached_word0_);
}
void AmdCommandSetFlash::RestoreState(StateReader& r) {
    uint8_t st = 0; r.Read("st", st); st_ = (St)st;
    uint8_t byp = 0; r.Read("bypass", byp); bypass_ = (byp != 0);
    r.Read("cached_word0", cached_word0_);
}

std::vector<WidgetMenuItem> AmdCommandSetFlash::BuildMenu() {
    WidgetMenuItem hdr;
    hdr.label   = Tooltip();
    hdr.enabled = false;
    return { std::move(hdr) };
}

void AmdCommandSetFlash::DrawIcon(HDC dc, const RECT& box) const {
    DrawChipIcon(dc, box);
}
