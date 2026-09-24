#include "intel_command_set_flash.h"

#include "../core/cerf_emulator.h"
#include "../cpu/emulated_memory.h"
#include "peripheral_dispatcher.h"
#include "../state/state_stream.h"

#include <cstring>

void IntelCommandSetFlash::OnReady() {
    (void)emu_.Get<EmulatedMemory>().Translate(MmioBase());
    block_locked_.assign(NumBlocks(), 0u);
    emu_.Get<PeripheralDispatcher>().Register(this);
}

uint8_t* IntelCommandSetFlash::Host(uint32_t addr) {
    return emu_.Get<EmulatedMemory>().TryTranslate(addr);
}

void IntelCommandSetFlash::SaveAndWrite(uint32_t addr, uint8_t v) {
    uint8_t* p = Host(addr);
    if (!p) return;
    shadow_.push_back({addr, *p});
    *p = v;
}

void IntelCommandSetFlash::SaveAndWriteWord(uint32_t addr, uint32_t word) {
    for (uint32_t i = 0; i < 4u; ++i)
        SaveAndWrite(addr + i, uint8_t(word >> (8u * i)));
}

void IntelCommandSetFlash::EmitLaneByte(uint32_t addr, uint8_t v) {
    const uint32_t dw = DeviceWidth();
    for (uint32_t c = 0; c < Parallel(); ++c) {
        SaveAndWrite(addr + c * dw, v);
        for (uint32_t j = 1; j < dw; ++j) SaveAndWrite(addr + c * dw + j, 0);
    }
}

void IntelCommandSetFlash::RestoreArray() {
    for (auto it = shadow_.rbegin(); it != shadow_.rend(); ++it)
        if (uint8_t* p = Host(it->first)) *p = it->second;
    shadow_.clear();
}

void IntelCommandSetFlash::PresentStatus(uint32_t addr, uint8_t sr) {
    RestoreArray();
    EmitLaneByte(addr, sr);
}

uint32_t IntelCommandSetFlash::BlockIndexChecked(uint32_t addr) {
    const uint32_t i = BlockIndex(addr);
    if (i >= block_locked_.size())
        HaltUnsupportedAccess("flash block index out of range", addr, 0);
    return i;
}

/* MMCRestore.exe sub_130E8 reads the manufacturer at a data-block base
   0x1FFA0000; block lock bit at block_base + kLockReadOffset (datasheet Table 5). */
void IntelCommandSetFlash::PresentIdentifier(uint32_t addr) {
    RestoreArray();
    const uint32_t bw = BusBytes();
    EmitLaneByte(MmioBase(),      uint8_t(Manufacturer() & 0xFFu));
    EmitLaneByte(MmioBase() + bw, uint8_t(Device()       & 0xFFu));
    const uint32_t qbase = BlockBase(BlockIndex(addr));
    if (qbase != MmioBase()) {
        EmitLaneByte(qbase,      uint8_t(Manufacturer() & 0xFFu));
        EmitLaneByte(qbase + bw, uint8_t(Device()       & 0xFFu));
    }
    const uint32_t n = NumBlocks();
    for (uint32_t i = 0; i < n; ++i)
        EmitLaneByte(BlockBase(i) + kLockReadOffset, uint8_t(block_locked_[i] & 0x01u));
}

void IntelCommandSetFlash::PresentCfi() {
    const uint8_t* cfi = CfiTable();
    const uint32_t n   = CfiCount();
    if (!cfi || n == 0u) HaltUnsupportedAccess("flash CFI query", MmioBase(), 0x98);
    RestoreArray();
    const uint32_t bw  = BusBytes();
    const uint32_t win = MmioBase() + kCfiFirst * bw;
    for (uint32_t i = 0; i < n; ++i) EmitLaneByte(win + i * bw, cfi[i]);
}

bool IntelCommandSetFlash::ProgramInto(uint32_t addr, uint32_t value, uint32_t width) {
    if (block_locked_[BlockIndexChecked(addr)]) return false;   /* datasheet p20: locked block aborts */
    if (uint8_t* h = Host(addr))
        for (uint32_t i = 0; i < width; ++i) h[i] &= uint8_t(value >> (8u * i));
    return true;
}

void IntelCommandSetFlash::CommitProgram(uint32_t addr, uint32_t value, uint32_t width) {
    RestoreArray();
    if (!ProgramInto(addr, value, width))
        PresentStatus(addr, kSrReady | kSrProgErr | kSrLockAbort);
    else
        PresentStatus(addr);
}

void IntelCommandSetFlash::EraseBlock(uint32_t addr) {
    const uint32_t blk   = EraseBlockBytes();
    const uint32_t bbase = addr & ~(blk - 1u);
    if (uint8_t* h = Host(bbase)) std::memset(h, 0xFF, blk);
}

void IntelCommandSetFlash::Command(uint32_t addr, uint32_t value, uint32_t width) {
    switch (mode_) {
    case Mode::kProgramSetup:
        CommitProgram(addr, value, width);
        mode_ = Mode::kArray;
        return;
    case Mode::kEraseSetup:
        if ((value & 0xFFu) == 0xD0u) {
            if (block_locked_[BlockIndexChecked(addr)])
                PresentStatus(addr, kSrReady | kSrEraseErr | kSrLockAbort);
            else { EraseBlock(addr); PresentStatus(addr); }
        }
        mode_ = Mode::kArray;
        return;
    case Mode::kLockSetup: {
        const uint32_t cmd = value & 0xFFu;
        if (cmd == 0x01u) {                        /* Set Block Lock-Bit (datasheet Table 4) */
            block_locked_[BlockIndexChecked(addr)] = 1u;
            PresentStatus(addr);
        } else if (cmd == 0xD0u) {                 /* Clear Block Lock-Bits: clears ALL (note 15) */
            block_locked_.assign(block_locked_.size(), 0u);
            PresentStatus(addr);
        } else {
            RestoreArray();
        }
        mode_ = Mode::kArray;
        return;
    }
    case Mode::kWriteBufCount:                      /* MMCRestore.exe sub_131F8 writes 0x0F = 16 words */
        buf_remaining_ = (value & 0xFFu) + 1u;
        RestoreArray();
        mode_ = Mode::kWriteBufData;
        return;
    case Mode::kWriteBufData:
        if (!ProgramInto(addr, value, width))
            HaltUnsupportedAccess("flash write-buffer to locked block", addr, value);
        if (--buf_remaining_ == 0u) mode_ = Mode::kWriteBufConfirm;
        return;
    case Mode::kWriteBufConfirm:
        if ((value & 0xFFu) == 0xD0u) { PresentStatus(addr); mode_ = Mode::kArray; }
        else HaltUnsupportedAccess("flash write-buffer confirm", addr, value);
        return;
    case Mode::kArray:
        break;
    }

    const uint8_t cmd = DecodeCommand(value, width);
    if (!CommandEnabled(cmd)) HaltUnsupportedAccess("flash command", addr, value);
    switch (cmd) {
        case 0xFF: RestoreArray();               break;
        case 0x90: PresentIdentifier(addr);      break;
        case 0x98: PresentCfi();                 break;
        case 0x70: PresentStatus(addr);          break;
        case 0x50:                               break;
        case 0x40:
        case 0x10: mode_ = Mode::kProgramSetup;  break;
        case 0x20: mode_ = Mode::kEraseSetup;    break;
        case 0xE8: mode_ = Mode::kWriteBufCount;          /* MMCRestore.exe sub_131F8 */
                   PresentStatus(addr);          break;
        case 0x60: mode_ = Mode::kLockSetup;
                   PresentStatus(addr);          break;
        case 0xB0:
        case 0xD0:                               break;
        default:
            HaltUnsupportedAccess("flash command", addr, value);
    }
}

uint8_t  IntelCommandSetFlash::ReadByte(uint32_t addr) { return emu_.Get<EmulatedMemory>().ReadByte(addr); }
uint16_t IntelCommandSetFlash::ReadHalf(uint32_t addr) { return emu_.Get<EmulatedMemory>().ReadHalf(addr); }
uint32_t IntelCommandSetFlash::ReadWord(uint32_t addr) { return emu_.Get<EmulatedMemory>().ReadWord(addr); }
void     IntelCommandSetFlash::WriteByte(uint32_t addr, uint8_t  v) { Command(addr, v, 1); }
void     IntelCommandSetFlash::WriteHalf(uint32_t addr, uint16_t v) { Command(addr, v, 2); }
void     IntelCommandSetFlash::WriteWord(uint32_t addr, uint32_t v) { Command(addr, v, 4); }

uint8_t IntelCommandSetFlash::DecodeCommand(uint32_t value, uint32_t /*width*/) {
    return uint8_t(value & 0xFFu);
}

void IntelCommandSetFlash::SaveState(StateWriter& w) {
    w.Write("mode", mode_);
    w.Write("buf_remaining", buf_remaining_);
    w.Write<uint64_t>("shadow_count", shadow_.size());
    for (const auto& pr : shadow_) {
        w.Write("shadow_address", pr.first);
        w.Write("shadow_original_byte", pr.second);
    }
    w.WriteBytes("block_locked", block_locked_.data(), block_locked_.size());
}

void IntelCommandSetFlash::RestoreState(StateReader& r) {
    r.Read("mode", mode_);
    r.Read("buf_remaining", buf_remaining_);
    uint64_t n = 0; r.Read("shadow_count", n);
    shadow_.clear();
    for (uint64_t i = 0; i < n; ++i) {
        uint32_t a = 0; uint8_t b = 0;
        r.Read("shadow_address", a); r.Read("shadow_original_byte", b);
        shadow_.push_back({a, b});
    }
    r.ReadBytes("block_locked", block_locked_.data(), block_locked_.size());
}
