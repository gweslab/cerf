#pragma once

#include "../../peripherals/peripheral_base.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"

#include <cstdint>
#include <typeinfo>

namespace cerf_vr41xx_reg_window_detail {

constexpr uint32_t kMaxRegs = 16u;

enum class ReadKind : uint8_t {
    kFatal,
    kStored,
    kZero,
};

enum class WriteKind : uint8_t {
    kFatal,
    kStored,
    kClear,
    kDrop,
};

enum class OtherReset : uint8_t {
    kReset,
    kRetain,
};

struct Vr41xxRegSpec {
    ReadKind   read         = ReadKind::kFatal;
    WriteKind  write        = WriteKind::kFatal;
    uint16_t   wmask        = 0u;
    uint16_t   reset        = 0u;
    uint16_t   fatal_on_set = 0u;
    OtherReset other_reset  = OtherReset::kReset;
    uint16_t   undefined_on_other_reset = 0u;
};

struct Vr41xxRegWindowModel {
    uint32_t      base;
    uint32_t      size;
    uint32_t      num_regs;
    bool          word_pairs;
    Vr41xxRegSpec reg[kMaxRegs];
};

template <const std::string_view& Soc, Vr41xxRegWindowModel M>
class Vr41xxRegWindowBase : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == Soc;
    }

    void OnReady() override {
        for (uint32_t i = 0; i < M.num_regs; ++i) reg_[i] = ResetValue(i, true);
        emu_.Get<PeripheralDispatcher>().Register(this);
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind kind) {
            const bool rtc = kind == ResetLineKind::Rtc;
            for (uint32_t i = 0; i < M.num_regs; ++i) {
                if (rtc || M.reg[i].other_reset == OtherReset::kReset) reg_[i] = ResetValue(i, rtc);
                undefined_[i] = rtc ? uint16_t{0} : M.reg[i].undefined_on_other_reset;
            }
            AfterReset();
        });
    }

    uint32_t MmioBase() const override { return M.base; }
    uint32_t MmioSize() const override { return M.size; }

    uint16_t ReadHalf(uint32_t addr) override {
        const uint32_t i = RegIndex(addr, "ReadHalf", 0);
        if (undefined_[i]) {
            HaltUnsupportedAccess("ReadHalf of bits the Other-resets row leaves Undefined",
                                  addr, undefined_[i]);
        }
        switch (M.reg[i].read) {
            case ReadKind::kStored: return reg_[i];
            case ReadKind::kZero:   return 0u;
            default: HaltUnsupportedAccess("ReadHalf", addr, 0);
        }
    }

    void WriteHalf(uint32_t addr, uint16_t value) override {
        const uint32_t i = RegIndex(addr, "WriteHalf", value);
        if (value & M.reg[i].fatal_on_set) {
            HaltUnsupportedAccess("WriteHalf sets an unmodeled trigger bit", addr, value);
        }
        switch (M.reg[i].write) {
            case WriteKind::kStored:
                StoreMasked(i, value);
                return;
            case WriteKind::kClear:
                reg_[i] = static_cast<uint16_t>(reg_[i] & ~(value & M.reg[i].wmask));
                return;
            case WriteKind::kDrop:
                return;
            default: HaltUnsupportedAccess("WriteHalf", addr, value);
        }
    }

    uint32_t ReadWord(uint32_t addr) override {
        if (!M.word_pairs) HaltUnsupportedAccess("ReadWord", addr, 0);
        const uint32_t lo = PairLow(addr, "ReadWord");
        return ReadHalf(M.base + lo * 2u) |
               (static_cast<uint32_t>(ReadHalf(M.base + (lo + 1u) * 2u)) << 16);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        if (!M.word_pairs) HaltUnsupportedAccess("WriteWord", addr, value);
        PairLow(addr, "WriteWord");
        WriteHalf(addr,     static_cast<uint16_t>(value));
        WriteHalf(addr + 2, static_cast<uint16_t>(value >> 16));
    }

    uint8_t ReadByte(uint32_t addr) override { HaltUnsupportedAccess("ReadByte", addr, 0); }
    void WriteByte(uint32_t addr, uint8_t v) override { HaltUnsupportedAccess("WriteByte", addr, v); }

    void SaveState(StateWriter& w) override {
        for (uint32_t i = 0; i < M.num_regs; ++i) w.Write("reg", reg_[i]);
        for (uint32_t i = 0; i < M.num_regs; ++i) w.Write("undefined", undefined_[i]);
    }
    void RestoreState(StateReader& r) override {
        for (uint32_t i = 0; i < M.num_regs; ++i) r.Read("reg", reg_[i]);
        for (uint32_t i = 0; i < M.num_regs; ++i) r.Read("undefined", undefined_[i]);
    }

protected:
    virtual uint16_t ResetValue(uint32_t i, bool rtc) const {
        (void)rtc;
        return M.reg[i].reset;
    }
    virtual void AfterReset() {}

    uint16_t StoredReg(uint32_t i) const { return reg_[i]; }

    void ApplyStoredWrite(uint32_t offset, uint16_t value) {
        const uint32_t i = offset / 2u;
        if ((offset & 1u) || i >= M.num_regs || M.reg[i].write != WriteKind::kStored ||
            (value & ~M.reg[i].wmask) != 0u || (value & M.reg[i].fatal_on_set) != 0u) {
            emu_.Get<Fatal>().Die("%s: stored write 0x%04X at offset 0x%02X is not a "
                                  "stored-register write", typeid(*this).name(), value,
                                  offset);
        }
        StoreMasked(i, value);
    }

private:
    void StoreMasked(uint32_t i, uint16_t value) {
        reg_[i] = static_cast<uint16_t>((reg_[i] & ~M.reg[i].wmask) | (value & M.reg[i].wmask));
        undefined_[i] = static_cast<uint16_t>(undefined_[i] & ~M.reg[i].wmask);
    }

    uint32_t RegIndex(uint32_t addr, const char* what, uint32_t value) {
        const uint32_t off = addr - M.base;
        if (off >= M.num_regs * 2u || (off & 1u)) HaltUnsupportedAccess(what, addr, value);
        return off / 2u;
    }
    uint32_t PairLow(uint32_t addr, const char* what) {
        const uint32_t lo = RegIndex(addr, what, 0);
        if (lo + 1u >= M.num_regs) HaltUnsupportedAccess(what, addr, 0);
        return lo;
    }

    uint16_t reg_[kMaxRegs]       = {};
    uint16_t undefined_[kMaxRegs] = {};
};

}
