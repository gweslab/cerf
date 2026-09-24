#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../board_context.h"
#include "nokia_lumia_800_id.h"

#include <atomic>
#include <cstdint>

namespace {

constexpr uint32_t kEbi2Cs6Base = 0x8E000000u;
constexpr uint32_t kEbi2Cs6Size = 0x00100000u;

constexpr uint32_t kRegLatch017C = 0x17Cu;
constexpr uint32_t kRegProbe01AA = 0x1AAu;
constexpr uint32_t kRegLatch01B0 = 0x1B0u;

constexpr uint8_t  kProbe01AAStub     = 0xFFu;
constexpr uint16_t kProbe01AAStubHalf = 0xFFFFu;

class NokiaLumia800Ebi2Cs6 : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetBoardId() == BoardId::NokiaLumia800;
    }

    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kEbi2Cs6Base; }
    uint32_t MmioSize() const override { return kEbi2Cs6Size; }

    uint8_t ReadByte(uint32_t addr) override {
        if (addr - MmioBase() != kRegProbe01AA) {
            HaltUnsupportedAccess("ReadByte", addr, 0);
        }
        return kProbe01AAStub;
    }

    uint16_t ReadHalf(uint32_t addr) override {
        if (addr - MmioBase() != kRegProbe01AA) {
            HaltUnsupportedAccess("ReadHalf", addr, 0);
        }
        return kProbe01AAStubHalf;
    }

    void WriteHalf(uint32_t addr, uint16_t value) override {
        const uint32_t off = addr - MmioBase();
        switch (off) {
        case kRegLatch017C: Latch(latch_017c_, off, value); break;
        case kRegLatch01B0: Latch(latch_01b0_, off, value); break;
        default:            HaltUnsupportedAccess("WriteHalf", addr, value);
        }
    }

    void SaveState(StateWriter& w) override {
        w.Write<uint16_t>("latch_017c", latch_017c_.load(std::memory_order_acquire));
        w.Write<uint16_t>("latch_01b0", latch_01b0_.load(std::memory_order_acquire));
    }

    void RestoreState(StateReader& r) override {
        uint16_t latch_017c = 0;
        uint16_t latch_01b0 = 0;
        r.Read("latch_017c", latch_017c);
        r.Read("latch_01b0", latch_01b0);
        latch_017c_.store(latch_017c, std::memory_order_release);
        latch_01b0_.store(latch_01b0, std::memory_order_release);
    }

private:
    void Latch(std::atomic<uint16_t>& reg, uint32_t off, uint16_t value) {
        reg.store(value, std::memory_order_release);
        if (++writes_ > kLogFirst) return;
        LOG(Periph, "[Ebi2Cs6] +0x%03X = 0x%04X\n", off, value);
    }

    static constexpr uint32_t kLogFirst = 16u;

    std::atomic<uint16_t> latch_017c_{0};
    std::atomic<uint16_t> latch_01b0_{0};
    uint32_t writes_ = 0;
};

}

REGISTER_SERVICE(NokiaLumia800Ebi2Cs6);
