#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "odo_id.h"
#include "../../host/keyboard_input.h"
#include "../../host/keyboard_map.h"
#include "../../host/keyboard_router.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../socs/irq_controller.h"
#include "../../state/state_stream.h"
#include "odo_arm720_board_intc.h"

#include <cstdint>
#include <mutex>

namespace {

constexpr uint32_t kKeyboardPaBase    = 0x1000C000u;
constexpr uint32_t kKeyboardSize      = 0x08u;       /* CSR + ISR */

constexpr uint32_t kSlotKbCsr         = 0x00u;
constexpr uint32_t kSlotKbIsr         = 0x04u;

constexpr uint16_t kKbRdrf            = 0x0001u;
constexpr uint16_t kKbClkEn           = 0x8000u;

constexpr uint16_t kKbCsrReadOnlyMask = 0x07FFu;
constexpr uint16_t kKbCsrRwMask       = static_cast<uint16_t>(
                                          ~kKbCsrReadOnlyMask & 0xFFFFu);

/* PS/2 Set 2 protocol prefixes. */
constexpr uint8_t  kPs2ExtendedPrefix = 0xE0u;
constexpr uint8_t  kPs2KeyUpPrefix    = 0xF0u;

class OdoArm720Keyboard : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::Odo;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kKeyboardPaBase; }
    uint32_t MmioSize() const override { return kKeyboardSize; }

    uint16_t ReadHalf (uint32_t addr) override;
    void     WriteHalf(uint32_t addr, uint16_t value) override;

    /* State image: the two registers plus the PS/2 byte FIFO and its
       ring indices. The scancode lookup table is constant data. */
    void SaveState(StateWriter& w) override {
        std::lock_guard<std::mutex> lk(state_mutex_);
        w.Write<uint16_t>("kb_csr", kb_csr_);
        w.Write<uint16_t>("kb_isr", kb_isr_);
        w.WriteBytes("scancode_fifo", scancode_fifo_, sizeof(scancode_fifo_));
        w.Write<int>("fifo_head", fifo_head_);
        w.Write<int>("fifo_tail", fifo_tail_);
    }
    void RestoreState(StateReader& r) override {
        std::lock_guard<std::mutex> lk(state_mutex_);
        r.Read("kb_csr", kb_csr_);
        r.Read("kb_isr", kb_isr_);
        r.ReadBytes("scancode_fifo", scancode_fifo_, sizeof(scancode_fifo_));
        r.Read("fifo_head", fifo_head_);
        r.Read("fifo_tail", fifo_tail_);
    }

    void OnHostKey(uint8_t vk, bool key_up);

private:
    void PushByteLocked(uint8_t byte);

    /* Caller MUST AssertKeybIrq outside state_mutex_ if true is
       returned - board INTC has its own mutex; nested lock would
       deadlock. */
    bool DeliverNextLocked();

    void AssertKeybIrq();
    void DeAssertKeybIrq();

    mutable std::mutex state_mutex_;
    uint16_t           kb_csr_ = 0;
    uint16_t           kb_isr_ = 0;

    /* PS/2 byte FIFO. 32 bytes absorbs bursts of typing. */
    static constexpr int kFifoLen = 32;
    uint8_t scancode_fifo_[kFifoLen] = {};
    int     fifo_head_ = 0;
    int     fifo_tail_ = 0;
};

uint16_t OdoArm720Keyboard::ReadHalf(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    uint16_t value;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        if      (off == kSlotKbCsr) value = kb_csr_;
        else if (off == kSlotKbIsr) value = kb_isr_;
        else                        HaltUnsupportedAccess("ReadHalf", addr, 0);
    }
#if CERF_DEV_MODE
    LOG(SocIoport, "Odo KB read  +0x%02X -> 0x%04X\n", off, value);
#endif
    return value;
}

void OdoArm720Keyboard::WriteHalf(uint32_t addr, uint16_t value) {
    const uint32_t off = addr - MmioBase();
#if CERF_DEV_MODE
    LOG(SocIoport, "Odo KB write +0x%02X = 0x%04X\n", off, value);
#endif
    bool assert_irq_after   = false;
    bool deassert_irq_after = false;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        if (off == kSlotKbCsr) {
            kb_csr_ = static_cast<uint16_t>(
                (kb_csr_ & kKbCsrReadOnlyMask) |
                (value   & kKbCsrRwMask));
        } else if (off == kSlotKbIsr) {
            if ((value & ~kKbRdrf) != 0) {
                LOG(Caution, "Odo KB: KB_ISR write value=0x%04X has "
                        "bits other than KB_RDRF (0x0001) set; only "
                        "KB_RDRF has a modeled W1C semantic. Halt "
                        "rather than guess behavior for other "
                        "bits.\n", value);
                CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
            }
            const bool was_set = (kb_isr_ & kKbRdrf) != 0;
            kb_isr_ &= static_cast<uint16_t>(~(value & kKbRdrf));
            if (was_set && (kb_isr_ & kKbRdrf) == 0) {
                /* Without DeAssert here, cpuIsr.keyb stays set →
                   kernel ISR re-enters on next cpuMr pulse. */
                deassert_irq_after = true;
                assert_irq_after   = DeliverNextLocked();
            }
        } else {
            HaltUnsupportedAccess("WriteHalf", addr, value);
        }
    }
    if (deassert_irq_after) DeAssertKeybIrq();
    if (assert_irq_after)   AssertKeybIrq();
}

void OdoArm720Keyboard::OnHostKey(uint8_t vk, bool key_up) {
    uint32_t code;
    if (!emu_.Get<KeyboardMap>().BaseDeviceCode(vk, code)) return;
    const uint8_t sc       = static_cast<uint8_t>(code);
    const bool    extended = (code & 0x100u) != 0;

    bool assert_after = false;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        if ((kb_csr_ & kKbClkEn) == 0) return;

        if (extended) PushByteLocked(kPs2ExtendedPrefix);
        if (key_up)   PushByteLocked(kPs2KeyUpPrefix);
        PushByteLocked(sc);

        if ((kb_isr_ & kKbRdrf) == 0) {
            assert_after = DeliverNextLocked();
        }
    }
    if (assert_after) AssertKeybIrq();
}

void OdoArm720Keyboard::PushByteLocked(uint8_t byte) {
    const int next_head = (fifo_head_ + 1) % kFifoLen;
    if (next_head == fifo_tail_) {
        /* Halting on overflow would crash on burst typing -
           mirror PS/2 hardware behavior: lose oldest byte. */
        fifo_tail_ = (fifo_tail_ + 1) % kFifoLen;
        LOG(Caution, "Odo KB: FIFO overflow - dropping oldest byte "
                "to make room. Burst typing rate exceeds kernel ISR "
                "drain rate; consider increasing kFifoLen.\n");
    }
    scancode_fifo_[fifo_head_] = byte;
    fifo_head_ = next_head;
}

bool OdoArm720Keyboard::DeliverNextLocked() {
    if (fifo_head_ == fifo_tail_) return false;
    if ((kb_isr_ & kKbRdrf) != 0) return false;

    const uint8_t byte = scancode_fifo_[fifo_tail_];
    fifo_tail_ = (fifo_tail_ + 1) % kFifoLen;

    kb_csr_ = static_cast<uint16_t>(
        (kb_csr_ & kKbCsrRwMask) | byte);
    kb_isr_ |= kKbRdrf;
    return true;
}

void OdoArm720Keyboard::AssertKeybIrq() {
    emu_.Get<IrqController>().AssertIrq(kSourceKeybIntr);
}

void OdoArm720Keyboard::DeAssertKeybIrq() {
    emu_.Get<IrqController>().DeAssertIrq(kSourceKeybIntr);
}


class OdoArm720KeyboardInput : public KeyboardInput {
public:
    using KeyboardInput::KeyboardInput;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::Odo;
    }

    void OnReady() override { emu_.Get<KeyboardRouter>().Register(this); }

    void OnHostKey(uint8_t vk, bool key_up) override {
        emu_.Get<OdoArm720Keyboard>().OnHostKey(vk, key_up);
    }
};

}  /* namespace */

REGISTER_SERVICE(OdoArm720Keyboard);
REGISTER_SERVICE(OdoArm720KeyboardInput);
