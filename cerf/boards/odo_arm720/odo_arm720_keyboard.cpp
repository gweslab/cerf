#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_detector.h"
#include "../../host/keyboard_input.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../socs/irq_controller.h"
#include "odo_arm720_board_intc.h"

#include <cstdint>
#include <mutex>

namespace {

/* Delivering scancodes while KB_CLK_EN=0 breaks KeybdPowerOff
   (KEYBDPDD.CPP:182 writes CSR=0 to gate the receiver). */

constexpr uint32_t kKeyboardPaBase    = 0x1000C000u;
constexpr uint32_t kKeyboardSize      = 0x08u;       /* CSR + ISR */

constexpr uint32_t kSlotKbCsr         = 0x00u;
constexpr uint32_t kSlotKbIsr         = 0x04u;

/* From P2.H lines 323-332. */
constexpr uint16_t kKbRdrf            = 0x0001u;
constexpr uint16_t kKbClkEn           = 0x8000u;

/* P2.H:320-332 — masks must stay disjoint or kernel R/W of control
   bits clobbers the in-flight scancode in CSR low 8 bits. */
constexpr uint16_t kKbCsrReadOnlyMask = 0x07FFu;
constexpr uint16_t kKbCsrRwMask       = static_cast<uint16_t>(
                                          ~kKbCsrReadOnlyMask & 0xFFFFu);

/* PS/2 Set 2 protocol prefixes. */
constexpr uint8_t  kPs2ExtendedPrefix = 0xE0u;
constexpr uint8_t  kPs2KeyUpPrefix    = 0xF0u;

/* Standard PS/2 Set 2 — kernel ScanCodeToVKeyEx (SCTOVK.CPP) is
   the reverse map; deviating from Set 2 shuffles all keys. */
struct ScancodeEntry { uint8_t scancode; bool extended; };

constexpr ScancodeEntry MakePlain(uint8_t sc) { return { sc, false }; }
constexpr ScancodeEntry MakeExt  (uint8_t sc) { return { sc, true  }; }
constexpr ScancodeEntry MakeNone() { return { 0, false }; }

constexpr ScancodeEntry kVkToPs2Set2[256] = {
    /* 0x00..0x07 */ MakeNone(), MakeNone(), MakeNone(), MakeNone(),
                     MakeNone(), MakeNone(), MakeNone(), MakeNone(),
    /* 0x08 VK_BACK    */ MakePlain(0x66),
    /* 0x09 VK_TAB     */ MakePlain(0x0D),
    /* 0x0A..0x0C */ MakeNone(), MakeNone(), MakeNone(),
    /* 0x0D VK_RETURN  */ MakePlain(0x5A),
    /* 0x0E..0x0F */ MakeNone(), MakeNone(),
    /* 0x10 VK_SHIFT   */ MakePlain(0x12),    /* L-shift; R-shift is 0x59 ext */
    /* 0x11 VK_CONTROL */ MakePlain(0x14),    /* L-ctrl; R-ctrl is ext 0x14 */
    /* 0x12 VK_MENU    */ MakePlain(0x11),    /* L-alt; R-alt is ext 0x11 */
    /* 0x13..0x1A */ MakeNone(), MakeNone(), MakeNone(), MakeNone(),
                     MakeNone(), MakeNone(), MakeNone(), MakeNone(),
    /* 0x1B VK_ESCAPE  */ MakePlain(0x76),
    /* 0x1C..0x1F */ MakeNone(), MakeNone(), MakeNone(), MakeNone(),
    /* 0x20 VK_SPACE   */ MakePlain(0x29),
    /* 0x21 VK_PRIOR (PageUp)   */ MakeExt(0x7D),
    /* 0x22 VK_NEXT  (PageDown) */ MakeExt(0x7A),
    /* 0x23 VK_END    */ MakeExt(0x69),
    /* 0x24 VK_HOME   */ MakeExt(0x6C),
    /* 0x25 VK_LEFT   */ MakeExt(0x6B),
    /* 0x26 VK_UP     */ MakeExt(0x75),
    /* 0x27 VK_RIGHT  */ MakeExt(0x74),
    /* 0x28 VK_DOWN   */ MakeExt(0x72),
    /* 0x29..0x2C */ MakeNone(), MakeNone(), MakeNone(), MakeNone(),
    /* 0x2D VK_INSERT */ MakeExt(0x70),
    /* 0x2E VK_DELETE */ MakeExt(0x71),
    /* 0x2F */ MakeNone(),
    /* 0x30..0x39 '0'..'9' */
    MakePlain(0x45), MakePlain(0x16), MakePlain(0x1E), MakePlain(0x26),
    MakePlain(0x25), MakePlain(0x2E), MakePlain(0x36), MakePlain(0x3D),
    MakePlain(0x3E), MakePlain(0x46),
    /* 0x3A..0x40 */ MakeNone(), MakeNone(), MakeNone(), MakeNone(),
                     MakeNone(), MakeNone(), MakeNone(),
    /* 0x41..0x5A 'A'..'Z' */
    MakePlain(0x1C), MakePlain(0x32), MakePlain(0x21), MakePlain(0x23),
    MakePlain(0x24), MakePlain(0x2B), MakePlain(0x34), MakePlain(0x33),
    MakePlain(0x43), MakePlain(0x3B), MakePlain(0x42), MakePlain(0x4B),
    MakePlain(0x3A), MakePlain(0x31), MakePlain(0x44), MakePlain(0x4D),
    MakePlain(0x15), MakePlain(0x2D), MakePlain(0x1B), MakePlain(0x2C),
    MakePlain(0x3C), MakePlain(0x2A), MakePlain(0x1D), MakePlain(0x22),
    MakePlain(0x35), MakePlain(0x1A),
    /* 0x5B..0x6F */ MakeNone(), MakeNone(), MakeNone(), MakeNone(),
                     MakeNone(), MakeNone(), MakeNone(), MakeNone(),
                     MakeNone(), MakeNone(), MakeNone(), MakeNone(),
                     MakeNone(), MakeNone(), MakeNone(), MakeNone(),
                     MakeNone(), MakeNone(), MakeNone(), MakeNone(),
                     MakeNone(),
    /* 0x70..0x7B F1..F12 */
    MakePlain(0x05), MakePlain(0x06), MakePlain(0x04), MakePlain(0x0C),
    MakePlain(0x03), MakePlain(0x0B), MakePlain(0x83), MakePlain(0x0A),
    MakePlain(0x01), MakePlain(0x09), MakePlain(0x78), MakePlain(0x07),
    /* 0x7C..0x8B */
    MakeNone(), MakeNone(), MakeNone(), MakeNone(),
    MakeNone(), MakeNone(), MakeNone(), MakeNone(),
    MakeNone(), MakeNone(), MakeNone(), MakeNone(),
    MakeNone(), MakeNone(), MakeNone(), MakeNone(),
    /* 0x8C..0x9F */
    MakeNone(), MakeNone(), MakeNone(), MakeNone(),
    MakeNone(), MakeNone(), MakeNone(), MakeNone(),
    MakeNone(), MakeNone(), MakeNone(), MakeNone(),
    MakeNone(), MakeNone(), MakeNone(), MakeNone(),
    MakeNone(), MakeNone(), MakeNone(), MakeNone(),
    /* 0xA0..0xFF */
    MakeNone(), MakeNone(), MakeNone(), MakeNone(),
    MakeNone(), MakeNone(), MakeNone(), MakeNone(),
    MakeNone(), MakeNone(), MakeNone(), MakeNone(),
    MakeNone(), MakeNone(), MakeNone(), MakeNone(),
    MakeNone(), MakeNone(), MakeNone(), MakeNone(),
    MakeNone(), MakeNone(), MakeNone(), MakeNone(),
    MakeNone(), MakeNone(), MakeNone(), MakeNone(),
    MakeNone(), MakeNone(), MakeNone(), MakeNone(),
    MakeNone(), MakeNone(), MakeNone(), MakeNone(),
    MakeNone(), MakeNone(), MakeNone(), MakeNone(),
    MakeNone(), MakeNone(), MakeNone(), MakeNone(),
    MakeNone(), MakeNone(), MakeNone(), MakeNone(),
    MakeNone(), MakeNone(), MakeNone(), MakeNone(),
    MakeNone(), MakeNone(), MakeNone(), MakeNone(),
    MakeNone(), MakeNone(), MakeNone(), MakeNone(),
    MakeNone(), MakeNone(), MakeNone(), MakeNone(),
    MakeNone(), MakeNone(), MakeNone(), MakeNone(),
    MakeNone(), MakeNone(), MakeNone(), MakeNone(),
    MakeNone(), MakeNone(), MakeNone(), MakeNone(),
    MakeNone(), MakeNone(), MakeNone(), MakeNone(),
    MakeNone(), MakeNone(), MakeNone(), MakeNone(),
    MakeNone(), MakeNone(), MakeNone(), MakeNone(),
    MakeNone(), MakeNone(),
};

class OdoArm720Keyboard : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::OdoArm720;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kKeyboardPaBase; }
    uint32_t MmioSize() const override { return kKeyboardSize; }

    uint16_t ReadHalf (uint32_t addr) override;
    void     WriteHalf(uint32_t addr, uint16_t value) override;

    void OnHostKey(uint8_t vk, bool key_up);

private:
    void PushByteLocked(uint8_t byte);

    /* Caller MUST AssertKeybIrq outside state_mutex_ if true is
       returned — board INTC has its own mutex; nested lock would
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
                        "KB_RDRF has a documented W1C semantic per "
                        "P2.H + KEYBDPDD.CPP. Halt rather than guess "
                        "behavior for other bits.\n", value);
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
    const ScancodeEntry& ent = kVkToPs2Set2[vk];
    if (ent.scancode == 0) return;

    bool assert_after = false;
    {
        std::lock_guard<std::mutex> lk(state_mutex_);
        if ((kb_csr_ & kKbClkEn) == 0) return;

        if (ent.extended) PushByteLocked(kPs2ExtendedPrefix);
        if (key_up)       PushByteLocked(kPs2KeyUpPrefix);
        PushByteLocked(ent.scancode);

        if ((kb_isr_ & kKbRdrf) == 0) {
            assert_after = DeliverNextLocked();
        }
    }
    if (assert_after) AssertKeybIrq();
}

void OdoArm720Keyboard::PushByteLocked(uint8_t byte) {
    const int next_head = (fifo_head_ + 1) % kFifoLen;
    if (next_head == fifo_tail_) {
        /* Halting on overflow would crash on burst typing —
           mirror PS/2 hardware behavior: lose oldest byte. */
        fifo_tail_ = (fifo_tail_ + 1) % kFifoLen;
        LOG(Caution, "Odo KB: FIFO overflow — dropping oldest byte "
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
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::OdoArm720;
    }

    void OnHostKey(uint8_t vk, bool key_up) override {
        emu_.Get<OdoArm720Keyboard>().OnHostKey(vk, key_up);
    }
};

}  /* namespace */

REGISTER_SERVICE(OdoArm720Keyboard);
REGISTER_SERVICE_AS(OdoArm720KeyboardInput, KeyboardInput);
