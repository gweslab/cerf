#include "../peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "../../boards/nec_rockhopper/nec_rockhopper_id.h"
#include "../peripheral_dispatcher.h"
#include "../intel_i8042/i8042_controller.h"
#include "../../socs/vrc5477/vrc5477_intc.h"
#include "../../state/state_stream.h"

#include <cstdint>
#include <mutex>


namespace {

constexpr uint32_t kBase = 0x14000000u;   /* BSP_REG_PA_PCI_IO */
constexpr uint32_t kSize = 0x00001000u;   /* legacy ISA I/O page */

enum : uint32_t {
    kKbcData = 0x060, kKbcStatus = 0x064,
    kPic1Cmd = 0x020, kPic1Data = 0x021,   /* BSP_REG_PA_M1535_PIC1 = PCI_IO + 0x20 */
    kPic2Cmd = 0x0A0, kPic2Data = 0x0A1,   /* BSP_REG_PA_M1535_PIC2 = PCI_IO + 0xA0 */
    kElcr1   = 0x4D0, kElcr2    = 0x4D1,    /* BSP_REG_PA_M1535_EDGE1/2 */
};

constexpr uint32_t kIrqIntc      = 10;
constexpr int      kPic1CascadeLine = 2;
constexpr int      kPic1KbdLine     = 1;   /* keyboard = IRQ1 (IRQ_PIC_1) */
constexpr int      kPic2MouseLine   = 4;   /* mouse = IRQ12 -> PIC2 local line 12-8 (IRQ_PIC_12) */

/* One Intel 8259A (ICW1-4 init, OCW1 mask, OCW2 EOI, OCW3 poll P=bit2 /
   read-select RR=bit1+RIS=bit0). Edge IRRs latch on RaiseEdge; the OCW3 poll
   acks like an INTA (IRR->ISR). Exercised by SG2 OAL BSPIntrInit/BSPIntrActiveIrq. */
struct Pic8259 {
    uint8_t imr = 0;
    uint8_t irr = 0;          /* request latch (edge) + bit2 = slave output mirror */
    uint8_t isr = 0;          /* in-service */
    uint8_t icw1 = 0, icw2 = 0, icw3 = 0, icw4 = 0;
    uint8_t init_step = 0;    /* 0 = operational, 1=expect ICW2, 2=ICW3, 3=ICW4 */
    bool    icw4_needed = false;
    bool    single = false;
    bool    read_isr = false; /* OCW3 RIS: cmd-port read returns ISR vs IRR */
    bool    poll_pending = false;

    template <typename F>
    static constexpr void Visit(Pic8259& p, F& field) {
        field("imr", p.imr);
        field("irr", p.irr);
        field("isr", p.isr);
        field("icw1", p.icw1);
        field("icw2", p.icw2);
        field("icw3", p.icw3);
        field("icw4", p.icw4);
        field("init_step", p.init_step);
        field("icw4_needed", p.icw4_needed);
        field("single", p.single);
        field("read_isr", p.read_isr);
        field("poll_pending", p.poll_pending);
    }

    void WriteCmd(uint8_t v) {
        if (v & 0x10) {                       /* ICW1 */
            icw1 = v; icw4_needed = v & 0x01; single = v & 0x02;
            imr = 0; isr = 0; read_isr = false; poll_pending = false; init_step = 1;
        } else if (v & 0x08) {                /* OCW3 */
            if (v & 0x04) poll_pending = true;        /* P: next cmd-port read = poll word */
            else if (v & 0x02) read_isr = (v & 0x01); /* RR set: RIS selects IRR/ISR */
        } else {                              /* OCW2 */
            if (v & 0x20) {                   /* EOI */
                if (v & 0x40) {               /* specific EOI: clear named level */
                    isr &= static_cast<uint8_t>(~(1u << (v & 0x07)));
                } else if (isr) {             /* non-specific EOI: clear highest priority */
                    for (uint8_t b = 0; b < 8; ++b) {
                        if (isr & (1u << b)) { isr &= static_cast<uint8_t>(~(1u << b)); break; }
                    }
                }
            }
        }
    }

    void WriteData(uint8_t v) {
        switch (init_step) {
            case 1: icw2 = v; init_step = single ? (icw4_needed ? 3 : 0) : 2; break;
            case 2: icw3 = v; init_step = icw4_needed ? 3 : 0; break;
            case 3: icw4 = v; init_step = 0; break;
            default: imr = v; break;          /* OCW1 */
        }
    }

    void RaiseEdge(int line)   { irr |= static_cast<uint8_t>(1u << line); }
    void SetCascade(bool level) {
        if (level) irr |= static_cast<uint8_t>(1u << kPic1CascadeLine);
        else       irr &= static_cast<uint8_t>(~(1u << kPic1CascadeLine));
    }
    uint8_t PendingUnmasked() const { return static_cast<uint8_t>(irr & ~imr); }
    bool    Output() const { return PendingUnmasked() != 0; }

    /* OCW3 poll acknowledge: highest-priority unmasked request -> set ISR, clear
       its IRR latch (except the master cascade bit, a level mirror of the slave).
       Returns the poll word (bit7=pending, bits[2:0]=line). */
    uint8_t PollAck(bool is_master) {
        const uint8_t p = PendingUnmasked();
        if (!p) return 0;
        int b = 0;
        for (; b < 8; ++b) if (p & (1u << b)) break;
        isr |= static_cast<uint8_t>(1u << b);
        if (!(is_master && b == kPic1CascadeLine))
            irr &= static_cast<uint8_t>(~(1u << b));
        return static_cast<uint8_t>(0x80 | b);
    }

    uint8_t ReadCmd(bool is_master) {
        if (poll_pending) { poll_pending = false; return PollAck(is_master); }
        return read_isr ? isr : irr;
    }
    uint8_t ReadData() const { return imr; }
};

class AliM1535 : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::NecRockhopper;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
        auto& kbc = emu_.Get<I8042Controller>();
        kbc.SetKbdIrqSink([this] { RaiseKbdIrq(); });
        kbc.SetAuxIrqSink([this] { RaiseMouseIrq(); });
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint8_t ReadByte (uint32_t addr) override;
    void    WriteByte(uint32_t addr, uint8_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override {
        std::lock_guard<std::mutex> lk(pic_mtx_);
        RecomputeOutputLocked();
    }

private:
    /* i8042 OBF -> 8259 edge. Called from the i8042 IRQ sinks (host-input thread
       or the JIT thread on a read-pop re-raise). */
    void RaiseKbdIrq() {
        std::lock_guard<std::mutex> lk(pic_mtx_);
        pic_[0].RaiseEdge(kPic1KbdLine);
        RecomputeOutputLocked();
    }
    void RaiseMouseIrq() {
        std::lock_guard<std::mutex> lk(pic_mtx_);
        pic_[1].RaiseEdge(kPic2MouseLine);
        RecomputeOutputLocked();
    }

    /* Propagate slave->master cascade, then drive IRQ_INTC from the PIC1 output
       level. Caller holds pic_mtx_. */
    void RecomputeOutputLocked() {
        pic_[0].SetCascade(pic_[1].Output());
        auto& intc = emu_.Get<Vrc5477Intc>();
        if (pic_[0].Output()) intc.AssertSource(kIrqIntc);
        else                  intc.DeassertSource(kIrqIntc);
    }

    std::mutex pic_mtx_;
    Pic8259 pic_[2];          /* [0] = master (0x20), [1] = slave (0xA0) */
    uint8_t elcr_[2] = {0, 0};
};

uint8_t AliM1535::ReadByte(uint32_t addr) {
    const uint32_t off = addr - kBase;
    if (off == kKbcData)   return emu_.Get<I8042Controller>().ReadData();
    if (off == kKbcStatus) return emu_.Get<I8042Controller>().ReadStatus();
    std::lock_guard<std::mutex> lk(pic_mtx_);
    switch (off) {
        case kPic1Cmd:  { const uint8_t v = pic_[0].ReadCmd(true);  RecomputeOutputLocked(); return v; }
        case kPic1Data: return pic_[0].ReadData();
        case kPic2Cmd:  { const uint8_t v = pic_[1].ReadCmd(false); RecomputeOutputLocked(); return v; }
        case kPic2Data: return pic_[1].ReadData();
        case kElcr1:    return elcr_[0];
        case kElcr2:    return elcr_[1];
        default:        HaltUnsupportedAccess("ReadByte", addr, 0);
    }
}

void AliM1535::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off = addr - kBase;
    if (off == kKbcData)   { emu_.Get<I8042Controller>().WriteData(value);    return; }
    if (off == kKbcStatus) { emu_.Get<I8042Controller>().WriteCommand(value); return; }
    std::lock_guard<std::mutex> lk(pic_mtx_);
    switch (off) {
        case kPic1Cmd:  pic_[0].WriteCmd(value);  RecomputeOutputLocked(); break;
        case kPic1Data: pic_[0].WriteData(value); RecomputeOutputLocked(); break;
        case kPic2Cmd:  pic_[1].WriteCmd(value);  RecomputeOutputLocked(); break;
        case kPic2Data: pic_[1].WriteData(value); RecomputeOutputLocked(); break;
        case kElcr1:    elcr_[0] = value; break;
        case kElcr2:    elcr_[1] = value; break;
        default:        HaltUnsupportedAccess("WriteByte", addr, value);
    }
}

void AliM1535::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(pic_mtx_);
    static_assert(StateVisitCoversAllBytes<Pic8259>(
                      [](Pic8259& p, StateFieldBytes& f) { Pic8259::Visit(p, f); }),
                  "Pic8259::Visit must name or skip every field of Pic8259");
    StateWriteField field(w);
    for (Pic8259& p : pic_) Pic8259::Visit(p, field);
    w.WriteBytes("elcr", elcr_, sizeof(elcr_));
    emu_.Get<I8042Controller>().SaveState(w);   /* delegated sub-block (not auto-enumerated) */
}

void AliM1535::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(pic_mtx_);
    StateReadField field(r);
    for (Pic8259& p : pic_) Pic8259::Visit(p, field);
    r.ReadBytes("elcr", elcr_, sizeof(elcr_));
    emu_.Get<I8042Controller>().RestoreState(r);
}

}  /* namespace */

REGISTER_SERVICE(AliM1535);
