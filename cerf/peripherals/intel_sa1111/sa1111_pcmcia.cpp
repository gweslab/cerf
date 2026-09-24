#include "sa1111_intc.h"

#include "../peripheral_base.h"
#include "../peripheral_dispatcher.h"
#include "../pcmcia/pcmcia_slot.h"
#include "../pcmcia/pcmcia_space_router.h"

#include "../../boards/board_context.h"
#include "../../boards/jornada720/jornada_720_id.h"
#include "../../core/cerf_emulator.h"
#include "../../host/host_widget_registry.h"
#include "../../state/state_stream.h"

#include <mutex>

namespace {

/* SA-1111 PCMCIA interface (Developer's Manual §12.6, base 0x40001800):
   PCCR +0x00 control, PCSSR +0x04 sleep state, PCSR +0x08 read-only
   status. */
constexpr uint32_t kOffPccr  = 0x00u;
constexpr uint32_t kOffPcssr = 0x04u;
constexpr uint32_t kOffPcsr  = 0x08u;

/* PCCR bits (§12.6.2). */
constexpr uint32_t kPccrS0Rst = 1u << 0;
constexpr uint32_t kPccrS1Rst = 1u << 1;

/* PCSR bits (§12.6.1). */
constexpr uint32_t kPcsrS0Ready    = 1u << 0;
constexpr uint32_t kPcsrS1Ready    = 1u << 1;
constexpr uint32_t kPcsrS0CdInvalid = 1u << 2;   /* 0 = card present */
constexpr uint32_t kPcsrS1CdInvalid = 1u << 3;
constexpr uint32_t kPcsrS0Vs1 = 1u << 4;
constexpr uint32_t kPcsrS0Vs2 = 1u << 5;
constexpr uint32_t kPcsrS1Vs1 = 1u << 6;
constexpr uint32_t kPcsrS1Vs2 = 1u << 7;
constexpr uint32_t kPcsrS0Bvd1 = 1u << 10;
constexpr uint32_t kPcsrS0Bvd2 = 1u << 11;
constexpr uint32_t kPcsrS1Bvd1 = 1u << 12;
constexpr uint32_t kPcsrS1Bvd2 = 1u << 13;

/* SA-1111 interrupt sources (Developer's Manual Table 11-1): 49/50 =
   S0/S1 READY_nIREQ, 51/52 = S0/S1 CD valid change. */
constexpr uint8_t kIntS0Ready   = 49u;
constexpr uint8_t kIntS1Ready   = 50u;
constexpr uint8_t kIntS0CdValid = 51u;
constexpr uint8_t kIntS1CdValid = 52u;

class Sa1111Pcmcia : public Peripheral, public PcmciaSlotHost {
public:
    explicit Sa1111Pcmcia(CerfEmulator& emu)
        : Peripheral(emu),
          slot0_(emu, *this, L"PC Card slot"),
          slot1_(emu, *this, L"CF slot"),
          slots_{ &slot0_, &slot1_ } {}

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::Jornada720;
    }

    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
        emu_.Get<PcmciaSpaceRouter>().ProvideSockets(slots_[0], slots_[1]);
        auto& widgets = emu_.Get<HostWidgetRegistry>();
        widgets.Register(slots_[0]);
        widgets.Register(slots_[1]);
    }

    void OnShutdown() override {
        slot0_.OnShutdown();
        slot1_.OnShutdown();
    }

    uint32_t MmioBase() const override { return 0x40001800u; }
    uint32_t MmioSize() const override { return 0x00000010u; }

    uint32_t ReadWord(uint32_t addr) override {
        switch (addr - MmioBase()) {
            case kOffPccr:  {
                std::lock_guard<std::mutex> lk(state_mutex_);
                return pccr_;
            }
            case kOffPcssr: {
                std::lock_guard<std::mutex> lk(state_mutex_);
                return pcssr_;
            }
            case kOffPcsr:  return ComputePcsr();
        }
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        switch (addr - MmioBase()) {
            case kOffPccr:  WritePccr(value); return;
            case kOffPcssr: {
                std::lock_guard<std::mutex> lk(state_mutex_);
                pcssr_ = value;
                return;
            }
        }
        HaltUnsupportedAccess("WriteWord", addr, value);
    }

    void SaveState(StateWriter& w) override {
        std::lock_guard<std::mutex> lk(state_mutex_);
        w.Write("pccr", pccr_);
        w.Write("pcssr", pcssr_);
        w.WriteBytes("irq_asserted", irq_asserted_, sizeof(irq_asserted_));
    }
    void RestoreState(StateReader& r) override {
        std::lock_guard<std::mutex> lk(state_mutex_);
        r.Read("pccr", pccr_);
        r.Read("pcssr", pcssr_);
        r.ReadBytes("irq_asserted", irq_asserted_, sizeof(irq_asserted_));
    }

    /* PcmciaSlotHost. */
    void OnCardDetectChanged(PcmciaSlot& slot) override {
        emu_.Get<Sa1111Intc>().RaiseInterrupt(
            SocketOf(slot) == 0 ? kIntS0CdValid : kIntS1CdValid);
    }
    void OnCardIrqAsserted(PcmciaSlot& slot) override {
        const int n = SocketOf(slot);
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            irq_asserted_[n] = true;
        }
        emu_.Get<Sa1111Intc>().RaiseInterrupt(n == 0 ? kIntS0Ready
                                                     : kIntS1Ready);
    }
    void OnCardIrqDeasserted(PcmciaSlot& slot) override {
        const int n = SocketOf(slot);
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            irq_asserted_[n] = false;
        }
        emu_.Get<Sa1111Intc>().LowerInterrupt(n == 0 ? kIntS0Ready
                                                     : kIntS1Ready);
    }

private:
    int SocketOf(const PcmciaSlot& slot) const {
        return &slot == slots_[0] ? 0 : 1;
    }

    uint32_t ComputePcsr() {
        bool present0, present1, powered0, powered1, irq0, irq1;
        present0 = slots_[0]->HasCard();
        present1 = slots_[1]->HasCard();
        powered0 = slots_[0]->IsPowered();
        powered1 = slots_[1]->IsPowered();
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            irq0 = irq_asserted_[0];
            irq1 = irq_asserted_[1];
        }
        /* Empty-socket pins float high: CD invalid, VS/BVD pulled up.
           READY_nIREQ reads low while the card asserts its IRQ. */
        uint32_t v = kPcsrS0Vs1 | kPcsrS0Vs2 | kPcsrS1Vs1 | kPcsrS1Vs2 |
                     kPcsrS0Bvd1 | kPcsrS0Bvd2 | kPcsrS1Bvd1 | kPcsrS1Bvd2;
        if (!present0) v |= kPcsrS0CdInvalid;
        if (!present1) v |= kPcsrS1CdInvalid;
        if (present0 && powered0 && !irq0) v |= kPcsrS0Ready;
        if (present1 && powered1 && !irq1) v |= kPcsrS1Ready;
        return v;
    }

    void WritePccr(uint32_t value) {
        uint32_t released;
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            released = pccr_ & ~value & (kPccrS0Rst | kPccrS1Rst);
            pccr_ = value;
        }
        /* RESET pin released (1 → 0) returns a powered card to its
           power-on state. */
        if (released & kPccrS0Rst) slots_[0]->ResetCard();
        if (released & kPccrS1Rst) slots_[1]->ResetCard();
    }

    PcmciaSlot  slot0_;
    PcmciaSlot  slot1_;
    PcmciaSlot* slots_[2];

    std::mutex state_mutex_;
    uint32_t   pccr_  = 0u;
    uint32_t   pcssr_ = 0u;
    bool       irq_asserted_[2] = {};
};

}  /* namespace */

REGISTER_SERVICE(Sa1111Pcmcia);
