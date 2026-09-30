#include "sa1111_intc.h"
#include "sa1111_sbi.h"
#include "sa1111_system_controller.h"
#include "sa1111_unit.h"

#include "../pcmcia/pcmcia_slot.h"
#include "../pcmcia/pcmcia_space_router.h"

#include "../../boards/board_context.h"
#include "../../boards/jornada720/jornada_720_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
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
constexpr uint32_t kPccrS0Flt = 1u << 2;

/* SA-1111 Developer's Manual §12.6.2 (printed 12-14): PCCR bits 7:0; §12.6.3 (printed
   12-15): PCSSR bits 1:0; Table 3-3 note 1: "All reserved bits are read back as zero." */
constexpr uint32_t kPccrDefined  = 0xFFu;
constexpr uint32_t kPcssrDefined = 0x3u;

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

class Sa1111Pcmcia : public Sa1111Unit, public PcmciaSlotHost {
public:
    explicit Sa1111Pcmcia(CerfEmulator& emu)
        : Sa1111Unit(emu),
          slot0_(emu, *this, L"PC Card slot"),
          slot1_(emu, *this, L"CF slot"),
          slots_{ &slot0_, &slot1_ } {}

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::Jornada720;
    }

    void OnShutdown() override {
        slot0_.OnShutdown();
        slot1_.OnShutdown();
    }

    uint32_t MmioBase() const override { return 0x40001800u; }
    uint32_t MmioSize() const override { return 0x00000010u; }

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
    void PostRestore() override { UpdateResetSignals(true); }

    void OnCardDetectChanged(PcmciaSlot& slot) override { DriveCardDetect(slot); }

    /* Table 12-3 (printed 12-8) S0_nCE: "If PCCR<2> = 1 Then {if it is in sleep mode, {if
       PCSSR<0> =0, This signal is tri-stated, elseif This signal is forced to high.} ...}
       Else S0_nCE is tri-stated." */
    void OnCardAccess(PcmciaSlot& slot) override {
        const int n = SocketOf(slot);
        uint32_t pccr = 0u;
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            pccr = pccr_;
        }
        if (!ChipHeld() && (pccr & (kPccrS0Flt << n)) != 0u && !sbi_->SleepRequested()) return;
        emu_.Get<Fatal>().Die("Sa1111Pcmcia: card access on socket %d with PCCR 0x%02X (FLT "
                              "clear), the SA-1111 held in reset, or SKCR Sleep set is not "
                              "modelled", n, pccr);
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

protected:
    void OnUnitReady() override {
        slot0_.GateCardAccess();
        slot1_.GateCardAccess();
        emu_.Get<PcmciaSpaceRouter>().ProvideSockets(slots_[0], slots_[1]);
        auto& widgets = emu_.Get<HostWidgetRegistry>();
        widgets.Register(slots_[0]);
        widgets.Register(slots_[1]);
        sbi_ = &emu_.Get<Sa1111Sbi>();
        emu_.Get<Sa1111SystemController>().RegisterClockListener(
            [this] { UpdateResetSignals(false); });
    }

    uint32_t UnitReadWord(uint32_t addr) override {
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

    void UnitWriteWord(uint32_t addr, uint32_t value) override {
        switch (addr - MmioBase()) {
            case kOffPccr:  WritePccr(value); return;
            case kOffPcssr: {
                {
                    std::lock_guard<std::mutex> lk(state_mutex_);
                    pcssr_ = value & kPcssrDefined;
                }
                UpdateResetSignals(false);
                return;
            }
        }
        HaltUnsupportedAccess("WriteWord", addr, value);
    }

    /* SA-1111 Developer's Manual §12.2.3: the socket reset signals "are asserted when the
       SA-1111 is in reset, or the relevant bit in the Control Register is set". */
    void OnChipReset(bool held) override {
        if (held) {
            {
                std::lock_guard<std::mutex> lk(state_mutex_);
                pccr_  = 0u;
                pcssr_ = 0u;
            }
            DriveCardDetect(*slots_[0]);
            DriveCardDetect(*slots_[1]);
        }
        UpdateResetSignals(false);
    }

private:
    int SocketOf(const PcmciaSlot& slot) const {
        return &slot == slots_[0] ? 0 : 1;
    }

    /* Table 12-1 (printed 12-5) S0_CDVALID: "1 = Card not fully inserted"; Table 12-4 (printed
       12-12): "The S1_CDVALID is used as an interrupt source". */
    void DriveCardDetect(const PcmciaSlot& slot) {
        emu_.Get<Sa1111Intc>().SetSourceLevel(SocketOf(slot) == 0 ? kIntS0CdValid : kIntS1CdValid,
                                              !slot.HasCard());
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
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            pccr_ = value & kPccrDefined;
        }
        UpdateResetSignals(false);
    }

    /* Table 12-3 (printed 12-7) S0_RESET: "This signal needs a weak pull-up on board. The
       signal is active high"; "If PCCR<2> = 1 then {if in sleep mode, {if PCSSR<0> =0, This
       signal is tri-stated, elseif This signal is forced to low.} else S0_RESET = PCCR<0>}". */
    bool ResetAssertedLocked(int n) const {
        if (ChipHeld()) return true;
        if ((pccr_ & (kPccrS0Flt << n)) == 0u) return true;
        if (sbi_->SleepRequested()) return (pcssr_ & (1u << n)) == 0u;
        return (pccr_ & (kPccrS0Rst << n)) != 0u;
    }

    void UpdateResetSignals(bool quiet) {
        bool released[2] = {};
        {
            std::lock_guard<std::mutex> lk(state_mutex_);
            for (int n = 0; n < 2; ++n) {
                const bool asserted = ResetAssertedLocked(n);
                released[n]         = reset_asserted_[n] && !asserted;
                reset_asserted_[n]  = asserted;
            }
        }
        if (quiet) return;
        for (int n = 0; n < 2; ++n) {
            if (released[n]) slots_[n]->ResetCard();
        }
    }

    PcmciaSlot  slot0_;
    PcmciaSlot  slot1_;
    PcmciaSlot* slots_[2];

    const Sa1111Sbi* sbi_ = nullptr;

    std::mutex state_mutex_;
    uint32_t   pccr_  = 0u;
    uint32_t   pcssr_ = 0u;
    bool       irq_asserted_[2]   = {};
    bool       reset_asserted_[2] = {true, true};
};

}  /* namespace */

REGISTER_SERVICE(Sa1111Pcmcia);
