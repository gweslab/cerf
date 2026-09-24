#include "../../boards/board_context.h"
#include "msm8255_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../jit/guest_cycle_clock.h"
#include "../../peripherals/peripheral_base.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "../irq_controller.h"
#include "msm8255_adm_command_list.h"
#include "msm8255_crci_bus.h"

#include <cstdint>
#include <mutex>

namespace {

constexpr uint32_t kBase = 0xAC400800u;
constexpr uint32_t kSize = 0x00002000u;

/* Linux arch/arm/mach-msm dma.c: MSM_DMOV_CHANNEL_COUNT. */
constexpr uint32_t kChannelCount = 16u;

/* Linux arch/arm/mach-msm include mach dma.h: every channel register is
   DMOV_ADDR(off, ch) = off + (ch << 2) inside one security domain. */
constexpr uint32_t kRegCmdPtr      = 0x000u;
constexpr uint32_t kRegRslt        = 0x040u;
constexpr uint32_t kRegFlush0      = 0x080u;
constexpr uint32_t kRegStatus      = 0x200u;
constexpr uint32_t kRegRsltConf    = 0x300u;
constexpr uint32_t kRegIsr         = 0x380u;

/* Linux arch/arm/mach-msm include mach dma.h: DMOV_RSLT_VALID, _ERROR,
   _FLUSH, _DONE and _USER. */
constexpr uint32_t kRsltValid = 1u << 31;
constexpr uint32_t kRsltFlush = 1u << 2;
constexpr uint32_t kRsltDone  = 1u << 1;

/* Linux arch/arm/mach-msm include mach dma.h: DMOV_STATUS_CMD_PTR_RDY,
   DMOV_STATUS_RSLT_VALID, DMOV_STATUS_RSLT_COUNT and _CMD_COUNT. */
constexpr uint32_t kStatusCmdPtrRdy   = 1u << 0;
constexpr uint32_t kStatusRsltValid   = 1u << 1;
constexpr uint32_t kStatusRsltCountSh = 29u;

/* Linux arch/arm/mach-msm include mach dma.h: DMOV_RSLT_CONF_IRQ_EN and
   DMOV_RSLT_CONF_FORCE_FLUSH_RSLT. */
constexpr uint32_t kRsltConfIrqEn          = 1u << 0;
constexpr uint32_t kRsltConfForceFlushRslt = 1u << 1;
constexpr uint32_t kRsltConfServed = kRsltConfIrqEn | kRsltConfForceFlushRslt;

/* Linux arch/arm/mach-msm irqs-7x30.h: INT_ADM_AARM is INT_ADM_SC2. */
constexpr int kVicLine = 64 + 15;

constexpr uint32_t kRsltFifoDepth = 7u;

class Msm8255Dmov : public Peripheral, public Msm8255CrciClient {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        return emu_.Get<BoardContext>().GetSocId() == SocId::Msm8255;
    }

    void OnReady() override {
        done_ = emu_.Get<GuestCycleClock>().Add([this] { CompleteDue(); });
        ResetState();
        emu_.Get<GuestCpuReset>().RegisterResetListener(
            [this](ResetLineKind) { ResetState(); });
        emu_.Get<PeripheralDispatcher>().Register(this);
        emu_.Get<Msm8255CrciBus>().Register(this);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint32_t ReadWord(uint32_t addr) override {
        const uint32_t off = addr - kBase;
        if (off == kRegIsr) {
            std::lock_guard<std::mutex> g(lock_);
            return IsrWordLocked();
        }
        const uint32_t ch = ChannelOf(off);
        if (ch == kChannelCount) HaltUnsupportedAccess("ReadWord", addr, 0);
        const uint32_t reg = RegOf(off);
        std::lock_guard<std::mutex> g(lock_);
        if (reg == kRegStatus)   return StatusLocked(ch);
        if (reg == kRegRslt)     return PopResultLocked(ch);
        if (reg == kRegRsltConf) return chans_[ch].rslt_conf;
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }

    void WriteWord(uint32_t addr, uint32_t value) override {
        const uint32_t ch = ChannelOf(addr - kBase);
        if (ch == kChannelCount) HaltUnsupportedAccess("WriteWord", addr, value);
        const uint32_t reg = RegOf(addr - kBase);
        if (reg == kRegRsltConf) {
            if ((value & ~kRsltConfServed) != 0u) {
                HaltUnsupportedAccess("WriteWord", addr, value);
            }
            std::lock_guard<std::mutex> g(lock_);
            chans_[ch].rslt_conf = value;
            PublishLineLocked();
            return;
        }
        if (reg == kRegFlush0) {
            if (value != 0u) {
                emu_.Get<Fatal>().Die(
                    "msm8255 dmov: channel %u took a flush of type 0x%08X, and "
                    "how this flush type changes what the engine does to the "
                    "transfer in flight is not modeled", ch, value);
            }
            std::lock_guard<std::mutex> g(lock_);
            Channel& c = chans_[ch];
            /* Linux drivers dma qcom qcom_adm.c: adm_dma_remove terminates every
               channel, including ones that never ran. */
            if (!c.in_flight) return;
            c.in_flight  = false;
            c.cmd_ptr    = 0u;
            c.crci       = 0u;
            c.await_crci = 0u;
            if ((c.rslt_conf & kRsltConfForceFlushRslt) == 0u) {
                emu_.Get<Fatal>().Die(
                    "msm8255 dmov: channel %u took a flush with FORCE_FLUSH_RSLT "
                    "clear, and what this engine reports for a terminated "
                    "transfer without it is not modeled", ch);
            }
            PushResultLocked(ch, kRsltValid | kRsltFlush);
            return;
        }
        if (reg == kRegCmdPtr) {
            StartTransfer(ch, value);
            return;
        }
        HaltUnsupportedAccess("WriteWord", addr, value);
    }

    void SaveState(StateWriter& w) override {
        std::lock_guard<std::mutex> g(lock_);
        static_assert(StateVisitCoversAllBytes<Channel>(
                          [](Channel& c, StateFieldBytes& f) { Channel::Visit(c, f); }),
                      "Channel::Visit must name or skip every field of Channel");
        StateWriteField field(w);
        for (Channel& c : chans_) Channel::Visit(c, field);
    }

    void RestoreState(StateReader& r) override {
        std::lock_guard<std::mutex> g(lock_);
        StateReadField field(r);
        for (Channel& c : chans_) {
            Channel::Visit(c, field);
            if (c.count > kRsltFifoDepth || c.head >= kRsltFifoDepth) {
                r.Reject(
                    "msm8255 dmov: restored channel result fifo carries count %u "
                    "head %u past its depth %u", c.count, c.head, kRsltFifoDepth);
            }
            if (c.crci != 0u &&
                !emu_.Get<Msm8255CrciBus>().Declared(c.crci)) {
                r.Reject(
                    "msm8255 dmov: restored channel is paced on crci %u, and no "
                    "modeled peripheral drives that line", c.crci);
            }
            if (c.await_crci != 0u && c.await_crci != c.crci) {
                r.Reject(
                    "msm8255 dmov: restored channel waits on crci %u while it "
                    "is paced on crci %u", c.await_crci, c.crci);
            }
            if (c.in_flight &&
                !emu_.Get<Msm8255AdmCommandList>().IsModeledCmdPtr(c.cmd_ptr)) {
                r.Reject("msm8255 dmov: restored in-flight command pointer 0x%08X "
                         "is not a modeled type 0 pointer list", c.cmd_ptr);
            }
        }
    }

    void PostRestore() override {
        std::lock_guard<std::mutex> g(lock_);
        auto& clock = emu_.Get<GuestCycleClock>();
        for (const Channel& c : chans_) {
            if (c.in_flight && c.await_crci == 0u) {
                clock.Arm(done_, clock.Cycles());
                break;
            }
        }
        PublishLineLocked();
    }

private:
    struct Channel {
        uint32_t rslt_conf = 0u;
        uint32_t fifo[kRsltFifoDepth] = {};
        uint32_t head  = 0u;
        uint32_t count = 0u;
        uint32_t cmd_ptr   = 0u;
        bool     in_flight = false;
        uint8_t  pad[3]    = {};
        uint32_t crci       = 0u;
        uint32_t await_crci = 0u;

        template <typename F>
        static constexpr void Visit(Channel& c, F& field) {
            field("rslt_conf", c.rslt_conf);
            field("fifo", c.fifo);
            field("head", c.head);
            field("count", c.count);
            field("cmd_ptr", c.cmd_ptr);
            field("in_flight", c.in_flight);
            field.Skip(c.pad);
            field("crci", c.crci);
            field("await_crci", c.await_crci);
        }
    };

    static uint32_t RegOf(uint32_t off) { return off & ~0x3Cu; }

    static uint32_t ChannelOf(uint32_t off) {
        if ((off & 3u) != 0u) return kChannelCount;
        const uint32_t ch = (off & 0x3Cu) / 4u;
        const uint32_t reg = RegOf(off);
        const bool known = reg == kRegCmdPtr || reg == kRegRslt ||
                           reg == kRegFlush0 ||
                           reg == kRegStatus || reg == kRegRsltConf;
        return known ? ch : kChannelCount;
    }

    uint32_t StatusLocked(uint32_t ch) const {
        uint32_t v = kStatusCmdPtrRdy;
        if (chans_[ch].count != 0u) {
            v |= kStatusRsltValid;
            v |= chans_[ch].count << kStatusRsltCountSh;
        }
        return v;
    }

    uint32_t PopResultLocked(uint32_t ch) {
        Channel& c = chans_[ch];
        if (c.count == 0u) return 0u;
        const uint32_t v = c.fifo[c.head];
        c.head = (c.head + 1u) % kRsltFifoDepth;
        --c.count;
        PublishLineLocked();
        return v;
    }

    void PushResultLocked(uint32_t ch, uint32_t value) {
        Channel& c = chans_[ch];
        if (c.count == kRsltFifoDepth) {
            emu_.Get<Fatal>().Die(
                "msm8255 dmov: channel %u result fifo overflowed at depth %u",
                ch, kRsltFifoDepth);
        }
        c.fifo[(c.head + c.count) % kRsltFifoDepth] = value;
        ++c.count;
        PublishLineLocked();
    }

    uint32_t IsrWordLocked() const {
        uint32_t v = 0u;
        for (uint32_t ch = 0; ch < kChannelCount; ++ch) {
            if (chans_[ch].count != 0u &&
                (chans_[ch].rslt_conf & kRsltConfIrqEn) != 0u) {
                v |= 1u << ch;
            }
        }
        return v;
    }

    void PublishLineLocked() {
        auto& vic = emu_.Get<IrqController>();
        if (IsrWordLocked() != 0u) {
            vic.AssertIrq(kVicLine);
        } else {
            vic.DeAssertIrq(kVicLine);
        }
    }

    void StartTransfer(uint32_t ch, uint32_t value) {
        auto& list = emu_.Get<Msm8255AdmCommandList>();
        list.RequireModeledCmdPtr(value);
        const uint32_t crci = list.FirstCrci(value);
        std::lock_guard<std::mutex> g(lock_);
        Channel& c = chans_[ch];
        if (c.in_flight) {
            emu_.Get<Fatal>().Die(
                "msm8255 dmov: channel %u took a command pointer while one was "
                "still in flight, and the depth this engine queues them to is "
                "not modeled", ch);
        }
        c.cmd_ptr   = value;
        c.in_flight = true;
        c.crci      = crci;
        auto& lines = emu_.Get<Msm8255CrciBus>();
        if (crci != 0u && !lines.Declared(crci)) {
            emu_.Get<Fatal>().Die(
                "msm8255 dmov: channel %u is paced on crci %u, and no modeled "
                "peripheral drives that line", ch, crci);
        }
        if (crci != 0u && !lines.LevelHigh(crci)) {
            c.await_crci = crci;
            return;
        }
        c.await_crci = 0u;
        auto& clock = emu_.Get<GuestCycleClock>();
        clock.Arm(done_, clock.Cycles());
    }

    void AssertCrci(uint32_t crci) override {
        bool due = false;
        {
            std::lock_guard<std::mutex> g(lock_);
            for (Channel& c : chans_) {
                if (c.in_flight && c.await_crci == crci) {
                    c.await_crci = 0u;
                    due = true;
                }
            }
        }
        if (!due) return;
        auto& clock = emu_.Get<GuestCycleClock>();
        clock.Arm(done_, clock.Cycles());
    }

    void CompleteDue() {
        for (uint32_t ch = 0; ch < kChannelCount; ++ch) {
            uint32_t value;
            uint32_t crci;
            {
                std::lock_guard<std::mutex> g(lock_);
                if (!chans_[ch].in_flight) continue;
                if (chans_[ch].await_crci != 0u) continue;
                value = chans_[ch].cmd_ptr;
                crci  = chans_[ch].crci;
            }
            RunTransfer(ch, value, crci);
            std::lock_guard<std::mutex> g(lock_);
            chans_[ch].in_flight  = false;
            chans_[ch].cmd_ptr    = 0u;
            chans_[ch].crci       = 0u;
            chans_[ch].await_crci = 0u;
        }
    }

    void RunTransfer(uint32_t ch, uint32_t value, uint32_t crci) {
        emu_.Get<Msm8255AdmCommandList>().Run(value, crci);
        std::lock_guard<std::mutex> g(lock_);
        PushResultLocked(ch, kRsltValid | kRsltDone);
    }

    void ResetState() {
        std::lock_guard<std::mutex> g(lock_);
        for (Channel& c : chans_) c = Channel{};
        emu_.Get<GuestCycleClock>().Disarm(done_);
        PublishLineLocked();
    }

    GuestCycleClock::Event* done_ = nullptr;
    std::mutex lock_;
    Channel    chans_[kChannelCount];
};

}  // namespace

REGISTER_SERVICE(Msm8255Dmov);
