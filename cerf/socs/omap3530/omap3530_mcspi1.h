#pragma once

#include "../../peripherals/peripheral_base.h"
#include "../../state/state_stream.h"

#include <cstdint>
#include <mutex>

/* SPI slave attached to one McSPI channel. The McSPI controller
   forwards each TX-register write to the slave's Transfer and
   stores the returned value into RX. wl_bits is the effective
   word length programmed via CHCONF.WL (1..32). */
class McspiSlave {
public:
    virtual ~McspiSlave() = default;
    virtual uint32_t Transfer(uint32_t tx_word, uint32_t wl_bits) = 0;
};

class Omap3530Mcspi1 : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return 0x48098000u; }
    uint32_t MmioSize() const override { return 0x00000100u; }

    uint32_t ReadWord (uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void RegisterSlave(uint32_t channel, McspiSlave* slave);

    /* RegisterSlave is a cross-thread caller, so the same mutex guards
       state in both methods. The McspiSlave* pointers are host wiring,
       re-established by RegisterSlave at construction - not serialized. */
    void SaveState(StateWriter& w) override {
        std::lock_guard<std::mutex> lk(mu_);
        w.Write("sysconfig", sysconfig_);
        w.Write("irqstatus", irqstatus_);
        w.Write("irqenable", irqenable_);
        w.Write("wakeupenable", wakeupenable_);
        w.Write("syst", syst_);
        w.Write("modulctrl", modulctrl_);
        static_assert(StateVisitCoversAllBytes<Channel>(
                          [](Channel& c, StateFieldBytes& f) { Channel::Visit(c, f); }),
                      "Channel::Visit must name or skip every field of Channel");
        StateWriteField field(w);
        for (Channel& c : channels_) Channel::Visit(c, field);
    }
    void RestoreState(StateReader& r) override {
        std::lock_guard<std::mutex> lk(mu_);
        r.Read("sysconfig", sysconfig_);
        r.Read("irqstatus", irqstatus_);
        r.Read("irqenable", irqenable_);
        r.Read("wakeupenable", wakeupenable_);
        r.Read("syst", syst_);
        r.Read("modulctrl", modulctrl_);
        StateReadField field(r);
        for (Channel& c : channels_) Channel::Visit(c, field);
    }

private:
    struct Channel {
        uint32_t    chconf  = 0;
        uint32_t    chctrl  = 0;
        uint32_t    rx      = 0;
        bool        rx_full = false;
        uint8_t     pad[3]  = {};
        McspiSlave* slave   = nullptr;

        template <typename F>
        static constexpr void Visit(Channel& c, F& field) {
            field("chconf", c.chconf);
            field("chctrl", c.chctrl);
            field("rx", c.rx);
            field("rx_full", c.rx_full);
            field.Skip(c.pad);
            field.Skip(c.slave);
        }
    };

    void     PerformTransfer(uint32_t channel_index, uint32_t tx_word);
    uint32_t WordLength(const Channel& c) const;

    static constexpr uint32_t kNumChannels = 4;

    mutable std::mutex mu_;
    uint32_t sysconfig_    = 0;
    uint32_t irqstatus_    = 0;
    uint32_t irqenable_    = 0;
    uint32_t wakeupenable_ = 0;
    uint32_t syst_         = 0;
    uint32_t modulctrl_    = 0;
    Channel  channels_[kNumChannels];
};
