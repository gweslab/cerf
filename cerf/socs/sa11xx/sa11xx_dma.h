#pragma once

#include "../../peripherals/peripheral_base.h"
#include "../../jit/guest_cycle_clock.h"
#include "sa11xx_dma_clients.h"
#include "sa11xx_dma_stream.h"

#include <cstdint>
#include <vector>

class Sa11xxDmaPort;

class Sa11xxDma : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override { return 0xB0000000u; }
    uint32_t MmioSize() const override { return 0x00010000u; }

    uint8_t  ReadByte (uint32_t addr) override;
    uint16_t ReadHalf (uint32_t addr) override;
    uint32_t ReadWord (uint32_t addr) override;
    void     WriteByte(uint32_t addr, uint8_t  value) override;
    void     WriteHalf(uint32_t addr, uint16_t value) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void RegisterPort(uint32_t device_select, Sa11xxDmaPort* port);
    void RegisterTransmitObserver(Sa11xxDmaTransmitObserver* observer);
    void RegisterReceiveSource(Sa11xxDmaReceiveSource* source);
    void OnPortChange();

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override;

    static constexpr uint32_t kChannelCount  = 6;
    static constexpr uint32_t kChannelStride = 0x20u;

private:
    static constexpr uint8_t kUnbound = 0xFFu;

    template <typename F>
    static constexpr void VisitChannel(Sa11xxDmaChannelRegs& c, F& field) {
        field("ddar", c.ddar);
        field("dcsr", c.dcsr);
        field("dbsa", c.dbsa);
        field("dbta", c.dbta);
        field("dbsb", c.dbsb);
        field("dbtb", c.dbtb);
    }

    static bool DecodeOffset(uint32_t off, uint32_t& ch, uint32_t& reg);
    uint32_t StoredReg(uint32_t off) const;
    uint32_t ReadReg(uint32_t off);
    uint32_t ReadBuffer(uint32_t ch, uint32_t reg);
    void     WriteReg(uint32_t off, uint32_t value);
    Sa11xxDmaPort* PortFor(uint32_t ddar) const;
    bool           SelectsPort(uint32_t ddar) const;
    void           RequireSupportedTransfer(uint32_t ch, uint32_t dcsr) const;
    void     Bind(uint32_t ch, Sa11xxDmaPort* port);
    void     OnResetLine();
    void     RequireBuffers(uint32_t ch) const;
    void     WriteDdar(uint32_t ch, uint32_t value);
    void     WriteDcsrSet(uint32_t ch, uint32_t value);
    void     WriteDcsrClear(uint32_t ch, uint32_t value);
    void     WriteBuffer(uint32_t ch, uint32_t reg, uint32_t value);
    void     KickUnbound(uint32_t ch, uint32_t newly_set);
    void     Update();
    void     ArmDone(uint32_t ch);
    void     RefreshIrqLine(uint32_t ch);
    void     Transmit(uint32_t ddar, uint32_t pa, uint32_t bytes, GuestCycleClock::Rate rate);
    void     Receive(uint32_t ddar, uint32_t pa, uint32_t bytes, GuestCycleClock::Rate rate);

    GuestCycleClock*        clock_ = nullptr;
    GuestCycleClock::Event* done_[kChannelCount] = {};
    Sa11xxDmaChannelRegs    ch_[kChannelCount]{};
    Sa11xxDmaStream         stream_[kChannelCount];
    Sa11xxDmaPort*          ports_[16] = {};
    Sa11xxDmaStream::Hooks  hooks_;
    std::vector<Sa11xxDmaTransmitObserver*> transmit_;
    std::vector<Sa11xxDmaReceiveSource*>    receive_;
};
