#pragma once

#include "../../peripherals/peripheral_base.h"

#include <cstdint>
#include <functional>
#include <mutex>
#include <vector>

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

    struct ChannelState {
        uint32_t channel_index;
        uint32_t ddar;
        uint32_t dbsa;
        uint32_t dbta;
        uint32_t dbsb;
        uint32_t dbtb;
        bool     buffer_b;
    };

    /* Sink returns true if it claims the transfer and will call
       CompleteTransfer asynchronously; false to let the default
       instant-DONE path run. */
    using SinkFn = std::function<bool(const ChannelState&)>;
    void RegisterSink(SinkFn fn);

    void CompleteTransfer(uint32_t channel_index, bool buffer_b);

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;

    static constexpr uint32_t kChannelCount  = 6;
    static constexpr uint32_t kChannelStride = 0x20u;

private:
    struct Channel {
        uint32_t ddar = 0;
        uint32_t dcsr = 0;
        uint32_t dbsa = 0;
        uint32_t dbta = 0;
        uint32_t dbsb = 0;
        uint32_t dbtb = 0;
        /* Buffer claimed by a sink, CompleteTransfer not yet called.
           §11.6.1.3: RUN clear pauses, RUN re-set resumes the transfer -
           a RUN 0→1 edge must not re-submit a buffer a sink still owns. */
        bool in_flight_a = false;
        bool in_flight_b = false;
        uint8_t pad[2] = {};
    };

    template <typename F>
    static constexpr void VisitChannel(Channel& c, F& field) {
        field("ddar", c.ddar);
        field("dcsr", c.dcsr);
        field("dbsa", c.dbsa);
        field("dbta", c.dbta);
        field("dbsb", c.dbsb);
        field("dbtb", c.dbtb);
        field.Skip(c.in_flight_a);
        field.Skip(c.in_flight_b);
        field.Skip(c.pad);
    }

    mutable std::mutex   state_mtx_;
    Channel              ch_[kChannelCount]{};
    std::vector<SinkFn>  sinks_;

    static bool DecodeOffset(uint32_t off, uint32_t& ch, uint32_t& reg);
    uint32_t ReadRegLocked(uint32_t off);
    void     WriteRegLocked(uint32_t off, uint32_t value);
    void     KickIfStartedLocked(uint32_t channel_index, Channel& c,
                                 uint32_t newly_set);
    void     RefreshIrqLineLocked(uint32_t channel_index, Channel& c);
};
