#pragma once

#include <cstddef>
#include <cstdint>

/* Freescale i.MX SDMA <-> serial-peripheral coupling. Non-template (peripherals
   hold a pointer to it) because FreescaleSdmaBase is templated on its base. */
class FreescaleSdmaPeripheral {
public:
    virtual ~FreescaleSdmaPeripheral() = default;
    virtual void SdmaTxByte(uint8_t byte) = 0;
};

/* SDMA side, as seen by a peripheral. */
class FreescaleSdmaBus {
public:
    virtual ~FreescaleSdmaBus() = default;

    /* Bind a peripheral DMA-request / CHNENBL event to its data port (i.MX51
       UART1 TX=19 / RX=18). is_tx selects memory->peripheral (the SDMA drives it
       at channel start) vs peripheral->memory (the peripheral pushes received
       bytes via SdmaRxDeliver). */
    virtual void RegisterSdmaEvent(uint32_t event, FreescaleSdmaPeripheral* p,
                                   bool is_tx) = 0;

    /* A peripheral delivers received bytes into the armed channel(s) bound
       (CHNENBL) to its RX event. Returns true if a DMA channel consumed them
       (false -> no armed DMA channel; keep the bytes for a PIO read). */
    virtual bool SdmaRxDeliver(uint32_t event, const uint8_t* data,
                               std::size_t n) = 0;
};

class StateWriter;
class StateReader;

struct FreescaleSdmaChannelStart {
    uint32_t channel;
    int      event;
    uint32_t base_bd_pa;
    uint32_t stride;
};

class FreescaleSdmaChannelSink {
public:
    virtual ~FreescaleSdmaChannelSink() = default;

    virtual bool ClaimChannel(const FreescaleSdmaChannelStart& start) = 0;
    virtual void ReleaseChannel(uint32_t channel) = 0;
    virtual void SaveSinkState(StateWriter& w) = 0;
    virtual void RestoreSinkState(StateReader& r) = 0;
    virtual void PostRestoreSink() = 0;
};

class FreescaleSdmaChannelHost {
public:
    virtual ~FreescaleSdmaChannelHost() = default;

    virtual void RegisterChannelSink(FreescaleSdmaChannelSink* sink) = 0;
    virtual void SignalChannelBdDone(uint32_t channel, uint32_t bd_pa) = 0;
    virtual bool ChannelWatermark(uint32_t channel, uint32_t& value) const = 0;
};
