#pragma once

#include "../../core/service.h"
#include "../freescale_sdma_audio_player.h"

#include <cstdint>

class Imx51SsiSlaveFormat : public Service {
public:
    using Service::Service;

    virtual FreescaleAudioFormat Format(uint32_t ssi) const = 0;
    virtual uint32_t             FrameSyncBitClocks(uint32_t ssi) const = 0;
};
