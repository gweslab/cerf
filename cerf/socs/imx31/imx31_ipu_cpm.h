#pragma once

#include "../../core/service.h"

#include <cstdint>
#include <mutex>

class StateReader;
class StateWriter;

class Imx31IpuCpm : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;

    enum class PfsKind { Unknown = 0, RgbPack = 4, Yuv422 = 6, Generic = 7 };

    struct ChannelFormat {
        PfsKind  pfs       = PfsKind::Unknown;
        uint8_t  bpp_bits  = 0;
        uint16_t stride    = 0;
        uint8_t  wid[4]    = {};
        uint8_t  ofs[4]    = {};
        uint16_t fw        = 0;
        uint16_t fh        = 0;
    };

    static constexpr uint32_t kNoChannel = 0xFFFFFFFFu;

    void     WriteImaAddr(uint32_t value);
    uint32_t WriteImaData(uint32_t value);

    ChannelFormat Decode(uint32_t channel) const;
    uint32_t      Eba0(uint32_t channel) const;
    void          EncodeRgb565(uint32_t channel, uint32_t fb_pa, uint32_t w, uint32_t h);

    void Reset();
    void SaveState(StateWriter& w);
    void RestoreState(StateReader& r);

private:
    static constexpr uint32_t kRows          = 128u;
    static constexpr uint32_t kDwordsPerRow  = 5u;
    static constexpr uint32_t kDwordCount    = kRows * kDwordsPerRow;

    static uint32_t ExtractBits(const uint32_t* dwords, uint32_t lsb, uint32_t width);

    mutable std::mutex mtx_;

    uint32_t cpm_[kDwordCount] = {};
    uint8_t  ima_mem_nu_  = 0;
    uint16_t ima_row_nu_  = 0;
    uint8_t  ima_word_nu_ = 0;
};
