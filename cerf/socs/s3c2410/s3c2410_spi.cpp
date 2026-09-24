#include "s3c2410_spi.h"

#include "../../boards/board_context.h"
#include "s3c2410_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../core/log.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../guest_cpu_reset.h"
#include "../irq_controller.h"
#include "../../state/state_stream.h"

namespace {

/* S3C2410A UM pp. 22-7..22-10, Address columns. */
constexpr uint32_t kChannelStride  = 0x20u;
constexpr uint32_t kChannelRegSpan = 0x18u;

constexpr uint32_t kRegSpcon  = 0x00u;
constexpr uint32_t kRegSpsta  = 0x04u;
constexpr uint32_t kRegSppin  = 0x08u;
constexpr uint32_t kRegSppre  = 0x0Cu;
constexpr uint32_t kRegSptdat = 0x10u;
constexpr uint32_t kRegSprdat = 0x14u;

/* S3C2410A UM pp. 22-10, SPPREn / SPTDATn / SPRDATn Bit columns. */
constexpr uint32_t kByteMask = 0xFFu;

/* S3C2410A UM p. 22-7, SPCONn bit table. */
constexpr uint32_t kSpconDefinedMask = 0x7Fu;
constexpr uint32_t kSpconSmodShift   = 5u;
constexpr uint32_t kSpconSmodMask    = 0x3u;
constexpr uint32_t kSpconEnsck       = 1u << 4;
constexpr uint32_t kSpconMstr        = 1u << 3;
constexpr uint32_t kSpconTagd        = 1u << 0;
constexpr uint32_t kSmodPolling      = 0x0u;
constexpr uint32_t kSmodInterrupt    = 0x1u;

/* S3C2410A UM p. 22-8, SPSTAn bit table. */
constexpr uint32_t kSpstaRedy = 1u << 0;

/* S3C2410A UM p. 22-9, SPPINn bit table. */
constexpr uint32_t kSppinReserved1 = 1u << 1;

/* S3C2410A UM p. 14-7, SRCPND INT_SPI0 [22] and INT_SPI1 [29]. */
constexpr int kSrcpndIntSpi[2] = { 22, 29 };

}

bool S3C2410Spi::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::S3c2410;
}

void S3C2410Spi::OnReady() {
    Reset();
    emu_.Get<GuestCpuReset>().RegisterResetListener(
        [this](ResetLineKind) { Reset(); });
    emu_.Get<PeripheralDispatcher>().Register(this);
}

/* S3C2410A UM pp. 22-7..22-10, Reset Value columns. */
void S3C2410Spi::Reset() {
    for (Channel& c : channel_) {
        c = Channel{};
    }
}

void S3C2410Spi::SetSlave(int channel, SpiSlave* slave) {
    if (channel < 0 || channel >= kChannels) {
        emu_.Get<Fatal>().Die("S3C2410Spi::SetSlave: channel %d out of range", channel);
    }
    if (slave_[channel] != nullptr) {
        emu_.Get<Fatal>().Die("S3C2410Spi::SetSlave: channel %d already attached", channel);
    }
    slave_[channel] = slave;
}

uint32_t S3C2410Spi::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    const uint32_t ch  = off / kChannelStride;
    const uint32_t reg = off % kChannelStride;
    if (ch >= static_cast<uint32_t>(kChannels) || reg >= kChannelRegSpan) {
        HaltUnsupportedAccess("ReadWord", addr, 0);
    }
    const Channel& c = channel_[ch];
    uint32_t value = 0;
    switch (reg) {
        case kRegSpcon:  value = c.spcon;  break;
        case kRegSpsta:  value = c.spsta;  break;
        case kRegSppin:  value = c.sppin;  break;
        case kRegSppre:  value = c.sppre;  break;
        case kRegSptdat: value = c.sptdat; break;
        case kRegSprdat: value = c.sprdat; break;
        default:         HaltUnsupportedAccess("ReadWord", addr, 0);
    }
#if CERF_DEV_MODE
    LOG(SocSpi, "ch%u read  +0x%02X -> 0x%08X\n", ch, reg, value);
#endif
    return value;
}

void S3C2410Spi::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    const uint32_t ch  = off / kChannelStride;
    const uint32_t reg = off % kChannelStride;
    if (ch >= static_cast<uint32_t>(kChannels) || reg >= kChannelRegSpan) {
        HaltUnsupportedAccess("WriteWord", addr, value);
    }
    Channel& c = channel_[ch];
#if CERF_DEV_MODE
    LOG(SocSpi, "ch%u write +0x%02X = 0x%08X\n", ch, reg, value);
#endif
    switch (reg) {
        case kRegSpcon: {
            if ((value & ~kSpconDefinedMask) != 0u) {
                emu_.Get<Fatal>().Die(
                    "S3C2410Spi: SPCON%u write 0x%08X sets bits outside [6:0]", ch, value);
            }
            const uint32_t smod = (value >> kSpconSmodShift) & kSpconSmodMask;
            if (smod != kSmodPolling && smod != kSmodInterrupt) {
                emu_.Get<Fatal>().Die(
                    "S3C2410Spi: SPCON%u write 0x%08X selects SMOD %u", ch, value, smod);
            }
            if ((value & kSpconTagd) != 0u) {
                emu_.Get<Fatal>().Die(
                    "S3C2410Spi: SPCON%u write 0x%08X sets TAGD", ch, value);
            }
            c.spcon = value;
            break;
        }
        case kRegSppin:
            if (value != kSppinReserved1) {
                emu_.Get<Fatal>().Die(
                    "S3C2410Spi: SPPIN%u write 0x%08X is not the reset value", ch, value);
            }
            c.sppin = value;
            break;
        case kRegSppre:
            if ((value & ~kByteMask) != 0u) {
                emu_.Get<Fatal>().Die(
                    "S3C2410Spi: SPPRE%u write 0x%08X sets bits outside [7:0]", ch, value);
            }
            c.sppre = value;
            break;
        case kRegSptdat:
            if ((value & ~kByteMask) != 0u) {
                emu_.Get<Fatal>().Die(
                    "S3C2410Spi: SPTDAT%u write 0x%08X sets bits outside [7:0]", ch, value);
            }
            c.sptdat = value;
            Transfer(static_cast<int>(ch), static_cast<uint8_t>(value));
            break;
        default:
            HaltUnsupportedAccess("WriteWord", addr, value);
    }
}

/* S3C2410A UM p. 22-8, SPSTAn REDY. */
void S3C2410Spi::Transfer(int channel, uint8_t tx) {
    Channel& c = channel_[channel];
    c.spsta &= ~kSpstaRedy;
    if ((c.spcon & kSpconMstr) == 0u || (c.spcon & kSpconEnsck) == 0u) {
        emu_.Get<Fatal>().Die(
            "S3C2410Spi: ch%d transfer of 0x%02X with SPCON 0x%08X", channel, tx, c.spcon);
    }
    if (slave_[channel] == nullptr) {
        emu_.Get<Fatal>().Die(
            "S3C2410Spi: ch%d transfer of 0x%02X with no device attached", channel, tx);
    }
    c.sprdat = slave_[channel]->Exchange(tx);
    c.spsta |= kSpstaRedy;
    if (((c.spcon >> kSpconSmodShift) & kSpconSmodMask) == kSmodInterrupt) {
        emu_.Get<IrqController>().AssertIrq(kSrcpndIntSpi[channel]);
    }
}

void S3C2410Spi::SaveState(StateWriter& w) {
    static_assert(StateVisitCoversAllBytes<Channel>(
                      [](Channel& c, StateFieldBytes& f) { VisitChannel(c, f); }),
                  "S3C2410Spi::VisitChannel must name or skip every field of Channel");
    StateWriteField field(w);
    for (Channel& c : channel_) VisitChannel(c, field);
    for (int ch = 0; ch < kChannels; ++ch) {
        if (slave_[ch] != nullptr) {
            slave_[ch]->SaveState(w);
        }
    }
}

void S3C2410Spi::RestoreState(StateReader& r) {
    StateReadField field(r);
    for (Channel& c : channel_) VisitChannel(c, field);
    for (int ch = 0; ch < kChannels; ++ch) {
        if (slave_[ch] != nullptr) {
            slave_[ch]->RestoreState(r);
        }
    }
}

REGISTER_SERVICE(S3C2410Spi);
