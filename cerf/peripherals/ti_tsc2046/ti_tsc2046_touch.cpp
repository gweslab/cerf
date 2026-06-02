#include "ti_tsc2046_touch.h"

#include "../../boards/board_detector.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"

REGISTER_SERVICE(Tsc2046Touch);

bool Tsc2046Touch::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardDetector>();
    if (!bd) return false;
    const auto b = bd->GetBoard();
    return b == Board::OmapEvm3530;
}

void Tsc2046Touch::OnReady() {
    emu_.Get<Omap3530Mcspi1>().RegisterSlave(0u, this);
}

void Tsc2046Touch::SetState(uint16_t adc_x, uint16_t adc_y, bool pen_down) {
    adc_x_.store(static_cast<uint16_t>(adc_x & 0x0FFFu),
                 std::memory_order_relaxed);
    adc_y_.store(static_cast<uint16_t>(adc_y & 0x0FFFu),
                 std::memory_order_relaxed);
    pen_down_.store(pen_down, std::memory_order_release);
}

bool Tsc2046Touch::IsPenIrqAsserted() const {
    return pen_down_.load(std::memory_order_acquire);
}

uint32_t Tsc2046Touch::Transfer(uint32_t out_word, uint32_t wl_bits) {
    /* TSC2046 control byte is 8 bits (S A2:A0 MODE SER/DFR PD1:PD0).
       A SPI word length < 8 cannot carry it; McSPI's pre-Transfer mask
       would have already destroyed the control bits before Transfer is
       called. Fail loudly so a misconfigured BSP is caught at the slave. */
    if (wl_bits < 8u) {
        LOG(Caution, "Tsc2046Touch::Transfer wl_bits=%u; TSC2046 requires "
                     ">=8 bits per transaction\n", wl_bits);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    const uint32_t shift = wl_bits - 8u;
    const uint8_t  ctrl  = static_cast<uint8_t>((out_word >> shift) & 0xFFu);
    const uint8_t channel_a = static_cast<uint8_t>((ctrl >> 4) & 0x7u);

    uint16_t adc = 0;
    switch (channel_a) {
    case 0x5: adc = adc_x_.load(std::memory_order_relaxed); break;  /* X */
    case 0x1: adc = adc_y_.load(std::memory_order_relaxed); break;  /* Y */
    default:  adc = 0; break;
    }
    return static_cast<uint32_t>(adc & 0x0FFFu) << 3;
}
