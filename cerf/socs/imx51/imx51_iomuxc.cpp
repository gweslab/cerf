#include "imx51_iomuxc.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"
#include "imx51_id.h"

#include <cstdint>
#include <iterator>
#include <utility>

namespace {

/* MCIMX51RM Table A-493/A-494: IOMUXC_SW_MUX_CTL_PAD_GPIO1_4 at 0x3D8, SION [4] and
   MUX_MODE [2:0], reset 0; MUX_MODE 010 = WDOG_B of wdog1; Table 4-2 lists no other pad
   for it. */
constexpr uint32_t kMuxCtlPadGpio1_4 = 0x3D8u;
constexpr uint32_t kMuxCtlWritable   = 0x17u;
constexpr uint32_t kMuxModeMask      = 0x7u;
constexpr uint32_t kMuxModeWdog1B    = 0x2u;

constexpr uint32_t kSion = 1u << 4;

struct BoardPad {
    uint32_t mux_off;
    uint32_t gpio_base;
    uint32_t pin;
    uint32_t gpio_mode;
    uint32_t mode_mask;
    uint32_t reset;
};

constexpr BoardPad kBoardPadTable[] = {
    {0x3B0u, 0x73F84000u, 1u,  1u, 0x7u, 0u},
    {0x150u, 0x73F8C000u, 24u, 3u, 0x7u, 0u},
    {0x1F8u, 0x73F90000u, 16u, 3u, 0x3u, 3u},
    {0x1FCu, 0x73F90000u, 17u, 3u, 0x3u, 3u},
    {0x214u, 0x73F90000u, 23u, 3u, 0x7u, 3u},
};

}

REGISTER_SERVICE(Imx51Iomuxc);

bool Imx51Iomuxc::ShouldRegister() {
    return emu_.Get<BoardContext>().GetSocId() == SocId::Imx51;
}

/* MCIMX51RM Table 54-10 and p.54-15: test_logic_rst_b resets the IOMUXC, and only the POR
   and jtag_rst_b rows assert it. */
void Imx51Iomuxc::OnReady() {
    static_assert(std::size(kBoardPadTable) == kBoardPads);
    ResetBoardPads();
    auto& reset = emu_.Get<GuestCpuReset>();
    reset.RegisterResetListener([this](ResetLineKind kind) {
        if (kind != ResetLineKind::Rtc) return;
        gpio1_4_mux_ = 0u;
        ResetBoardPads();
    });
    reset.RegisterResetReleaseListener([this] { NotifyPads(); });
    emu_.Get<PeripheralDispatcher>().Register(this);
}

void Imx51Iomuxc::ResetBoardPads() {
    for (uint32_t i = 0u; i < kBoardPads; ++i) pad_mux_[i] = kBoardPadTable[i].reset;
}

uint32_t Imx51Iomuxc::ReadWord(uint32_t addr) {
    emu_.Get<Fatal>().Die("Imx51Iomuxc: read of +0x%03X is not modeled", addr - MmioBase());
}

void Imx51Iomuxc::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (off == kMuxCtlPadGpio1_4) {
        gpio1_4_mux_ = value & kMuxCtlWritable;
        CheckWdog1Pad();
        return;
    }
    for (uint32_t i = 0u; i < kBoardPads; ++i) {
        if (kBoardPadTable[i].mux_off != off) continue;
        const uint32_t next = value & (kSion | kBoardPadTable[i].mode_mask);
        if (next == pad_mux_[i]) return;
        pad_mux_[i] = next;
        NotifyPads();
        return;
    }
}

bool Imx51Iomuxc::MapsGpioPin(uint32_t gpio_base, uint32_t pin) {
    for (const BoardPad& p : kBoardPadTable) {
        if (p.gpio_base == gpio_base && p.pin == pin) return true;
    }
    return false;
}

/* MCIMX51RM Table A-474: SION "Force the selected mux mode Input path no matter of MUX_MODE
   functionality"; Table 35-5: "Reading the data register with the input path disabled will
   always return a zero value". */
uint32_t Imx51Iomuxc::InputPathMask(uint32_t gpio_base) const {
    uint32_t mask = 0xFFFFFFFFu;
    for (uint32_t i = 0u; i < kBoardPads; ++i) {
        const BoardPad& p = kBoardPadTable[i];
        if (p.gpio_base != gpio_base) continue;
        const bool gpio = (pad_mux_[i] & p.mode_mask) == p.gpio_mode;
        if (!gpio && (pad_mux_[i] & kSion) == 0u) mask &= ~(1u << p.pin);
    }
    return mask;
}

/* MCIMX51RM Table 35-5: "The I/O multiplexer associated with each bit must be configured
   for GPIO for the function to affect the state of the pin." */
uint32_t Imx51Iomuxc::GpioPadMask(uint32_t gpio_base) const {
    uint32_t mask = 0xFFFFFFFFu;
    for (uint32_t i = 0u; i < kBoardPads; ++i) {
        const BoardPad& p = kBoardPadTable[i];
        if (p.gpio_base != gpio_base) continue;
        if ((pad_mux_[i] & p.mode_mask) != p.gpio_mode) mask &= ~(1u << p.pin);
    }
    return mask;
}

void Imx51Iomuxc::RegisterPadListener(std::function<void()> fn) {
    pad_listeners_.push_back(std::move(fn));
}

void Imx51Iomuxc::NotifyPads() {
    for (auto& fn : pad_listeners_) fn();
}

void Imx51Iomuxc::DriveWdog1WdogB(bool asserted) {
    wdog1_wdog_b_ = asserted;
    CheckWdog1Pad();
}

void Imx51Iomuxc::CheckWdog1Pad() const {
    if (!wdog1_wdog_b_) return;
    if ((gpio1_4_mux_ & kMuxModeMask) != kMuxModeWdog1B) return;
    emu_.Get<Fatal>().Die("Imx51Iomuxc: WDOG1 WDOG_B is asserted on pad GPIO1_4 (mux 0x%08X); "
                          "the board's response to the pin is not modeled", gpio1_4_mux_);
}

void Imx51Iomuxc::SaveState(StateWriter& w) {
    w.Write<uint32_t>("gpio1_4_mux", gpio1_4_mux_);
    w.WriteBytes("board_pad_mux", pad_mux_.data(), sizeof(pad_mux_));
}

void Imx51Iomuxc::RestoreState(StateReader& r) {
    uint32_t mux = 0u;
    r.Read("gpio1_4_mux", mux);
    gpio1_4_mux_ = mux;
    r.ReadBytes("board_pad_mux", pad_mux_.data(), sizeof(pad_mux_));
}
