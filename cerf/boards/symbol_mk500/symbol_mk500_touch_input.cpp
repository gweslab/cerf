#define NOMINMAX

#include "../../host/touch_input.h"

#include <windows.h>

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../host/host_canvas.h"
#include "../../peripherals/ac97_codec.h"
#include "../../peripherals/wolfson_wm9713/wm9713_codec.h"
#include "../../socs/pxa27x/pxa27x_gpio.h"
#include "../../state/emulation_freeze.h"
#include "../board_context.h"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <cstdint>
#include <thread>

namespace {

/* WM9713L datasheet (Cirrus Logic, Rev 4.0) page 122, register 7Ah bits 11:0
   ADCD "Touchpanel ADC Data (Read-only) Bit 0 = LSB, Bit 11 = MSB"; symbol_mk500
   touch.dll FUN_022379ac @0x022379ac keeps those bits as the channel value. */
constexpr long kAdcMax = 0x0FFF;

/* symbol_mk500 touch.dll FUN_02237380 @0x02237380 waits 0x32 ms between MODR
   retries and gives up after ten of them. */
constexpr DWORD kSamplePeriodMs = 11u;

/* symbol_mk500 touch.dll TouchPanelEnable @0x02233AF4 arms *0x01DD10C4 = 0x11
   and FUN_022323a8 @0x0223240C acks with InterruptDone(0x11); symbol_mk500
   nk.exe OEMInterruptEnable @0x801BC44C reads [0x8C32B0A0 + 0x11*4] = 0x22
   (written @0x801BB2E8), whose case body @0x801BC520 sets GFER3 bit 5. */
constexpr uint32_t kGpioPenDown = 101u;

class SymbolMk500TouchInput : public TouchInput {
public:
    using TouchInput::TouchInput;

    ~SymbolMk500TouchInput() override {
        shutdown_.store(true, std::memory_order_release);
        if (wake_) SetEvent(wake_);
        if (pacer_.joinable()) pacer_.join();
        if (wake_) CloseHandle(wake_);
    }

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoard() == Board::SymbolMk500;
    }

    void OnReady() override {
        codec_ = dynamic_cast<Wm9713Codec*>(emu_.TryGet<Ac97Codec>());
        if (!codec_) {
            LOG(Caution, "[MK500 touch] no WM9713 codec registered\n");
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        wake_  = CreateEventW(nullptr, FALSE, FALSE, nullptr);
        gpio_  = &emu_.Get<Pxa27xGpio>();
        gpio_->SetInputLevel(kGpioPenDown, true);
        pacer_ = std::thread([this] { PacerMain(); });
    }

    void OnPenDown(int x, int y) override { SetPos(x, y); SetDown(true); }
    void OnPenMove(int x, int y) override { SetPos(x, y); }
    void OnPenUp(int, int) override       { SetDown(false); }
    void OnCaptureLost() override         { SetDown(false); }

private:
    void SetPos(int x, int y) {
        pos_x_.store(x, std::memory_order_relaxed);
        pos_y_.store(y, std::memory_order_relaxed);
    }

    void SetDown(bool down) {
        const bool was = pen_down_.exchange(down, std::memory_order_acq_rel);
        if (down == was) return;
        LOG(Periph, "[MK500 touch] pen %s pos=(%d,%d)\n", down ? "DOWN" : "UP",
            pos_x_.load(std::memory_order_relaxed),
            pos_y_.load(std::memory_order_relaxed));
        if (!down) pen_up_pending_.store(true, std::memory_order_release);
        SetEvent(wake_);
    }

    void PacerMain() {
        auto& freeze = emu_.Get<EmulationFreeze>();
        while (!shutdown_.load(std::memory_order_acquire)) {
            if (pen_down_.load(std::memory_order_acquire)) {
                {
                    auto frozen = freeze.WorkerSection();
                    Deliver(true);
                }
                WaitForSingleObject(wake_, kSamplePeriodMs);
            } else {
                if (pen_up_pending_.exchange(false, std::memory_order_acq_rel)) {
                    auto frozen = freeze.WorkerSection();
                    Deliver(false);
                }
                WaitForSingleObject(wake_, INFINITE);
            }
        }
    }

    void Deliver(bool down) {
        uint16_t rx = 0, ry = 0;
        RawFromScreen(pos_x_.load(std::memory_order_relaxed),
                      pos_y_.load(std::memory_order_relaxed), rx, ry);
        codec_->SetPen(down, rx, ry);
        gpio_->SetInputLevel(kGpioPenDown, !down);
    }

    void RawFromScreen(int sx, int sy, uint16_t& raw_x, uint16_t& raw_y) {
        auto& hc = emu_.Get<HostCanvas>();
        const long w = static_cast<long>(hc.GuestSurfaceWidth());
        const long h = static_cast<long>(hc.GuestSurfaceHeight());
        raw_x = Scale(sx, w);
        raw_y = Scale(sy, h);
    }

    static uint16_t Scale(int pos, long span) {
        if (span <= 1) return 0u;
        const long v = std::lround(static_cast<double>(pos) * kAdcMax / (span - 1));
        return static_cast<uint16_t>(std::clamp<long>(v, 0, kAdcMax));
    }

    Wm9713Codec*      codec_ = nullptr;
    Pxa27xGpio*       gpio_  = nullptr;
    std::atomic<bool> pen_down_{false};
    std::atomic<bool> pen_up_pending_{false};
    std::atomic<bool> shutdown_{false};
    std::atomic<int>  pos_x_{0}, pos_y_{0};
    HANDLE            wake_ = nullptr;
    std::thread       pacer_;
};

}  // namespace

REGISTER_SERVICE_AS(SymbolMk500TouchInput, TouchInput);
