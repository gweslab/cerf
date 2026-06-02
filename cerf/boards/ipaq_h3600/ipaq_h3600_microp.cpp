#include "../../core/cerf_emulator.h"
#include "../../core/service.h"
#include "../../boards/board_detector.h"
#include "../../host/host_canvas.h"
#include "../../host/touch_input.h"
#include "../../socs/sa1110/sa1110_sp1_uart.h"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <mutex>
#include <thread>

namespace {

/* Message IDs from Linux include/linux/mfd/ipaq-micro.h. */
constexpr uint8_t kSof          = 0x02;
constexpr uint8_t kMsgVersion   = 0x0;
constexpr uint8_t kMsgTouch     = 0x3;
constexpr uint8_t kMsgEepromRd  = 0x4;
constexpr uint8_t kMsgBattery   = 0x9;

constexpr uint16_t kAdcXMin = 60;
constexpr uint16_t kAdcXMax = 960;
constexpr uint16_t kAdcYMin = 35;
constexpr uint16_t kAdcYMax = 980;
constexpr auto     kSamplePeriod = std::chrono::milliseconds(20);

class Ipaq3650MicroP : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::Ipaq3650;
    }

    void OnReady() override {
        emu_.Get<Sa1110Sp1Uart>().SetTxListener(
            [this](uint8_t b) { OnTxByte(b); });
    }

    /* Linux drivers/input/touchscreen/ipaq-micro-ts.c:
       press = MSG_TOUCHSCREEN with len=4, payload [Y_BE16, X_BE16].
       release = MSG_TOUCHSCREEN with len=0. */
    void SendTouchPress(uint16_t adc_x, uint16_t adc_y) {
        const uint8_t payload[4] = {
            static_cast<uint8_t>((adc_y >> 8) & 0xFFu),
            static_cast<uint8_t>(adc_y        & 0xFFu),
            static_cast<uint8_t>((adc_x >> 8) & 0xFFu),
            static_cast<uint8_t>(adc_x        & 0xFFu),
        };
        SendFrame(kMsgTouch, payload, 4);
    }
    void SendTouchRelease() { SendFrame(kMsgTouch, nullptr, 0); }

private:
    enum State : uint8_t { kWaitSof, kHaveSof, kData, kWaitCksum };

    std::mutex state_mtx_;
    State    state_         = kWaitSof;
    uint8_t  rx_id_         = 0;
    uint8_t  rx_len_        = 0;
    uint8_t  rx_count_      = 0;
    uint8_t  rx_buf_[16]    = {};

    void Push(uint8_t b) { emu_.Get<Sa1110Sp1Uart>().PushRxByte(b); }

    void SendFrame(uint8_t msg_id, const uint8_t* data, uint8_t len) {
        const uint8_t hdr = static_cast<uint8_t>(
            ((msg_id & 0x0Fu) << 4) | (len & 0x0Fu));
        uint8_t cksum = hdr;
        Push(kSof);
        Push(hdr);
        for (uint8_t i = 0; i < len; ++i) {
            Push(data[i]);
            cksum = static_cast<uint8_t>(cksum + data[i]);
        }
        Push(cksum);
    }

    void OnTxByte(uint8_t b) {
        std::lock_guard<std::mutex> lk(state_mtx_);
        switch (state_) {
            case kWaitSof:
                if (b == kSof) state_ = kHaveSof;
                break;
            case kHaveSof:
                rx_id_    = (b >> 4) & 0x0Fu;
                rx_len_   = b & 0x0Fu;
                rx_count_ = 0;
                state_    = (rx_len_ == 0) ? kWaitCksum : kData;
                break;
            case kData:
                if (rx_count_ < sizeof(rx_buf_)) rx_buf_[rx_count_] = b;
                ++rx_count_;
                if (rx_count_ >= rx_len_) state_ = kWaitCksum;
                break;
            case kWaitCksum:
                RespondTo(rx_id_, rx_buf_, rx_count_);
                state_ = kWaitSof;
                break;
        }
    }

    void RespondTo(uint8_t id, const uint8_t* /*req*/, uint8_t /*req_len*/) {
        switch (id) {
            case kMsgVersion: {
                const uint8_t v[4] = { '1', '.', '7', '7' };
                SendFrame(kMsgVersion, v, 4);
                break;
            }
            case kMsgEepromRd: {
                const uint8_t v[2] = { 0xFFu, 0xFFu };
                SendFrame(kMsgEepromRd, v, 2);
                break;
            }
            case kMsgBattery: {
                const uint8_t v[4] = { 0x01u, 0x00u, 0x0Fu, 0x01u };
                SendFrame(kMsgBattery, v, 4);
                break;
            }
            default:
                SendFrame(id, nullptr, 0);
                break;
        }
    }
};

static uint16_t MapAxis(int v, int v_max, uint16_t adc_lo, uint16_t adc_hi) {
    if (v <= 0)     return adc_lo;
    if (v >= v_max) return adc_hi;
    const uint32_t span = adc_hi - adc_lo;
    return static_cast<uint16_t>(
        adc_lo + (uint32_t)v * span / (uint32_t)v_max);
}

class Ipaq3650Touch : public TouchInput {
public:
    using TouchInput::TouchInput;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardDetector>();
        return bd && bd->GetBoard() == Board::Ipaq3650;
    }

    void OnReady() override {
        sampler_ = std::thread([this] { SamplerLoop(); });
    }

    ~Ipaq3650Touch() override {
        {
            std::lock_guard<std::mutex> lk(mtx_);
            stop_ = true;
        }
        cv_.notify_all();
        if (sampler_.joinable()) sampler_.join();
    }

    void OnPenDown(int x, int y) override {
        {
            std::lock_guard<std::mutex> lk(mtx_);
            last_x_   = x;
            last_y_   = y;
            pen_down_ = true;
        }
        cv_.notify_all();
    }
    void OnPenMove(int x, int y) override {
        std::lock_guard<std::mutex> lk(mtx_);
        if (!pen_down_) return;
        last_x_ = x;
        last_y_ = y;
    }
    void OnPenUp(int /*x*/, int /*y*/) override {
        {
            std::lock_guard<std::mutex> lk(mtx_);
            if (!pen_down_) return;
            pen_down_ = false;
        }
        cv_.notify_all();
    }
    void OnCaptureLost() override { OnPenUp(0, 0); }

private:
    std::mutex              mtx_;
    std::condition_variable cv_;
    std::thread             sampler_;
    bool                    stop_     = false;
    bool                    pen_down_ = false;
    int                     last_x_   = 0;
    int                     last_y_   = 0;

    void EmitPress(int x_host, int y_host) {
        auto&     hc = emu_.Get<HostCanvas>();
        const int w = (int)hc.GuestSurfaceWidth ();
        const int h = (int)hc.GuestSurfaceHeight();
        const uint16_t adc_x = MapAxis(x_host, w - 1, kAdcXMin, kAdcXMax);
        const uint16_t adc_y = MapAxis(y_host, h - 1, kAdcYMin, kAdcYMax);
        emu_.Get<Ipaq3650MicroP>().SendTouchPress(adc_x, adc_y);
    }

    void SamplerLoop() {
        std::unique_lock<std::mutex> lk(mtx_);
        bool was_down = false;
        while (!stop_) {
            if (pen_down_) {
                const int x = last_x_;
                const int y = last_y_;
                lk.unlock();
                EmitPress(x, y);
                lk.lock();
                was_down = true;
                cv_.wait_for(lk, kSamplePeriod,
                             [&] { return stop_ || !pen_down_; });
            } else {
                if (was_down) {
                    was_down = false;
                    lk.unlock();
                    emu_.Get<Ipaq3650MicroP>().SendTouchRelease();
                    lk.lock();
                }
                cv_.wait(lk, [&] { return stop_ || pen_down_; });
            }
        }
        if (was_down) {
            lk.unlock();
            emu_.Get<Ipaq3650MicroP>().SendTouchRelease();
        }
    }
};

}  /* namespace */

REGISTER_SERVICE(Ipaq3650MicroP);
REGISTER_SERVICE_AS(Ipaq3650Touch, TouchInput);
