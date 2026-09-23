#include "jornada820_battery.h"

#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../host/host_widget_registry.h"
#include "../../socs/sa11xx/sa11xx_intc.h"
#include "../../socs/sa11xx/sa11xx_sp1_uart.h"
#include "../../state/emulation_freeze.h"
#include "../board_context.h"
#include "jornada_820_id.h"

#include <array>
#include <chrono>
#include <cstdint>

namespace {

constexpr uint8_t kFrameStart = 0xE0u;
constexpr uint8_t kFrameEnd   = 0xE1u;
constexpr auto    kStreamPeriod = std::chrono::milliseconds(1000);

/* SP1 UART = SA-1100 INTC source 15. The kernel sets ICMR bit15 only when hplib
   registers SYSINTR 34 (OAL OEMInterruptEnable sub_8005A858 case 0x22). Pushing
   RX bytes before that asserts an undrained source and storms the OAL. */
constexpr uint32_t kSp1IntcMask = 1u << 15;

/* gwes sub_8FB14 derives power status from these byte indices (hplib copies the
   packet to gauge config[0..13]): [2]=BatteryLifePercent; [3,4]=capacity LE,
   minutes=capacity-5 drives BatteryFlag + BatteryLifeTime; [12] bit2=charging.
   Minutes mapped 1:1 to percent (host models percent only); bytes 7-11 unused. */
std::array<uint8_t, 14> BuildPacket(int percent, bool on_battery) {
    if (percent < 0)   percent = 0;
    if (percent > 100) percent = 100;
    const uint16_t cap = static_cast<uint16_t>(percent + 5);
    std::array<uint8_t, 14> p{};
    p[0]  = kFrameStart;
    p[2]  = static_cast<uint8_t>(percent);
    cerf::le::Put16(p.data() + 3, cap);
    p[12] = on_battery ? 0x00u : 0x04u;
    p[13] = kFrameEnd;
    return p;
}

}  /* namespace */

bool Jornada820Battery::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::Jornada820;
}

void Jornada820Battery::OnReady() {
    battery_.SetChangeHandler([this] {
        {
            std::lock_guard<std::mutex> lk(mtx_);
            dirty_ = true;
        }
        cv_.notify_all();
    });
    emu_.Get<HostWidgetRegistry>().Register(&battery_);
    thread_ = std::thread([this] { StreamLoop(); });
}

void Jornada820Battery::OnShutdown() {
    {
        std::lock_guard<std::mutex> lk(mtx_);
        stop_ = true;
    }
    cv_.notify_all();
    if (thread_.joinable()) thread_.join();
}

void Jornada820Battery::StreamLoop() {
    auto& sp1    = emu_.Get<Sa11xxSp1Uart>();
    auto& intc   = emu_.Get<Sa11xxIntc>();
    auto& freeze = emu_.Get<EmulationFreeze>();
#if CERF_DEV_MODE
    bool logged = false;
#endif
    /* Widget getters lock the widget mutex; the change handler locks mtx_ while
       the UI thread holds the widget mutex. Read the widget WITHOUT mtx_ held to
       keep the two locks unnested. */
    for (;;) {
        {
            auto frozen = freeze.WorkerSection();
            if ((intc.GetIcmr() & kSp1IntcMask) != 0) {
#if CERF_DEV_MODE
                if (!logged) {
                    LOG(SocUart, "[J820BATT] SP1 IRQ unmasked (hplib ready) - streaming battery\n");
                    logged = true;
                }
#endif
                const auto pkt = BuildPacket(battery_.FillPercent(), battery_.IsOnBattery());
                sp1.PushRxBurst(pkt.data(), pkt.size());
            }
        }

        std::unique_lock<std::mutex> lk(mtx_);
        if (stop_) return;
        cv_.wait_for(lk, kStreamPeriod, [this] { return stop_ || dirty_; });
        if (stop_) return;
        dirty_ = false;
    }
}

REGISTER_SERVICE(Jornada820Battery);
