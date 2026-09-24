#include "../../core/service.h"

#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../host/battery_widget.h"
#include "../../host/host_widget_registry.h"
#include "../../socs/pxa255/pxa255_gpio.h"
#include "../../state/state_stream.h"
#include "../board_context.h"
#include "falcon_4220_id.h"

#include <cstdint>

namespace {

/* Falcon main battery: a 1-Wire smart battery the OAL bit-bangs over GPIO73
   (nk.exe sub_800F7F00 clocks a bit out, sub_800F7FBC reads one in). battdrvr
   reads cmd 0x0C = 14-byte telemetry (sub_17F1EF4), cmd 0x20 = 32-byte calib
   (sub_17F2384). Unmodelled GPIO73 = 0% = the power monitor force-suspends. */

/* Slot framing without timing: a READ slot samples GPLR2 (DriveGplr fires) after
   releasing the pin; a WRITE slot does not. The data read follows 2 command bytes
   = 16 write bits (sub_800F7DCC 0x69+cmd); type-detect/presence use fewer. */
constexpr uint32_t kGpdr2     = 0x14u;   /* PXA255 GPIO GPDR2 (bank2 direction). */
constexpr uint32_t kPinBit    = 0x200u;  /* bank2 bit9 = GPIO73. */
constexpr uint32_t kDataWrites = 16u;    /* 0x69 + command byte. */

/* Synthetic self-consistent battery (RE-only; the guest decode is the spec).
   percent=round(100*(a4-v13)/(v10-v13)) (sub_17F2654); v10=(calib[0]<<8)|calib[1]
   (sub_17F25A0), v13=210 with zero calib deltas; a4 from resp[4],resp[5]
   (sub_17F1EF4). Round-trips widget fill 0..100 -> guest % 0..100. */
constexpr uint32_t kVFull  = 4200u;      /* calib base 0x1068. */
constexpr uint32_t kVEmpty = 210u;

class FalconBattery : public Service, public Pxa255GpioSerialSlave {
public:
    explicit FalconBattery(CerfEmulator& e) : Service(e), battery_(e) {}

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::Falcon4220;
    }

    void OnReady() override {
        emu_.Get<HostWidgetRegistry>().Register(&battery_);
        emu_.Get<Pxa255Gpio>().SetSerialSlave(this);
    }

    /* GPIO write - only GPDR2 direction transitions on GPIO73 frame the bits. */
    void OnGuestWrite(uint32_t off, uint32_t value) override {
        if (off != kGpdr2) return;
        const bool out = (value & kPinBit) != 0u;
        if (out && !dir_out_) {              /* input -> output: a new bit begins */
            if (armed_) {                    /* prior slot released, never read => WRITE */
                if (last_was_read_) {        /* a read-run just ended => new command */
                    write_run_ = 0;
                    serving_   = false;
                    resp_bit_  = 0;
                    last_was_read_ = false;
                }
                ++write_run_;
                armed_ = false;
            }
            dir_out_ = true;
        } else if (!out && dir_out_) {       /* output -> input: guest will sample */
            armed_   = true;
            dir_out_ = false;
        }
    }

    /* GPLR read - a read slot. Drive GPIO73 with the next response bit (LSB-first,
       sub_800F80AC), 0 otherwise (type-detect/presence read low = present, type 1). */
    uint32_t DriveGplr(uint32_t bank) override {
        if (bank != 2u || !armed_) return 0u;
        armed_         = false;
        last_was_read_ = true;
        if (write_run_ < kDataWrites) return 0u;
        if (!serving_) {
            serving_  = true;
            resp_bit_ = 0;
            BuildResponse();
        }
        uint32_t bit = 0u;
        if (resp_bit_ < resp_len_ * 8u) {
            bit = (resp_[resp_bit_ >> 3] >> (resp_bit_ & 7u)) & 1u;
            ++resp_bit_;
        }
        return bit ? kPinBit : 0u;
    }

    /* Serialize the 1-Wire slot FSM so a save mid-bit-bang restores mid-bit-bang
       (forwarded by Pxa255Gpio::SaveState/RestoreState). */
    void SaveState(StateWriter& w) override {
        w.Write<uint8_t>("dir_out", dir_out_ ? 1u : 0u);
        w.Write<uint8_t>("armed", armed_ ? 1u : 0u);
        w.Write<uint8_t>("last_was_read", last_was_read_ ? 1u : 0u);
        w.Write<uint8_t>("serving", serving_ ? 1u : 0u);
        w.Write("write_run", write_run_);
        w.Write("resp_bit", resp_bit_);
        w.Write("resp_len", resp_len_);
        w.WriteBytes("resp", resp_, sizeof(resp_));
    }

    void RestoreState(StateReader& r) override {
        uint8_t b = 0;
        r.Read("dir_out", b); dir_out_       = (b != 0);
        r.Read("armed", b); armed_         = (b != 0);
        r.Read("last_was_read", b); last_was_read_ = (b != 0);
        r.Read("serving", b); serving_       = (b != 0);
        r.Read("write_run", write_run_);
        r.Read("resp_bit", resp_bit_);
        r.Read("resp_len", resp_len_);
        r.ReadBytes("resp", resp_, sizeof(resp_));
    }

private:
    /* One self-consistent block for EVERY data read: the slave can't decode which
       command (calib cmd 0x20 vs telemetry cmd 0x0C), so both must read healthy.
       b[0,1]=0x1068 = calib full ref v10 (sub_17F25A0) + telemetry voltage; b[4,5]
       = telemetry charge a4 (sub_17F1EF4); zero deltas keep empty v13=210. */
    void BuildResponse() {
        for (auto& b : resp_) b = 0u;
        int fill = battery_.FillPercent();
        if (fill < 0) fill = 0;
        if (fill > 100) fill = 100;
        const uint32_t a4  = kVEmpty + static_cast<uint32_t>(fill) * (kVFull - kVEmpty) / 100u;
        const uint32_t enc = a4 << 2;
        cerf::be::Put16(resp_ + 0, static_cast<uint16_t>(kVFull));
        cerf::be::Put16(resp_ + 4, static_cast<uint16_t>(enc & 0x7FFFu));
        resp_len_ = 32u;
    }

    BatteryWidget battery_;

    /* Bit-bang slot state (JIT thread only, serialized by the GPIO mutex). */
    bool     dir_out_       = false;
    bool     armed_         = false;
    bool     last_was_read_ = false;
    bool     serving_       = false;
    uint32_t write_run_     = 0;
    uint32_t resp_bit_      = 0;
    uint32_t resp_len_      = 0;
    uint8_t  resp_[32]      = {};
};

}  /* namespace */

REGISTER_SERVICE(FalconBattery);
