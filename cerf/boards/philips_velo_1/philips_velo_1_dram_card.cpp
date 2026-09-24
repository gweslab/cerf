#include "../../socs/pr31x00/pr31x00_mfio_slave.h"

#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../socs/pr31x00/pr31x00_io.h"
#include "../../state/state_stream.h"
#include "../board_context.h"
#include "philips_velo_1_id.h"

#include <array>
#include <cstdint>

namespace {

/* philips_velo_1_ce1 nk.exe sub_9F423CF0 @0x9F423CF0 bit-bangs the Miniature Card ID
   EEPROM on MFIO18 (SCL, 0x40000) and MFIO20 (SDA, 0x100000) for slot 1, addressing it
   with the control bytes 0xA0 (write) and 0xA1 (read) - device address 0x50 - and
   reading 256 bytes from word address 0 (sub_9F4242EC @0x9F4242EC). */
constexpr uint32_t kSclPin = 18;
constexpr uint32_t kSdaPin = 20;
constexpr uint32_t kScl    = 1u << kSclPin;
constexpr uint32_t kSda    = 1u << kSdaPin;

constexpr uint8_t kDeviceAddress = 0x50u;
constexpr size_t  kIdRomBytes    = 256u;

/* philips_velo_1_ce1 nk.exe sub_9F42453C @0x9F42453C reads the ID EEPROM as 0x40-byte
   tuples - header at 0x40 and at 0x80, geometry block at +0x20 - and abandons the card
   unless [16] holds 0x99, [59] is non-zero and [64] holds 2. */
constexpr uint8_t kSignature     = 0x99u;
constexpr uint8_t kTupleCount    = 1u;
constexpr uint8_t kTupleType     = 2u;

/* [67] size, unit <7:6>=00 -> ((n & 0x3F) + 1) Mbyte, published to MEMORY[0x80009F88]
   and returned as the DRAM BANK1 extent (philips_velo_1_ce1 nk.exe sub_9F42453C). */
constexpr uint8_t kSizeByte      = 0x0Fu;

/* [96] row and [97] column address bits, matched as a pair against asc_9F40A904
   @0x9F40A904 by philips_velo_1_ce1 nk.exe sub_9F42448C @0x9F42448C for the MEMCONFIG0
   ROWSEL1 value; (12, 11) is the largest of its 9 entries. A pair absent from that
   table makes sub_9F42453C return 0 and the bank is never mapped. */
constexpr uint8_t kRowBits       = 12u;
constexpr uint8_t kColumnBits    = 11u;

/* [98] <0> device present; <1> would select ENBANK1HDRAM, MEM_CONFIG4<31> (TMPR3911
   §4.7.5), which this DRAM part is not. */
constexpr uint8_t kDevicePresent = 0x01u;

/* [101] refresh: philips_velo_1_ce1 nk.exe sub_9F42436C @0x9F42436C programs RFSHVAL1,
   MEM_CONFIG4<13:8>, with (1000*[101] + 1000) / (1 << [96]) / 31 - 1; 127 yields 0,
   which TMPR3911 §4.7.5 defines as 15.26 us - 4096 rows in 62.5 ms. */
constexpr uint8_t kRefreshByte   = 127u;

enum class Phase : uint8_t { Idle, Control, WordAddr, WriteData, Transmit };

class PhilipsVelo1DramCard : public Pr31x00MfioSlave {
public:
    using Pr31x00MfioSlave::Pr31x00MfioSlave;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::PhilipsVelo1;
    }

    void OnReady() override {
        id_rom_.fill(0);
        id_rom_[16]  = kSignature;
        id_rom_[59]  = kTupleCount;
        id_rom_[64]  = kTupleType;
        id_rom_[67]  = kSizeByte;
        id_rom_[96]  = kRowBits;
        id_rom_[97]  = kColumnBits;
        id_rom_[98]  = kDevicePresent;
        id_rom_[101] = kRefreshByte;
        DriveSda(true);
    }

    void OnMfioOut(uint32_t mfio_dout, uint32_t out_mask) override {
        const bool scl = (out_mask & kScl) == 0u || (mfio_dout & kScl) != 0u;
        const bool sda = (out_mask & kSda) == 0u || (mfio_dout & kSda) != 0u;
        const bool prev_scl = scl_;
        const bool prev_sda = sda_;
        scl_ = scl;
        sda_ = sda;

        if (scl && prev_scl && sda != prev_sda) {
            if (sda) Stop();
            else     Start();
            return;
        }
        if (scl && !prev_scl)      ClockRise();
        else if (!scl && prev_scl) ClockFall();
    }

    void SaveState(StateWriter& w) override {
        w.Write("phase", static_cast<uint8_t>(phase_));
        w.Write("shift", shift_); w.Write("bit", bit_); w.Write("addr", addr_);
        w.Write("selected", static_cast<uint8_t>(selected_));
        w.Write("read", static_cast<uint8_t>(read_));
        w.Write("in_ack", static_cast<uint8_t>(in_ack_));
        w.Write("scl", static_cast<uint8_t>(scl_));
        w.Write("sda", static_cast<uint8_t>(sda_));
    }

    void RestoreState(StateReader& r) override {
        uint8_t v = 0;
        r.Read("phase", v); phase_ = static_cast<Phase>(v);
        r.Read("shift", shift_); r.Read("bit", bit_); r.Read("addr", addr_);
        r.Read("selected", v); selected_ = v != 0;
        r.Read("read", v); read_     = v != 0;
        r.Read("in_ack", v); in_ack_   = v != 0;
        r.Read("scl", v); scl_      = v != 0;
        r.Read("sda", v); sda_      = v != 0;
    }

private:
    void DriveSda(bool level) {
        emu_.Get<Pr31x00Io>().DriveMfioInput(kSdaPin, level);
    }

    void Start() {
        phase_    = Phase::Control;
        shift_    = 0;
        bit_      = 0;
        in_ack_   = false;
        selected_ = false;
        DriveSda(true);
    }

    void Stop() {
        phase_  = Phase::Idle;
        bit_    = 0;
        in_ack_ = false;
        DriveSda(true);
    }

    void ClockRise() {
        if (phase_ == Phase::Idle) return;
        if (bit_ < 8u) {
            if (phase_ != Phase::Transmit) {
                shift_ = static_cast<uint8_t>((shift_ << 1) | (sda_ ? 1u : 0u));
            }
            ++bit_;
            return;
        }
        if (phase_ == Phase::Transmit && sda_) Stop();
    }

    void ClockFall() {
        if (phase_ == Phase::Idle) return;

        if (in_ack_) {
            in_ack_ = false;
            bit_    = 0;
            AdvanceAfterAck();
            return;
        }

        if (bit_ == 8u) {
            in_ack_ = true;
            if (phase_ == Phase::Transmit) DriveSda(true);
            else                           DriveSda(!AcknowledgeByte());
            return;
        }

        if (phase_ == Phase::Transmit) {
            DriveSda((shift_ & 0x80u) != 0u);
            shift_ = static_cast<uint8_t>(shift_ << 1);
        }
    }

    bool AcknowledgeByte() {
        switch (phase_) {
            case Phase::Control:
                selected_ = (shift_ >> 1) == kDeviceAddress;
                read_     = (shift_ & 1u) != 0u;
                return selected_;
            case Phase::WordAddr:
                addr_ = shift_;
                return true;
            default:
                emu_.Get<Fatal>().Die("Philips Velo 1 DRAM card: ID EEPROM write of "
                                      "0x%02X to word 0x%02X", shift_, addr_);
        }
    }

    void AdvanceAfterAck() {
        switch (phase_) {
            case Phase::Control:
                if (!selected_) { Stop(); return; }
                if (read_) { phase_ = Phase::Transmit; LoadTxByte(); }
                else       { phase_ = Phase::WordAddr; DriveSda(true); }
                return;
            case Phase::WordAddr:
                phase_ = Phase::WriteData;
                DriveSda(true);
                return;
            case Phase::Transmit:
                LoadTxByte();
                return;
            default:
                return;
        }
    }

    void LoadTxByte() {
        shift_ = id_rom_[addr_];
        addr_  = static_cast<uint8_t>(addr_ + 1u);
        DriveSda((shift_ & 0x80u) != 0u);
        shift_ = static_cast<uint8_t>(shift_ << 1);
    }

    std::array<uint8_t, kIdRomBytes> id_rom_{};

    Phase   phase_    = Phase::Idle;
    uint8_t shift_    = 0;
    uint8_t bit_      = 0;
    uint8_t addr_     = 0;
    bool    selected_ = false;
    bool    read_     = false;
    bool    in_ack_   = false;
    bool    scl_      = true;
    bool    sda_      = true;
};

}  /* namespace */

REGISTER_SERVICE_AS(PhilipsVelo1DramCard, Pr31x00MfioSlave);
