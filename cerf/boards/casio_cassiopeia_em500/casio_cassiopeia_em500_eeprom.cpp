#include "casio_cassiopeia_em500_eeprom.h"

#include "../../state/state_stream.h"

namespace {

constexpr uint32_t kOffCsA100  = 0xA100u;
constexpr uint32_t kOffClkA104 = 0xA104u;
constexpr uint32_t kOffDiA108  = 0xA108u;
constexpr uint32_t kOffCtrlA110 = 0xA110u;
/* eeprom.dll DO word sub_F219D4 @0xF219D4 (lw base+0x14) via sub_F21700 /
   sub_F215B0; erased 93Cxx = 0xFFFF; gwes.exe E2pRead consumer @0x74DD6 (bnez
   -> defaults), @0x74DE0 (byte<0x7F), @0x74E02 (byte<0xA2) default on 0xFF. */
constexpr uint32_t kOffDoA114 = 0xA114u;
constexpr uint32_t kBlankWord = 0xFFFFu;
constexpr uint32_t kOffCtrlA118 = 0xA118u;
/* eeprom.dll @0xF219FC sw 0, base+0x1C (companion 0xA11C). */
constexpr uint32_t kOffA11C = 0xA11Cu;

}  /* namespace */

bool CasioCassiopeiaEm500Eeprom::TryReadWord(uint32_t off, uint32_t& out) {
    switch (off) {
        case kOffCtrlA110: out = ctrl_a110_; return true;
        case kOffCtrlA118: out = ctrl_a118_; return true;
        case kOffDoA114:   out = kBlankWord; return true;
        default: return false;
    }
}

bool CasioCassiopeiaEm500Eeprom::TryWriteWord(uint32_t off, uint32_t value) {
    switch (off) {
        case kOffCtrlA110: ctrl_a110_ = value; return true;
        case kOffCtrlA118: ctrl_a118_ = value; return true;
        case kOffCsA100:
        case kOffClkA104:
        case kOffDiA108:
        case kOffA11C: return true;
        default: return false;
    }
}

void CasioCassiopeiaEm500Eeprom::SaveState(StateWriter& w) const {
    w.Write("ctrl_a110", ctrl_a110_);
    w.Write("ctrl_a118", ctrl_a118_);
}

void CasioCassiopeiaEm500Eeprom::RestoreState(StateReader& r) {
    r.Read("ctrl_a110", ctrl_a110_);
    r.Read("ctrl_a118", ctrl_a118_);
}
