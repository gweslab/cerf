#include "vr41xx_piu_converter.h"

#include <optional>

#include "../../core/cerf_emulator.h"
#include "../../state/state_stream.h"
#include "vr41xx_cmu.h"
#include "vr41xx_piu_panel.h"
#include "vr41xx_piu_regs.h"

using namespace cerf_vr41xx_piu_detail;

namespace {

/* Page-buffer slots, from PIUPB00REG at piu2_base (VR4121 UM Table 20-1 == VR4102 UM
   Table 19-1): PIUPBn0-3 at +0x00/02/04/06 (page 0) and +0x08/0A/0C/0E (page 1),
   PIUPB04REG at +0x1C and PIUPB14REG at +0x1E. */
bool PageBufferSlot(uint32_t off, int* page, int* idx) {
    switch (off) {
        case 0x00: *page = 0; *idx = 0; return true;
        case 0x02: *page = 0; *idx = 1; return true;
        case 0x04: *page = 0; *idx = 2; return true;
        case 0x06: *page = 0; *idx = 3; return true;
        case 0x1C: *page = 0; *idx = 4; return true;
        case 0x08: *page = 1; *idx = 0; return true;
        case 0x0A: *page = 1; *idx = 1; return true;
        case 0x0C: *page = 1; *idx = 2; return true;
        case 0x0E: *page = 1; *idx = 3; return true;
        case 0x1E: *page = 1; *idx = 4; return true;
        default:   return false;
    }
}

}

int Vr41xxPiuConverter::ConvertCoordinates(uint16_t pos_x, uint16_t pos_y) {
    emu_.Get<Vr41xxCmu>().RequireTclock(kCmuMskPiu, "PIU coordinate sample");
    const int page = next_page_;
    uint16_t (&buf)[5] = page_buf_[page];
    const uint16_t x_rise = static_cast<uint16_t>(pos_x & 0x3FFu);
    const uint16_t x_fall = static_cast<uint16_t>((kAdcMax - pos_x) & 0x3FFu);
    const uint16_t y_rise = static_cast<uint16_t>(pos_y & 0x3FFu);
    const uint16_t y_fall = static_cast<uint16_t>((kAdcMax - pos_y) & 0x3FFu);
    buf[0] = kValid | x_rise;
    buf[1] = kValid | x_fall;
    buf[2] = kValid | y_rise;
    buf[3] = kValid | y_fall;
    const std::optional<uint16_t> z = emu_.Get<Vr41xxPiuPanel>().PressureSample();
    buf[4] = z ? static_cast<uint16_t>(kValid | (*z & 0x3FFu)) : 0u;
    next_page_ ^= 1;
    return page;
}

bool Vr41xxPiuConverter::ConvertCommand(uint16_t cmd, uint16_t pos_x, uint16_t pos_y) {
    emu_.Get<Vr41xxCmu>().RequireTclock(kCmuMskPiu, "PIU command scan");
    const std::optional<uint16_t> val = emu_.Get<Vr41xxPiuPanel>().ConvertCommandPort(
        static_cast<uint16_t>(cmd & 0x000Fu), pos_x, pos_y);
    adbuf_[0] = val ? static_cast<uint16_t>(kValid | (*val & 0x3FFu)) : 0u;
    return val.has_value();
}

/* Buffer slot n's port = (TPPSCAN?0:4)+n; PIUAMSKREG bit index = that port (VR4121 UM
   Table 20-5 + 20.3.7, VR4102 UM Table 19-5 + 19.3.7). */
bool Vr41xxPiuConverter::ScanAdPorts(uint16_t ascn, uint16_t amsk) {
    emu_.Get<Vr41xxCmu>().RequireTclock(kCmuMskPiu, "PIU A/D port scan");
    const uint16_t port_base = (ascn & kTppScan) ? 0u : 4u;
    bool any_valid = false;
    for (uint16_t slot = 0; slot < 4u; ++slot) {
        const uint16_t port = port_base + slot;
        if (amsk & (1u << port)) { adbuf_[slot] = 0; continue; }
        const std::optional<uint16_t> v = emu_.Get<Vr41xxPiuPanel>().AdPortScanSample(port);
        if (v) { adbuf_[slot] = static_cast<uint16_t>(kValid | (*v & 0x3FFu)); any_valid = true; }
        else   { adbuf_[slot] = 0; }
    }
    return any_valid;
}

void Vr41xxPiuConverter::InvalidatePage(int page) {
    for (uint16_t& b : page_buf_[page]) b &= ~kValid;
}

void Vr41xxPiuConverter::InvalidateAdBuffer() {
    for (uint16_t& b : adbuf_) b &= ~kValid;
}

/* PIUABnREG holds ADPortScan data in AB0-3 and CMDScanDATA in AB0 (VR4121 UM Table 20-5,
   VR4102 UM Table 19-5). */
bool Vr41xxPiuConverter::ReadBuffer(uint32_t off, uint16_t* value) const {
    if (off == kOffAb0 || off == kOffAb1 || off == kOffAb2 || off == kOffAb3) {
        *value = adbuf_[(off - kOffAb0) / 2u];
        return true;
    }
    int page = 0, idx = 0;
    if (!PageBufferSlot(off, &page, &idx)) return false;
    *value = page_buf_[page][idx];
    return true;
}

/* PIUPBnmREG D15 VALID + D9:0 PADDATA are R/W, D14:10 RFU "write 0 / read 0" (VR4121 UM
   20.3.9, VR4102 UM 19.3.9); casio_toricomail_ce212 touch.dll sub_1370AB0 masks each page
   buffer to 10 bits and writes it back while recovering the coordinate. */
bool Vr41xxPiuConverter::WriteBuffer(uint32_t off, uint16_t value) {
    int page = 0, idx = 0;
    if (!PageBufferSlot(off, &page, &idx)) return false;
    page_buf_[page][idx] = value & 0x83FFu;
    return true;
}

void Vr41xxPiuConverter::Reset() {
    for (auto& pg : page_buf_) for (uint16_t& b : pg) b = 0;
    next_page_ = 0;
    for (uint16_t& b : adbuf_) b = 0;
}

void Vr41xxPiuConverter::Save(StateWriter& w) const {
    for (auto& pg : page_buf_) for (uint16_t b : pg) w.Write("pg", b);
    w.Write("next_page", next_page_);
    for (uint16_t b : adbuf_) w.Write("adbuf", b);
}

void Vr41xxPiuConverter::Restore(StateReader& r) {
    for (auto& pg : page_buf_) for (uint16_t& b : pg) r.Read("pg", b);
    r.Read("next_page", next_page_);
    for (uint16_t& b : adbuf_) r.Read("adbuf", b);
}
