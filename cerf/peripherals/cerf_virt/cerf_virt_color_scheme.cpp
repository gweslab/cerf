#include "cerf_virt_color_scheme.h"
#include "cerf_virt_color_scheme_regs.h"

#include "../peripheral_dispatcher.h"
#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../core/log.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../state/state_stream.h"

#include <string>

REGISTER_SERVICE(CerfVirtColorScheme);

namespace {

const uint32_t kHpc3[27] = {
    0x00DEDEDE, 0x00808000, 0x00800000, 0x00808080, 0x00C0C0C0,
    0x00FFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00FFFFFF,
    0x00C0C0C0, 0x00C0C0C0, 0x00808080, 0x00800000, 0x00FFFFFF,
    0x00C0C0C0, 0x00808080, 0x00808080, 0x00000000, 0x00C0C0C0,
    0x00FFFFFF, 0x00000000, 0x00DFDFDF, 0x00000000, 0x00FFFFFF,
    0x00C0C0C0, 0x00000000,
};

const uint32_t kCe2Grayscale[27] = {
    0x00C0C0C0, 0x00FFFFFF, 0x00000000, 0x00808080, 0x00FFFFFF,
    0x00FFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00FFFFFF,
    0x00C0C0C0, 0x00C0C0C0, 0x00808080, 0x00000000, 0x00FFFFFF,
    0x00C0C0C0, 0x00808080, 0x00808080, 0x00000000, 0x00FFFFFF,
    0x00C0C0C0, 0x00000000, 0x00FFFFFF, 0x00000000, 0x00FFFFFF,
    0x00FFFFFF, 0x00000000,
};

const uint32_t kHpc2000[27] = {
    0x00F1F4F5, 0x00A56E3A, 0x006A240A, 0x00808080, 0x00C8D0D4,
    0x00FFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00FFFFFF,
    0x00C8D0D4, 0x00C8D0D4, 0x00808080, 0x006A240A, 0x00FFFFFF,
    0x00C8D0D4, 0x007B8E97, 0x00808080, 0x00000000, 0x00C8D0D4,
    0x00F1F4F5, 0x00516066, 0x00E3E8EA, 0x00000000, 0x00FFFFFF,
    0x00C8D0D4, 0x00000000,
};

const uint32_t kCe4[27] = {
    0x00E0E0E0, 0x00A56E3A, 0x00800000, 0x00808080, 0x00C0C0C0,
    0x00FFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00FFFFFF,
    0x00C0C0C0, 0x00C0C0C0, 0x00808080, 0x00800000, 0x00FFFFFF,
    0x00C0C0C0, 0x00808080, 0x00808080, 0x00000000, 0x00C0C0C0,
    0x00FFFFFF, 0x00000000, 0x00DFDFDF, 0x00000000, 0x00FFFFFF,
    0x00C0C0C0, 0x00000000,
};

const uint32_t kWin2k[27] = {
    0x00C8D0D4, 0x00A56E3A, 0x006A240A, 0x00808080, 0x00C8D0D4,
    0x00FFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00FFFFFF,
    0x00C8D0D4, 0x00C8D0D4, 0x00808080, 0x006A240A, 0x00FFFFFF,
    0x00C8D0D4, 0x00808080, 0x00808080, 0x00000000, 0x00C8D0D4,
    0x00FFFFFF, 0x00404040, 0x00C8D0D4, 0x00000000, 0x00E1FFFF,
    0x00C8D0D4, 0x00800000,
};

const uint32_t kXp[27] = {
    0x00C8D0D4, 0x00A56E3A, 0x00E35400, 0x00DF967A, 0x00DEEBEF,
    0x00FFFFFF, 0x00000000, 0x00000000, 0x00000000, 0x00FFFFFF,
    0x00C0C0C0, 0x00C0C0C0, 0x00808080, 0x00C66931, 0x00FFFFFF,
    0x00DEEBEF, 0x009CAAAD, 0x00808080, 0x00000000, 0x00F8E4D8,
    0x00FFFFFF, 0x00636D73, 0x00FFFFFF, 0x00000000, 0x00E1FFFF,
    0x00DEEBEF, 0x00800000,
};

const uint32_t kVista[27] = {
    0x00C8C8C8, 0x007A5F2D, 0x00D1B499, 0x00DBCDBF, 0x00F0F0F0,
    0x00FFFFFF, 0x00646464, 0x00000000, 0x00000000, 0x00000000,
    0x00B4B4B4, 0x00FCF7F4, 0x00ABABAB, 0x00FF9933, 0x00FFFFFF,
    0x00F0F0F0, 0x00A0A0A0, 0x006D6D6D, 0x00000000, 0x00544E43,
    0x00FFFFFF, 0x00696969, 0x00E3E3E3, 0x00000000, 0x00E1FFFF,
    0x00F0F0F0, 0x00CC6600,
};

const uint32_t kWm5[29] = {
    0x00E9DCC9, 0x00CE8600, 0x00D39137, 0x00D5B68D, 0x00E9DCC9,
    0x00FFFFFF, 0x00000000, 0x007F4E0C, 0x00000000, 0x00FFFFFF,
    0x00990000, 0x00C0C0C0, 0x00FFFFFF, 0x00D39137, 0x00FFFFFF,
    0x00E9DCC9, 0x00808080, 0x00BFBFBF, 0x00000000, 0x00FFFFFF,
    0x00FFFFFF, 0x00000000, 0x00FFFFFF, 0x00000000, 0x00CCFFFF,
    0x00E9DCC9, 0x00000000, 0x00F69A4F, 0x00C0C0C0,
};

const uint32_t kWm6[29] = {
    0x00E9E7C9, 0x008C7100, 0x00D3C737, 0x00D5D08D, 0x00E9E7C9,
    0x00FFFFFF, 0x00000000, 0x007F760C, 0x00000000, 0x00FFFFFF,
    0x00990000, 0x00C0C0C0, 0x00FFFFFF, 0x00D3C737, 0x00FFFFFF,
    0x00E9E7C9, 0x00808080, 0x00BFBFBF, 0x00000000, 0x00FFFFFF,
    0x00FFFFFF, 0x00000000, 0x00FFFFFF, 0x00000000, 0x00CCFFFF,
    0x00E9E7C9, 0x00000000, 0x00F69A4F, 0x00C0C0C0,
};

const uint32_t kWm6Guava[29] = {
    0x00C9CBE9, 0x0021209C, 0x00373FD3, 0x008D91D5, 0x00C9CBE9,
    0x00FFFFFF, 0x00000000, 0x000C127F, 0x00000000, 0x00FFFFFF,
    0x00990000, 0x00C0C0C0, 0x00FFFFFF, 0x00373FD3, 0x00FFFFFF,
    0x00C9CBE9, 0x00808080, 0x00BFBFBF, 0x00000000, 0x00FFFFFF,
    0x00FFFFFF, 0x00000000, 0x00FFFFFF, 0x00000000, 0x00CCFFFF,
    0x00C9CBE9, 0x00000000, 0x00F69A4F, 0x00C0C0C0,
};

const uint32_t kWm6Green[29] = {
    0x00CBE9C9, 0x0000C75A, 0x003FD337, 0x0091D58D, 0x00CBE9C9,
    0x00FFFFFF, 0x00000000, 0x00127F0C, 0x00000000, 0x00FFFFFF,
    0x00990000, 0x00C0C0C0, 0x00FFFFFF, 0x003FD337, 0x00FFFFFF,
    0x00CBE9C9, 0x00808080, 0x00BFBFBF, 0x00000000, 0x00FFFFFF,
    0x00FFFFFF, 0x00000000, 0x00FFFFFF, 0x00000000, 0x00CCFFFF,
    0x00CBE9C9, 0x00000000, 0x00F69A4F, 0x00C0C0C0,
};

const uint32_t kWm65[29] = {
    0x00E9D2C9, 0x009C4931, 0x00D34B37, 0x00D5968D, 0x00E9CDC9,
    0x00FFFFFF, 0x00000000, 0x007F0C12, 0x00330709, 0x00E9C9CB,
    0x00990000, 0x00C0C0C0, 0x00FFFFFF, 0x00CF5E2D, 0x00FFFFFF,
    0x00E9CDC9, 0x00808080, 0x00999999, 0x00330709, 0x00E9C9CB,
    0x00FFFFFF, 0x00000000, 0x00FFFFFF, 0x00000000, 0x00CCFFFF,
    0x00E9CDC9, 0x00000000, 0x00F69A4F, 0x00C0C0C0,
};

struct SchemeTable { const uint32_t* data; uint32_t count; };

SchemeTable ResolveTable(const std::string& key) {
    if (key == "hpc3")          return { kHpc3,         27 };
    if (key == "ce2_grayscale") return { kCe2Grayscale, 27 };
    if (key == "hpc2000")       return { kHpc2000,      27 };
    if (key == "ce4")           return { kCe4,          27 };
    if (key == "win2k")         return { kWin2k,        27 };
    if (key == "xp")            return { kXp,           27 };
    if (key == "vista")         return { kVista,        27 };
    if (key == "wm5")           return { kWm5,          29 };
    if (key == "wm6")           return { kWm6,          29 };
    if (key == "wm6_green")     return { kWm6Green,     29 };
    if (key == "wm6_guava")     return { kWm6Guava,     29 };
    if (key == "wm65")          return { kWm65,         29 };
    return { nullptr, 0 };
}

}

bool CerfVirtColorScheme::ShouldRegister() {
    return emu_.Get<DeviceConfig>().guest_additions;
}

void CerfVirtColorScheme::OnReady() {
    ApplyFromConfig();
    emu_.Get<GuestCpuReset>().RegisterResetListener(
        [this](ResetLineKind) { ApplyFromConfig(); });
    emu_.Get<PeripheralDispatcher>().Register(this);
}

void CerfVirtColorScheme::ApplyFromConfig() {
    const std::string& key = emu_.Get<DeviceConfig>().guest_additions_color_scheme;
    count_   = 0;
    present_ = false;
    if (key.empty()) return;

    SchemeTable st = ResolveTable(key);
    if (!st.data) {
        LOG(GuestAdditions, "unknown --ga-color-scheme key '%s'", key.c_str());
        CerfFatalExit();
    }
    count_ = st.count;
    for (uint32_t i = 0; i < count_ && i < CerfVirt::kColorSchemeMax; ++i)
        entries_[i] = st.data[i];
    present_ = true;
    LOG(GuestAdditions, "color scheme override: '%s' published (%u entries)",
        key.c_str(), count_);
}

uint32_t CerfVirtColorScheme::MmioBase() const {
    return emu_.Get<BoardContext>().GuestAdditionsWindowBase() + CerfVirt::kColorSchemeOffset;
}
uint32_t CerfVirtColorScheme::MmioSize() const { return CerfVirt::kColorSchemeSize; }

uint32_t CerfVirtColorScheme::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off == CerfVirt::kCscPresent) return present_ ? CerfVirt::kCscMagic : 0u;
    if (off == CerfVirt::kCscCount)   return present_ ? count_ : 0u;
    if (off >= CerfVirt::kCscEntries) {
        const uint32_t idx = (off - CerfVirt::kCscEntries) >> 2u;
        if (idx < CerfVirt::kColorSchemeMax) return entries_[idx];
    }
    return 0u;
}

void CerfVirtColorScheme::WriteWord(uint32_t, uint32_t) {}

void CerfVirtColorScheme::SaveState(StateWriter& w) {
    w.Write<uint32_t>("present", present_ ? 1u : 0u);
    w.Write<uint32_t>("count", count_);
    for (uint32_t i = 0; i < CerfVirt::kColorSchemeMax; ++i) w.Write<uint32_t>("entries", entries_[i]);
}

void CerfVirtColorScheme::RestoreState(StateReader& r) {
    uint32_t v;
    r.Read("present", v); present_ = (v != 0u);
    r.Read("count", v); count_ = v;
    for (uint32_t i = 0; i < CerfVirt::kColorSchemeMax; ++i) { r.Read("entries", v); entries_[i] = v; }
}
