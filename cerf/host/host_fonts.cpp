#include "host_fonts.h"

#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "host_resource.h"

REGISTER_SERVICE(HostFonts);

namespace {

constexpr wchar_t kUiFace[]       = L"IBM Plex Sans";
constexpr wchar_t kMonoFace[]     = L"IBM Plex Mono";
constexpr wchar_t kUiFallback[]   = L"Segoe UI";
constexpr wchar_t kMonoFallback[] = L"Fixedsys";

}

void HostFonts::OnReady() {
    const bool ui_regular = AddResourceFace(L"FONT_PLEX_SANS");
    const bool ui_bold    = AddResourceFace(L"FONT_PLEX_SANS_BOLD");
    ui_ok_   = ui_regular && ui_bold;
    mono_ok_ = AddResourceFace(L"FONT_PLEX_MONO_BOLD");

    if (!ui_ok_)
        LOG(Caution, "HostFonts: '%ls' unavailable, falling back to '%ls'\n",
            kUiFace, kUiFallback);
    if (!mono_ok_)
        LOG(Caution, "HostFonts: '%ls' unavailable, falling back to '%ls'\n",
            kMonoFace, kMonoFallback);
}

void HostFonts::OnShutdown() {
    for (HANDLE h : faces_) RemoveFontMemResourceEx(h);
    faces_.clear();
    ui_ok_ = mono_ok_ = false;
}

bool HostFonts::AddResourceFace(const wchar_t* resource_name) {
    std::span<const uint8_t> bytes =
        emu_.Get<HostResource>().Bytes(resource_name);
    if (bytes.empty()) return false;

    DWORD  installed = 0;
    HANDLE h = AddFontMemResourceEx(const_cast<uint8_t*>(bytes.data()),
                                    (DWORD)bytes.size(), nullptr, &installed);
    if (!h || installed == 0) return false;

    faces_.push_back(h);
    return true;
}

const wchar_t* HostFonts::UiFace() const {
    return ui_ok_ ? kUiFace : kUiFallback;
}

const wchar_t* HostFonts::MonoFace() const {
    return mono_ok_ ? kMonoFace : kMonoFallback;
}
