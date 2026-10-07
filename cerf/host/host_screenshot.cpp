#define NOMINMAX

#include "host_screenshot.h"

#include "../core/cerf_emulator.h"
#include "../core/cerf_paths.h"
#include "../core/device_config.h"
#include "../core/log.h"
#include "../core/string_utils.h"
#include "host_canvas.h"
#include "host_window.h"

#include <algorithm>
#include <string>
#include <vector>

#include <gdiplus.h>

REGISTER_SERVICE(HostScreenshot);

namespace {

int GetPngEncoderClsid(CLSID& clsid) {
    UINT num = 0, size = 0;
    Gdiplus::GetImageEncodersSize(&num, &size);
    if (size == 0) return -1;
    std::vector<uint8_t> buf(size);
    auto* codecs = reinterpret_cast<Gdiplus::ImageCodecInfo*>(buf.data());
    Gdiplus::GetImageEncoders(num, size, codecs);
    for (UINT i = 0; i < num; ++i) {
        if (wcscmp(codecs[i].MimeType, L"image/png") == 0) {
            clsid = codecs[i].Clsid;
            return (int)i;
        }
    }
    return -1;
}

std::wstring SanitizeForFilename(std::wstring w) {
    if (w.empty()) w = L"device";
    for (wchar_t& c : w) {
        if (c == L'\\' || c == L'/' || c == L':' || c == L'*' || c == L'?' ||
            c == L'"' || c == L'<' || c == L'>' || c == L'|')
            c = L'_';
    }
    return w;
}

std::wstring TimestampNow() {
    SYSTEMTIME st;
    GetLocalTime(&st);
    wchar_t buf[32];
    swprintf(buf, 32, L"%04u%02u%02u_%02u%02u%02u",
             st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
    return buf;
}

}  /* namespace */

void HostScreenshot::Save() {
    std::vector<uint32_t> px;
    uint32_t w = 0, h = 0;
    if (!emu_.Get<HostCanvas>().CaptureGuestSurface(px, w, h)) {
        LOG(Lcd, "HostScreenshot::Save: no guest frame to capture\n");
        return;
    }
    SavePixels(px, w, h,
               Utf8ToWide(emu_.Get<DeviceConfig>().device_name.c_str()));
}

void HostScreenshot::Copy() {
    std::vector<uint32_t> px;
    uint32_t w = 0, h = 0;
    if (!emu_.Get<HostCanvas>().CaptureGuestSurface(px, w, h)) {
        LOG(Lcd, "HostScreenshot::Copy: no guest frame to capture\n");
        return;
    }
    CopyPixels(px, w, h, emu_.Get<HostWindow>().Hwnd());
}

bool HostScreenshot::EncodePixels(const std::vector<uint32_t>& px, uint32_t w,
                                  uint32_t h, const std::wstring& path) {
    if (px.empty() || w == 0 || h == 0) return false;
    CLSID png;
    if (GetPngEncoderClsid(png) < 0) {
        LOG(Caution, "HostScreenshot: no PNG encoder available\n");
        return false;
    }
    Gdiplus::Bitmap bmp((INT)w, (INT)h, (INT)(w * 4),
                        PixelFormat32bppRGB,
                        reinterpret_cast<BYTE*>(const_cast<uint32_t*>(px.data())));
    const Gdiplus::Status st = bmp.Save(path.c_str(), &png, nullptr);
    if (st != Gdiplus::Ok) {
        LOG(Caution, "HostScreenshot: GDI+ Save failed (status=%d)\n", (int)st);
        return false;
    }
    return true;
}

void HostScreenshot::SaveGuestSurfaceTo(const std::wstring& path) {
    std::vector<uint32_t> px;
    uint32_t w = 0, h = 0;
    if (!emu_.Get<HostCanvas>().CaptureGuestSurface(px, w, h)) {
        LOG(Lcd, "HostScreenshot::SaveGuestSurfaceTo: no guest frame to capture\n");
        return;
    }
    if (EncodePixels(px, w, h, path))
        LOG(Lcd, "HostScreenshot::SaveGuestSurfaceTo: wrote %ux%u\n", w, h);
}

void HostScreenshot::SavePixels(const std::vector<uint32_t>& px, uint32_t w,
                                uint32_t h, const std::wstring& name_hint) {
    if (px.empty() || w == 0 || h == 0) return;

    const std::wstring dir = Utf8ToWide(GetCerfDir().c_str()) + L"screenshots\\";
    CreateDirectoryW(dir.c_str(), nullptr);  /* ok if it already exists */

    const std::wstring path =
        dir + SanitizeForFilename(name_hint) + L"_" + TimestampNow() + L".png";

    if (EncodePixels(px, w, h, path))
        LOG(Lcd, "HostScreenshot::SavePixels: wrote %ux%u screenshot\n", w, h);
}

void HostScreenshot::CopyPixels(const std::vector<uint32_t>& px, uint32_t w,
                                uint32_t h, HWND clipboard_owner) {
    if (px.empty() || w == 0 || h == 0) return;

    const size_t row_bytes = (size_t)w * 4u;
    const size_t total = sizeof(BITMAPINFOHEADER) + row_bytes * h;
    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, total);
    if (!hg) {
        LOG(Caution, "HostScreenshot::CopyPixels: GlobalAlloc failed\n");
        return;
    }
    auto* base = static_cast<uint8_t*>(GlobalLock(hg));
    auto* bih  = reinterpret_cast<BITMAPINFOHEADER*>(base);
    *bih = {};
    bih->biSize     = sizeof(BITMAPINFOHEADER);
    bih->biWidth    = (LONG)w;
    bih->biHeight   = (LONG)h;          /* positive => bottom-up */
    bih->biPlanes   = 1;
    bih->biBitCount = 32;
    bih->biCompression = BI_RGB;
    uint8_t* dst = base + sizeof(BITMAPINFOHEADER);
    for (uint32_t y = 0; y < h; ++y) {
        const uint8_t* src = reinterpret_cast<const uint8_t*>(px.data())
                           + (size_t)(h - 1 - y) * row_bytes;
        memcpy(dst + (size_t)y * row_bytes, src, row_bytes);
    }
    GlobalUnlock(hg);

    if (!OpenClipboard(clipboard_owner)) {
        LOG(Caution, "HostScreenshot::CopyPixels: OpenClipboard failed\n");
        GlobalFree(hg);
        return;
    }
    EmptyClipboard();
    if (SetClipboardData(CF_DIB, hg) == nullptr) {
        LOG(Caution, "HostScreenshot::CopyPixels: SetClipboardData failed\n");
        GlobalFree(hg);  /* still owned by us on failure */
    }
    CloseClipboard();    /* on success the clipboard owns hg */
    LOG(Lcd, "HostScreenshot::CopyPixels: copied %ux%u image\n", w, h);
}
