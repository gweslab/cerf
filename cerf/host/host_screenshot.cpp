#define NOMINMAX

#include "host_screenshot.h"

#include "../core/cerf_emulator.h"
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

std::wstring SanitizeForFilename(const std::string& utf8) {
    std::wstring w = Utf8ToWide(utf8.c_str());
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

HostScreenshot::~HostScreenshot() {
    if (gdiplus_token_) Gdiplus::GdiplusShutdown(gdiplus_token_);
}

void HostScreenshot::OnReady() {
    Gdiplus::GdiplusStartupInput in;
    Gdiplus::GdiplusStartup(&gdiplus_token_, &in, nullptr);
}

void HostScreenshot::Save() {
    std::vector<uint32_t> px;
    uint32_t w = 0, h = 0;
    if (!emu_.Get<HostCanvas>().CaptureGuestSurface(px, w, h)) {
        LOG(Lcd, "HostScreenshot::Save: no guest frame to capture\n");
        return;
    }

    const std::wstring dir = Utf8ToWide(GetCerfDir().c_str()) + L"screenshots\\";
    CreateDirectoryW(dir.c_str(), nullptr);  /* ok if it already exists */

    const std::string dev = emu_.Get<DeviceConfig>().meta.device_name.empty()
        ? emu_.Get<DeviceConfig>().device_name
        : emu_.Get<DeviceConfig>().meta.device_name;
    const std::wstring path =
        dir + SanitizeForFilename(dev) + L"_" + TimestampNow() + L".png";

    CLSID png;
    if (GetPngEncoderClsid(png) < 0) {
        LOG(Caution, "HostScreenshot::Save: no PNG encoder available\n");
        return;
    }

    Gdiplus::Bitmap bmp((INT)w, (INT)h, (INT)(w * 4),
                        PixelFormat32bppRGB,
                        reinterpret_cast<BYTE*>(px.data()));
    const Gdiplus::Status st = bmp.Save(path.c_str(), &png, nullptr);
    if (st != Gdiplus::Ok) {
        LOG(Caution, "HostScreenshot::Save: GDI+ Save failed (status=%d)\n",
            (int)st);
        return;
    }
    LOG(Lcd, "HostScreenshot::Save: wrote %ux%u screenshot\n", w, h);
}

void HostScreenshot::Copy() {
    std::vector<uint32_t> px;
    uint32_t w = 0, h = 0;
    if (!emu_.Get<HostCanvas>().CaptureGuestSurface(px, w, h)) {
        LOG(Lcd, "HostScreenshot::Copy: no guest frame to capture\n");
        return;
    }

    const size_t row_bytes = (size_t)w * 4u;
    const size_t total = sizeof(BITMAPINFOHEADER) + row_bytes * h;
    HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, total);
    if (!hg) {
        LOG(Caution, "HostScreenshot::Copy: GlobalAlloc failed\n");
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

    HWND owner = emu_.Get<HostWindow>().Hwnd();
    if (!OpenClipboard(owner)) {
        LOG(Caution, "HostScreenshot::Copy: OpenClipboard failed\n");
        GlobalFree(hg);
        return;
    }
    EmptyClipboard();
    if (SetClipboardData(CF_DIB, hg) == nullptr) {
        LOG(Caution, "HostScreenshot::Copy: SetClipboardData failed\n");
        GlobalFree(hg);  /* still owned by us on failure */
    }
    CloseClipboard();    /* on success the clipboard owns hg */
    LOG(Lcd, "HostScreenshot::Copy: copied %ux%u image\n", w, h);
}
