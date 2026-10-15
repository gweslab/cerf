#define NOMINMAX
#include "compactflash_menu.h"

#include "compactflash_card.h"
#include "compactflash_fat16.h"
#include "compactflash_fat32.h"

#include "../../core/cerf_emulator.h"
#include "../../core/cerf_paths.h"
#include "../../core/device_config.h"
#include "../../core/string_utils.h"
#include "../../host/host_dark_mode.h"
#include "../../host/host_window.h"
#include "../../host/ui_language.h"

#include <algorithm>
#include <cstdint>
#include <memory>
#include <vector>

#include <windows.h>
#include <commdlg.h>

REGISTER_SERVICE(CompactFlashMenu);

namespace {

constexpr int kIdSizeEdit = 1001;

/* Passed to SizeDlgProc via the DialogBoxIndirectParam lParam: the minimum the
   entered value is floored to, plus the dark-theme service the proc themes the
   dialog with. Lives on PromptSizeMb's stack for the modal call's duration. */
struct SizeDlgCtx {
    UINT          min_mb;
    HostDarkMode* dm;
};

/* Modal dialog proc for the card-size prompt. A SizeDlgCtx* arrives via lParam
   at WM_INITDIALOG; the chosen size is returned through EndDialog (0 = cancel).
   Win32 dialog callback - a C function pointer, the sanctioned free-function
   exception. */
INT_PTR CALLBACK SizeDlgProc(HWND dlg, UINT msg, WPARAM wp, LPARAM lp) {
    switch (msg) {
    case WM_INITDIALOG: {
        auto* ctx = reinterpret_cast<SizeDlgCtx*>(lp);
        SetWindowLongPtrW(dlg, DWLP_USER, reinterpret_cast<LONG_PTR>(ctx));
        SetDlgItemInt(dlg, kIdSizeEdit, ctx->min_mb, FALSE);
        if (ctx->dm) ctx->dm->ApplyToDialog(dlg);
        HWND edit = GetDlgItem(dlg, kIdSizeEdit);
        SetFocus(edit);
        SendMessageW(edit, EM_SETSEL, 0, -1);
        return FALSE;   /* focus set explicitly */
    }
    case WM_CTLCOLORDLG:
    case WM_CTLCOLORSTATIC:
    case WM_CTLCOLORBTN:
    case WM_CTLCOLOREDIT: {
        /* A dialog proc returns the CTLCOLOR brush by returning it directly cast
           to INT_PTR - DWLP_MSGRESULT is ignored for these messages.
           https://learn.microsoft.com/windows/win32/dlgbox/wm-ctlcolordlg */
        auto* ctx = reinterpret_cast<SizeDlgCtx*>(GetWindowLongPtrW(dlg, DWLP_USER));
        LRESULT br;
        if (ctx && ctx->dm && ctx->dm->HandleCtlColor(msg, wp, br))
            return static_cast<INT_PTR>(br);
        return FALSE;
    }
    case WM_COMMAND:
        if (LOWORD(wp) == IDOK) {
            auto* ctx = reinterpret_cast<SizeDlgCtx*>(GetWindowLongPtrW(dlg, DWLP_USER));
            BOOL ok = FALSE;
            UINT v = GetDlgItemInt(dlg, kIdSizeEdit, &ok, FALSE);
            UINT min_mb = ctx ? ctx->min_mb : 0;
            if (!ok || v < min_mb) v = min_mb;
            EndDialog(dlg, static_cast<INT_PTR>(v));
            return TRUE;
        }
        if (LOWORD(wp) == IDCANCEL) {
            EndDialog(dlg, 0);
            return TRUE;
        }
        return FALSE;
    }
    return FALSE;
}

/* Builds an in-memory DLGTEMPLATE (DWORD-aligned per the Win32 contract). */
struct DlgBuf {
    std::vector<uint8_t> b;
    void Align()          { while (b.size() & 3) b.push_back(0); }
    void W16(uint16_t v)  { b.push_back(v & 0xFF); b.push_back((v >> 8) & 0xFF); }
    void W32(uint32_t v)  { W16(v & 0xFFFF); W16((v >> 16) & 0xFFFF); }
    void Str(const wchar_t* s) { for (; *s; ++s) W16(static_cast<uint16_t>(*s)); W16(0); }
};

}  /* namespace */

std::wstring CompactFlashMenu::CfImgPath() const {
    wchar_t buf[MAX_PATH] = {};
    const DWORD n = GetModuleFileNameW(nullptr, buf, MAX_PATH);
    std::wstring path(buf, n);
    const std::size_t slash = path.find_last_of(L"\\/");
    const std::wstring dir =
        slash == std::wstring::npos ? L"." : path.substr(0, slash);
    return dir + L"\\CF.IMG";
}

std::wstring CompactFlashMenu::ChooseImageFile() const {
    const auto& language = emu_.Get<UiLanguage>();
    std::wstring filter = language.Text("pcmcia.cf.image_filter");
    filter.push_back(L'\0');
    filter += L"*.img;*.bin;*.ima";
    filter.push_back(L'\0');
    filter += language.Text("common.all_files");
    filter.push_back(L'\0');
    filter += L"*.*";
    filter.push_back(L'\0');
    filter.push_back(L'\0');
    wchar_t file[MAX_PATH] = {};
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = emu_.Get<HostWindow>().Hwnd();
    ofn.lpstrFilter = filter.c_str();
    ofn.lpstrFile   = file;
    ofn.nMaxFile    = MAX_PATH;
    ofn.lpstrTitle  = language.Text("pcmcia.cf.choose_image_title");
    ofn.Flags       = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY;
    return GetOpenFileNameW(&ofn) ? std::wstring(file) : std::wstring();
}

std::vector<std::wstring> CompactFlashMenu::ChooseFilesToGenerate() const {
    std::wstring filter = emu_.Get<UiLanguage>().Text("common.all_files");
    filter.push_back(L'\0');
    filter += L"*.*";
    filter.push_back(L'\0');
    filter.push_back(L'\0');
    std::vector<std::wstring> out;
    std::vector<wchar_t> buf(64u * 1024u, 0);   /* room for many paths */
    OPENFILENAMEW ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner   = emu_.Get<HostWindow>().Hwnd();
    ofn.lpstrFilter = filter.c_str();
    ofn.lpstrFile   = buf.data();
    ofn.nMaxFile    = static_cast<DWORD>(buf.size());
    ofn.lpstrTitle  = emu_.Get<UiLanguage>().Text("pcmcia.cf.choose_payload_title");
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_HIDEREADONLY |
                OFN_ALLOWMULTISELECT | OFN_EXPLORER;
    if (!GetOpenFileNameW(&ofn)) return out;

    /* OFN_EXPLORER multi-select: "dir\0file1\0file2\0\0"; a single pick is
       just the full path in one string. */
    const wchar_t* p = buf.data();
    std::wstring dir(p);
    p += dir.size() + 1;
    if (*p == L'\0') { out.push_back(dir); return out; }
    while (*p) {
        std::wstring f(p);
        p += f.size() + 1;
        out.push_back(dir + L"\\" + f);
    }
    return out;
}

uint32_t CompactFlashMenu::PayloadMb(
    const std::vector<std::wstring>& files) const {
    uint64_t total = 0;
    for (const auto& f : files) {
        WIN32_FILE_ATTRIBUTE_DATA fa = {};
        if (GetFileAttributesExW(f.c_str(), GetFileExInfoStandard, &fa)) {
            total += (static_cast<uint64_t>(fa.nFileSizeHigh) << 32) |
                     fa.nFileSizeLow;
        }
    }
    return static_cast<uint32_t>((total + (1u << 20) - 1) >> 20);
}

uint32_t CompactFlashMenu::PromptSizeMb(uint32_t min_mb) const {
    const auto& language = emu_.Get<UiLanguage>();
    const auto caption = language.Format("pcmcia.cf.minimum_size",
        {{"minimum", std::to_string(min_mb)}});

    DlgBuf t;
    /* DLGTEMPLATE header. */
    t.W32(WS_POPUP | WS_BORDER | WS_CAPTION | WS_SYSMENU |
          DS_MODALFRAME | DS_SETFONT | DS_CENTER);
    t.W32(0);                       /* exstyle              */
    t.W16(4);                       /* item count           */
    t.W16(0); t.W16(0);             /* x, y                 */
    t.W16(210); t.W16(72);          /* cx, cy (dialog units)*/
    t.W16(0);                       /* no menu              */
    t.W16(0);                       /* default class        */
    t.Str(language.Text("pcmcia.cf.generate_title"));
    t.W16(9);                       /* DS_SETFONT point size*/
    t.Str(L"Segoe UI");             /* ApplyToDialog re-applies the live UI font */

    /* Static label (caption baked with the live minimum). */
    t.Align();
    t.W32(WS_CHILD | WS_VISIBLE | SS_LEFT);
    t.W32(0);
    t.W16(7); t.W16(7); t.W16(196); t.W16(12);
    t.W16(0xFFFF);                  /* IDC_STATIC           */
    t.W16(0xFFFF); t.W16(0x0082);   /* Static class atom    */
    t.Str(caption.c_str());
    t.W16(0);

    /* Edit box (size in MiB). */
    t.Align();
    t.W32(WS_CHILD | WS_VISIBLE | WS_BORDER | WS_TABSTOP |
          ES_NUMBER | ES_AUTOHSCROLL);
    t.W32(0);
    t.W16(7); t.W16(24); t.W16(90); t.W16(12);
    t.W16(kIdSizeEdit);
    t.W16(0xFFFF); t.W16(0x0081);   /* Edit class atom      */
    t.W16(0);                       /* empty title          */
    t.W16(0);

    /* OK / Cancel. */
    t.Align();
    t.W32(WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_DEFPUSHBUTTON);
    t.W32(0);
    t.W16(96); t.W16(50); t.W16(50); t.W16(14);
    t.W16(IDOK);
    t.W16(0xFFFF); t.W16(0x0080);   /* Button class atom    */
    t.Str(language.Text("common.ok"));
    t.W16(0);

    t.Align();
    t.W32(WS_CHILD | WS_VISIBLE | WS_TABSTOP | BS_PUSHBUTTON);
    t.W32(0);
    t.W16(152); t.W16(50); t.W16(50); t.W16(14);
    t.W16(IDCANCEL);
    t.W16(0xFFFF); t.W16(0x0080);
    t.Str(language.Text("common.cancel"));
    t.W16(0);

    SizeDlgCtx ctx{ min_mb, &emu_.Get<HostDarkMode>() };
    const INT_PTR r = DialogBoxIndirectParamW(
        GetModuleHandleW(nullptr),
        reinterpret_cast<LPCDLGTEMPLATEW>(t.b.data()),
        emu_.Get<HostWindow>().Hwnd(), SizeDlgProc,
        reinterpret_cast<LPARAM>(&ctx));
    return r > 0 ? static_cast<uint32_t>(r) : 0;
}

std::vector<WidgetMenuItem> CompactFlashMenu::BuildInsertMenu(
    PcmciaCardCatalog::CardInserter inserter) {
    std::vector<WidgetMenuItem> items;

    /* CF images bundled with the device (cerf.json
       "additional_packages.compact_flash_cards") - offered only when the
       image file is actually present in the device directory. */
    const auto& cfg = emu_.Get<DeviceConfig>();
    for (const auto& card : cfg.bundled_compact_flash_cards) {
        const std::wstring path = Utf8ToWide(
            (GetDeviceDir(cfg.device_name) + card.file).c_str());
        if (GetFileAttributesW(path.c_str()) == INVALID_FILE_ATTRIBUTES)
            continue;
        WidgetMenuItem it;
        it.label    = emu_.Get<UiLanguage>().Format("pcmcia.insert_named", {{"name", card.name}});
        it.on_click = [this, inserter, path] {
            inserter(std::make_unique<CompactFlashCard>(emu_, path));
        };
        items.push_back(std::move(it));
    }

    {
        WidgetMenuItem it;
        it.label = emu_.Get<UiLanguage>().Text("pcmcia.cf.choose_image");
        it.on_click = [this, inserter] {
            const std::wstring p = ChooseImageFile();
            if (!p.empty())
                inserter(std::make_unique<CompactFlashCard>(emu_, p));
        };
        items.push_back(std::move(it));
    }
    {
        WidgetMenuItem it;
        const std::wstring cf = CfImgPath();
        it.label   = emu_.Get<UiLanguage>().Text("pcmcia.cf.choose_default");
        it.enabled = GetFileAttributesW(cf.c_str()) != INVALID_FILE_ATTRIBUTES;
        it.on_click = [this, inserter, cf] {
            inserter(std::make_unique<CompactFlashCard>(emu_, cf));
        };
        items.push_back(std::move(it));
    }
    {
        WidgetMenuItem it;
        it.label = emu_.Get<UiLanguage>().Format("pcmcia.cf.generate_and_choose", {{"format", "FAT16"}});
        it.on_click = [this, inserter] {
            const std::vector<std::wstring> files = ChooseFilesToGenerate();
            if (files.empty()) return;
            const uint32_t min_mb = std::max<uint32_t>(PayloadMb(files), 4u);
            const uint32_t size_mb = PromptSizeMb(min_mb);
            if (size_mb == 0) return;   /* cancelled */
            const std::wstring cf = CfImgPath();
            if (emu_.Get<CompactFlashFat16Builder>().Build(cf, files, size_mb))
                inserter(std::make_unique<CompactFlashCard>(emu_, cf));
        };
        items.push_back(std::move(it));
    }
    {
        WidgetMenuItem it;
        it.label = emu_.Get<UiLanguage>().Format("pcmcia.cf.generate_and_choose", {{"format", "FAT32"}});
        it.on_click = [this, inserter] {
            const std::vector<std::wstring> files = ChooseFilesToGenerate();
            if (files.empty()) return;
            /* Floor the prompt to the file payload, but never below the
               FAT32 minimum this builder can produce (66000 512-byte
               clusters ~= 32 MiB). */
            const uint32_t min_mb = std::max<uint32_t>(PayloadMb(files), 32u);
            const uint32_t size_mb = PromptSizeMb(min_mb);
            if (size_mb == 0) return;   /* cancelled */
            const std::wstring cf = CfImgPath();
            if (emu_.Get<CompactFlashFat32Builder>().Build(cf, files, size_mb))
                inserter(std::make_unique<CompactFlashCard>(emu_, cf));
        };
        items.push_back(std::move(it));
    }
    return items;
}
