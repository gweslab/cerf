#include "uninstall_dialogs.h"

#include "shell_integration_windows.h"
#include "uninstall_resource.h"

#include <thread>

namespace {

constexpr UINT     kLogMessage    = WM_APP + 1;
constexpr UINT     kAskMessage    = WM_APP + 2;
constexpr UINT     kFinishMessage = WM_APP + 3;
constexpr COLORREF kDangerText    = RGB(0xC4, 0x2B, 0x1C);

std::wstring KeptHint() {
    return L"Your devices, saved states and settings stay in the installation directory.";
}

std::wstring DeleteHint() {
    return L"Your devices, saved states and settings are deleted with the rest of the installation. This cannot be "
           L"undone.";
}

HFONT BoldFontOf(HWND control) {
    LOGFONTW font = {};
    const HFONT base = reinterpret_cast<HFONT>(SendMessageW(control, WM_GETFONT, 0, 0));
    if (base == nullptr || GetObjectW(base, sizeof(font), &font) == 0) return nullptr;
    font.lfWeight = FW_BOLD;
    return CreateFontIndirectW(&font);
}

void PrepareWindow(HWND dialog, const std::wstring& heading, HFONT& bold) {
    const HINSTANCE instance = reinterpret_cast<HINSTANCE>(GetWindowLongPtrW(dialog, GWLP_HINSTANCE));
    const HICON     icon     = LoadIconW(instance, MAKEINTRESOURCEW(IDI_UNINSTALL));
    SendMessageW(dialog, WM_SETICON, ICON_BIG, reinterpret_cast<LPARAM>(icon));
    SendMessageW(dialog, WM_SETICON, ICON_SMALL, reinterpret_cast<LPARAM>(icon));
    SetWindowTextW(dialog, UninstallTitle().c_str());
    const HWND heading_control = GetDlgItem(dialog, IDC_HEADING);
    SetWindowTextW(heading_control, heading.c_str());
    bold = BoldFontOf(heading_control);
    if (bold != nullptr) SendMessageW(heading_control, WM_SETFONT, reinterpret_cast<WPARAM>(bold), TRUE);
}

struct ConfirmState {
    std::wstring  install_dir;
    ConfirmResult result;
    HFONT         bold = nullptr;
};

void SyncHint(HWND dialog, const ConfirmState& state) {
    SetDlgItemTextW(dialog, IDC_HINT, state.result.delete_user_data ? DeleteHint().c_str() : KeptHint().c_str());
    InvalidateRect(GetDlgItem(dialog, IDC_HINT), nullptr, TRUE);
}

INT_PTR CALLBACK ConfirmProc(HWND dialog, UINT message, WPARAM wparam, LPARAM lparam) {
    auto* state = reinterpret_cast<ConfirmState*>(GetWindowLongPtrW(dialog, DWLP_USER));
    switch (message) {
    case WM_INITDIALOG:
        state = reinterpret_cast<ConfirmState*>(lparam);
        SetWindowLongPtrW(dialog, DWLP_USER, lparam);
        PrepareWindow(dialog, L"Would you like to uninstall " + shell_integration::ProductName() + L"?", state->bold);
        SetDlgItemTextW(dialog, IDC_PATH, state->install_dir.c_str());
        SetDlgItemTextW(dialog, IDC_DELETE_DATA, L"Delete devices and all user data");
        SetDlgItemTextW(dialog, IDOK, L"Uninstall");
        SyncHint(dialog, *state);
        return TRUE;
    case WM_CTLCOLORSTATIC:
        if (state != nullptr && state->result.delete_user_data &&
            reinterpret_cast<HWND>(lparam) == GetDlgItem(dialog, IDC_HINT)) {
            const HDC dc = reinterpret_cast<HDC>(wparam);
            SetTextColor(dc, kDangerText);
            SetBkMode(dc, TRANSPARENT);
            return reinterpret_cast<INT_PTR>(GetSysColorBrush(COLOR_BTNFACE));
        }
        return FALSE;
    case WM_COMMAND:
        switch (LOWORD(wparam)) {
        case IDC_DELETE_DATA:
            state->result.delete_user_data = IsDlgButtonChecked(dialog, IDC_DELETE_DATA) == BST_CHECKED;
            SyncHint(dialog, *state);
            return TRUE;
        case IDOK:
            state->result.accepted = true;
            EndDialog(dialog, IDOK);
            return TRUE;
        case IDCANCEL:
            state->result.accepted = false;
            EndDialog(dialog, IDCANCEL);
            return TRUE;
        }
        return FALSE;
    case WM_DESTROY:
        if (state != nullptr && state->bold != nullptr) DeleteObject(state->bold);
        return FALSE;
    }
    return FALSE;
}

struct ProgressState {
    std::function<void(const ProgressSink&)> work;
    std::thread                              worker;
    bool                                     finished = false;
    HFONT                                    bold     = nullptr;
};

void AppendLog(HWND dialog, const std::wstring& line) {
    const HWND edit   = GetDlgItem(dialog, IDC_LOG);
    const int  length = GetWindowTextLengthW(edit);
    SendMessageW(edit, EM_SETSEL, WPARAM(length), LPARAM(length));
    const std::wstring text = line + L"\r\n";
    SendMessageW(edit, EM_REPLACESEL, FALSE, reinterpret_cast<LPARAM>(text.c_str()));
}

INT_PTR CALLBACK ProgressProc(HWND dialog, UINT message, WPARAM wparam, LPARAM lparam) {
    auto* state = reinterpret_cast<ProgressState*>(GetWindowLongPtrW(dialog, DWLP_USER));
    switch (message) {
    case WM_INITDIALOG:
        state = reinterpret_cast<ProgressState*>(lparam);
        SetWindowLongPtrW(dialog, DWLP_USER, lparam);
        PrepareWindow(dialog, L"Uninstalling " + shell_integration::ProductName() + L"…", state->bold);
        SetDlgItemTextW(dialog, IDOK, L"Close");
        EnableWindow(GetDlgItem(dialog, IDOK), FALSE);
        state->worker = std::thread([dialog, state] { state->work(ProgressSink(dialog)); });
        return TRUE;
    case kLogMessage:
        AppendLog(dialog, *reinterpret_cast<const std::wstring*>(lparam));
        return TRUE;
    case kAskMessage: {
        const bool retry = AskRetry(dialog, *reinterpret_cast<const std::wstring*>(wparam),
                                    *reinterpret_cast<const std::wstring*>(lparam));
        SetWindowLongPtrW(dialog, DWLP_MSGRESULT, retry ? 1 : 0);
        return TRUE;
    }
    case kFinishMessage:
        SetDlgItemTextW(dialog, IDC_HEADING, reinterpret_cast<const std::wstring*>(lparam)->c_str());
        state->finished = true;
        EnableWindow(GetDlgItem(dialog, IDOK), TRUE);
        SetFocus(GetDlgItem(dialog, IDOK));
        return TRUE;
    case WM_COMMAND:
        if ((LOWORD(wparam) == IDOK || LOWORD(wparam) == IDCANCEL) && state->finished) EndDialog(dialog, IDOK);
        return TRUE;
    case WM_DESTROY:
        if (state != nullptr && state->bold != nullptr) DeleteObject(state->bold);
        return FALSE;
    }
    return FALSE;
}

}

void ProgressSink::Log(const std::wstring& line) const {
    SendMessageW(dialog_, kLogMessage, 0, reinterpret_cast<LPARAM>(&line));
}

bool ProgressSink::AskRetry(const std::wstring& title, const std::wstring& message) const {
    return SendMessageW(dialog_, kAskMessage, reinterpret_cast<WPARAM>(&title), reinterpret_cast<LPARAM>(&message)) !=
           0;
}

void ProgressSink::Finish(const std::wstring& heading) const {
    SendMessageW(dialog_, kFinishMessage, 0, reinterpret_cast<LPARAM>(&heading));
}

std::wstring UninstallTitle() { return shell_integration::UninstallName(); }

ConfirmResult RunConfirmDialog(HINSTANCE instance, const std::wstring& install_dir) {
    ConfirmState state;
    state.install_dir = install_dir;
    DialogBoxParamW(instance, MAKEINTRESOURCEW(IDD_CONFIRM), nullptr, ConfirmProc, reinterpret_cast<LPARAM>(&state));
    return state.result;
}

void RunProgressDialog(HINSTANCE instance, const std::function<void(const ProgressSink&)>& work) {
    ProgressState state;
    state.work = work;
    DialogBoxParamW(instance, MAKEINTRESOURCEW(IDD_PROGRESS), nullptr, ProgressProc, reinterpret_cast<LPARAM>(&state));
    if (state.worker.joinable()) state.worker.join();
}

bool AskRetry(HWND owner, const std::wstring& title, const std::wstring& message) {
    return MessageBoxW(owner, message.c_str(), title.c_str(), MB_RETRYCANCEL | MB_ICONWARNING | MB_DEFBUTTON2) ==
           IDRETRY;
}

void ShowError(HWND owner, const std::wstring& message) {
    MessageBoxW(owner, message.c_str(), UninstallTitle().c_str(), MB_OK | MB_ICONERROR);
}
