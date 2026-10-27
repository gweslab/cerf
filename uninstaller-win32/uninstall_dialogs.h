#pragma once

#define NOMINMAX
#include <windows.h>

#include <functional>
#include <string>

struct ConfirmResult {
    bool accepted         = false;
    bool delete_user_data = false;
};

class ProgressSink {
public:
    explicit ProgressSink(HWND dialog) : dialog_(dialog) {}

    void Log(const std::wstring& line) const;
    bool AskRetry(const std::wstring& title, const std::wstring& message) const;
    void Finish(const std::wstring& heading) const;

private:
    HWND dialog_;
};

std::wstring  UninstallTitle();
ConfirmResult RunConfirmDialog(HINSTANCE instance, const std::wstring& install_dir);
void          RunProgressDialog(HINSTANCE instance, const std::function<void(const ProgressSink&)>& work);
bool          AskRetry(HWND owner, const std::wstring& title, const std::wstring& message);
void          ShowError(HWND owner, const std::wstring& message);
