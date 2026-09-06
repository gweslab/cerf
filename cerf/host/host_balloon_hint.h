#pragma once

#include "../core/service.h"

#define NOMINMAX
#include <windows.h>

#include <string>

class HostWidget;

class HostBalloonHint : public Service {
public:
    using Service::Service;

    void OnReady() override;
    void OnShutdown() override;

    void ShowUnderWidget(const HostWidget* anchor, const wchar_t* text,
                         UINT hold_ms);
    void ShowUnderCaptureWidget(const wchar_t* text, UINT hold_ms);

private:
    static LRESULT CALLBACK WndProcStatic(HWND, UINT, WPARAM, LPARAM);

    void Show(const RECT* anchor, const wchar_t* text, UINT hold_ms);
    void Dismiss();

    HWND host_ = nullptr;
    HWND tip_  = nullptr;
    std::wstring shown_text_;
};
