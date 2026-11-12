#define NOMINMAX

#include "host_accent.h"

#include <QAbstractNativeEventFilter>
#include <QByteArray>
#include <QCoreApplication>

#include <windows.h>

#include <roapi.h>
#include <windows.ui.viewmanagement.h>
#include <winstring.h>
#include <wrl/client.h>

#include <cwchar>
#include <iterator>

namespace {

using ABI::Windows::UI::ViewManagement::IUISettings3;
using ABI::Windows::UI::ViewManagement::UIColorType;
using Microsoft::WRL::ComPtr;

using RoActivateInstanceFn           = decltype(&RoActivateInstance);
using WindowsCreateStringReferenceFn = decltype(&WindowsCreateStringReference);

constexpr char    kWindowMessageType[] = "windows_generic_MSG";
constexpr wchar_t kImmersiveColorSet[] = L"ImmersiveColorSet";
constexpr QColor  kLightTextOnAccent(0xFF, 0xFF, 0xFF);
constexpr QColor  kDarkTextOnAccent(0x00, 0x00, 0x00);

ComPtr<IUISettings3> OpenUiSettings() {
    const HMODULE combase = GetModuleHandleW(L"combase.dll");
    if (combase == nullptr) return {};
    const auto activate  = reinterpret_cast<RoActivateInstanceFn>(GetProcAddress(combase, "RoActivateInstance"));
    const auto reference = reinterpret_cast<WindowsCreateStringReferenceFn>(
        GetProcAddress(combase, "WindowsCreateStringReference"));
    if (activate == nullptr || reference == nullptr) return {};
    HSTRING_HEADER header{};
    HSTRING        name = nullptr;
    if (FAILED(reference(RuntimeClass_Windows_UI_ViewManagement_UISettings,
                         static_cast<UINT32>(std::size(RuntimeClass_Windows_UI_ViewManagement_UISettings) - 1), &header,
                         &name)))
        return {};
    ComPtr<IInspectable> instance;
    if (FAILED(activate(name, &instance))) return {};
    ComPtr<IUISettings3> settings;
    if (FAILED(instance.As(&settings))) return {};
    return settings;
}

QColor ColorValue(IUISettings3* settings, UIColorType type) {
    ABI::Windows::UI::Color color{};
    if (FAILED(settings->GetColorValue(type, &color))) return QColor();
    return QColor(color.R, color.G, color.B, color.A);
}

class UiSettingsAccent : public HostAccent, public QAbstractNativeEventFilter {
public:
    explicit UiSettingsAccent(QObject* parent) : HostAccent(parent) {
        QCoreApplication::instance()->installNativeEventFilter(this);
        Reload();
    }

    bool nativeEventFilter(const QByteArray& type, void* message, qintptr*) override {
        if (type != kWindowMessageType) return false;
        const MSG* msg = static_cast<const MSG*>(message);
        if (msg->message == WM_SETTINGCHANGE && msg->wParam == 0 && msg->lParam != 0 &&
            std::wcscmp(reinterpret_cast<const wchar_t*>(msg->lParam), kImmersiveColorSet) == 0)
            Reload();
        return false;
    }

protected:
    void Reload() override {
        const ComPtr<IUISettings3> settings = OpenUiSettings();
        if (!settings) {
            Publish(AccentShade(), AccentShade());
            return;
        }
        Publish(AccentShade{ColorValue(settings.Get(), UIColorType::UIColorType_AccentDark1), kLightTextOnAccent},
                AccentShade{ColorValue(settings.Get(), UIColorType::UIColorType_AccentLight2), kDarkTextOnAccent});
    }
};

}

HostAccent* NewHostAccent(QObject* parent) { return new UiSettingsAccent(parent); }
