#include "serial_cradle.h"

#include "host_serial_forward.h"
#include "modem_personality.h"
#include "serial_endpoint.h"
#include "serial_endpoint_kind.h"
#include "serial_forward_card_menu.h"
#include "serial_line.h"
#include "serial_modem_card_menu.h"

#include "../../core/cerf_emulator.h"
#include "../../core/string_utils.h"
#include "../../host/host_icon_cache.h"
#include "../../host/ui_language.h"
#include "../../state/state_stream.h"

#include <cstdint>
#include <utility>

SerialCradle::SerialCradle(CerfEmulator& emu, SerialLine& line, std::wstring label)
    : emu_(emu), line_(line), label_(std::move(label)) {}

SerialCradle::~SerialCradle() = default;

void SerialCradle::OnShutdown() {
    std::lock_guard<std::mutex> lk(mtx_);
    if (endpoint_) {
        line_.SetEndpoint(nullptr);
        endpoint_->OnClose();
        endpoint_.reset();
    }
    kind_ = Kind::None;
}

void SerialCradle::SaveCradleState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(mtx_);
    w.Write<uint8_t>("kind", static_cast<uint8_t>(kind_));
    const uint32_t n = static_cast<uint32_t>(host_port_.size());
    w.Write("host_port_count", n);
    if (n) w.WriteBytes("host_port", host_port_.data(), n * sizeof(wchar_t));
}

void SerialCradle::RestoreCradleState(StateReader& r) {
    std::lock_guard<std::mutex> lk(mtx_);
    uint8_t k = 0;
    r.Read("kind", k);
    restored_kind_ = static_cast<Kind>(k);

    uint32_t n = 0;
    r.Read("host_port_count", n);
    restored_port_.assign(n, L'\0');
    if (n) r.ReadBytes("host_port", restored_port_.data(), n * sizeof(wchar_t));
}

void SerialCradle::PostRestore() {
    std::lock_guard<std::mutex> lk(mtx_);
    SetPluggedLocked(restored_kind_, restored_port_);
}

void SerialCradle::SetPluggedLocked(Kind kind, std::wstring host_port) {
    if (endpoint_) {
        line_.SetEndpoint(nullptr);
        endpoint_->OnClose();
        endpoint_.reset();
    }

    kind_      = kind;
    host_port_ = std::move(host_port);
    ++generation_;

    if (kind == Kind::None) return;

    if (kind == Kind::Modem) {
        endpoint_ = std::make_unique<ModemPersonality>(
            emu_, "ppp:" + WideToUtf8(label_));
    } else {
        auto fwd = std::make_unique<HostSerialForward>(host_port_, emu_);
        const uint64_t gen = generation_;
        fwd->SetOnBridgeDead([this, gen] { Eject(gen); });
        endpoint_ = std::move(fwd);
    }

    endpoint_->BindUart(line_);
    endpoint_->OnOpen();
    line_.SetEndpoint(endpoint_.get());
}


void SerialCradle::SwapModem(uint64_t gen) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (generation_ != gen) return;
    SetPluggedLocked(Kind::Modem, {});
}

void SerialCradle::SwapForward(uint64_t gen, std::wstring host_port) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (generation_ != gen) return;
    SetPluggedLocked(Kind::Forward, std::move(host_port));
}

void SerialCradle::Eject(uint64_t gen) {
    std::lock_guard<std::mutex> lk(mtx_);
    if (generation_ != gen) return;
    SetPluggedLocked(Kind::None, {});
}

std::vector<WidgetMenuItem> SerialCradle::BuildInsertSubmenuLocked(uint64_t gen) {
    std::vector<WidgetMenuItem> items;

    WidgetMenuItem modem;
    modem.label   = emu_.Get<UiLanguage>().Text("pcmcia.serial_modem");
    modem.submenu = emu_.Get<SerialModemCardMenu>().BuildInsertMenu(
        [this, gen] { SwapModem(gen); });
    items.push_back(std::move(modem));

    WidgetMenuItem fwd;
    fwd.label   = emu_.Get<UiLanguage>().Text("pcmcia.serial_forward");
    fwd.submenu = emu_.Get<SerialForwardCardMenu>().BuildInsertMenu(
        [this, gen](std::wstring port) { SwapForward(gen, std::move(port)); });
    items.push_back(std::move(fwd));

    return items;
}

std::vector<WidgetMenuItem> SerialCradle::BuildMenu() {
    std::lock_guard<std::mutex> lk(mtx_);
    const uint64_t gen = generation_;
    std::vector<WidgetMenuItem> items;

    if (kind_ == Kind::None) {
        WidgetMenuItem insert;
        insert.label   = emu_.Get<UiLanguage>().Text("pcmcia.insert_card");
        insert.submenu = BuildInsertSubmenuLocked(gen);
        items.push_back(std::move(insert));
        return items;
    }

    WidgetMenuItem header;
    header.label   = emu_.Get<UiLanguage>().Text(kind_ == Kind::Modem
        ? "pcmcia.serial_modem" : "pcmcia.serial_forward");
    header.enabled = false;
    items.push_back(std::move(header));

    WidgetMenuItem eject;
    eject.label    = emu_.Get<UiLanguage>().Text("pcmcia.eject");
    eject.on_click = [this, gen] { Eject(gen); };
    items.push_back(std::move(eject));

    WidgetMenuItem swap;
    swap.label   = emu_.Get<UiLanguage>().Text("pcmcia.eject_and_insert");
    swap.submenu = BuildInsertSubmenuLocked(gen);
    items.push_back(std::move(swap));

    return items;
}

const wchar_t* SerialCradle::IconResourceLocked() const {
    switch (kind_) {
        case Kind::Modem:   return L"ICON_SERIAL_MODEM";
        case Kind::Forward: return L"ICON_SERIAL_COM";
        case Kind::None:    return L"ICON_SERIAL_EMPTY";
    }
    return L"ICON_SERIAL_EMPTY";
}

void SerialCradle::DrawIcon(HDC dc, const RECT& box) const {
    const wchar_t* res;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        res = IconResourceLocked();
    }
    emu_.Get<HostIconCache>().DrawCentered(dc, box, res);
}

bool SerialCradle::PollDirty() {
    std::wstring res;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        res = IconResourceLocked();
    }
    if (res == ui_last_res_) return false;
    ui_last_res_ = std::move(res);
    return true;
}

std::wstring SerialCradle::Tooltip() const {
    std::lock_guard<std::mutex> lk(mtx_);
    switch (kind_) {
        case Kind::Modem:
            return label_ + L" - " + emu_.Get<UiLanguage>().Text("pcmcia.serial_modem");
        case Kind::Forward:
            return label_ + L" - " + emu_.Get<UiLanguage>().Format(
                "pcmcia.forward_to_host", {{"port", WideToUtf8(host_port_)}});
        case Kind::None:
            return label_ + L" - " + emu_.Get<UiLanguage>().Text("pcmcia.empty");
    }
    return label_;
}
