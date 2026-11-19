#include "automation_params.h"
#include "automation_server.h"

#include "../automation_option.h"
#include "../frontend_window.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/service.h>
#include <cerfcore/host/host_pointer_event.h>
#include <cerfcore/host/host_pointer_input_lock.h>
#include <cerfcore/host/pointer_router.h>
#include <cerfcore/host/pointer_source.h>
#include <cerfcore/host/relative_mouse_input.h>

#include <cstdint>
#include <map>
#include <string>

namespace cerffrontend {

namespace {

using cerfcore::HostButton;
using cerfcore::HostPointerEvent;
using Kind = HostPointerEvent::Kind;

constexpr char kLockedText[]   = "the automatic touch calibration holds the pointer input";
constexpr char kRelativeText[] = "the active pointing device takes relative motion; use pointer.relative";
constexpr char kAbsoluteText[] = "the active pointing device takes positions; use pointer.press, move and release";
constexpr char kNoPointerText[] = "this device has no pointing device";
constexpr char kNotTakenText[]  = "the active pointing device does not take this input";

class AutomationPointerCommands : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    bool ShouldRegister() override { return AutomationRequested(emu_.Argc(), emu_.Argv()); }

    void OnReady() override {
        auto&                        server = emu_.Get<AutomationServer>();
        const AutomationParam        x{"x", "int", true, "guest-surface column, from 0 to screen width - 1"};
        const AutomationParam        y{"y", "int", true, "guest-surface row, from 0 to screen height - 1"};
        const AutomationParam        button{"button", "string", false, "left, right or middle (default left)"};
        server.AddMethod("pointer.press",
                         "Presses a button at a point. On a stylus device the right button sends Alt+Tap while "
                         "the pointer feature alt_tap is on.",
                         {x, y, button}, "empty object", [this](const AutomationCall& call) { Button(call, true); });
        server.AddMethod("pointer.release", "Releases a button at a point.", {x, y, button}, "empty object",
                         [this](const AutomationCall& call) { Button(call, false); });
        server.AddMethod("pointer.move", "Moves the pointer, with the buttons that this connection holds.", {x, y},
                         "empty object", [this](const AutomationCall& call) { Move(call); });
        server.AddMethod("pointer.wheel", "Turns the wheel at a point.",
                         {x, y, {"delta", "int", true, "wheel delta, 120 for one notch"}}, "empty object",
                         [this](const AutomationCall& call) { Wheel(call); });
        server.AddMethod("pointer.relative", "Moves a relative pointing device and sets its buttons.",
                         {{"dx", "int", true, "horizontal motion"},
                          {"dy", "int", true, "vertical motion"},
                          {"buttons", "string[]", false, "held buttons: left, right"}},
                         "empty object", [this](const AutomationCall& call) { Relative(call); });
        server.AddDisconnectListener([this](uint64_t connection) { Release(connection); });
        emu_.Get<cerfcore::HostPointerInputLock>().RegisterAcquireListener(
            [this] { emu_.Get<FrontendWindow>().RunOnUiThread([this] { held_.clear(); }); });
    }

private:
    struct Held {
        uint32_t buttons  = 0;
        uint32_t relative = 0;
        int      x        = 0;
        int      y        = 0;
    };

    static HostButton ButtonOf(const AutomationParams& params) {
        const std::string name = params.OptionalString("button").value_or("left");
        if (name == "left") return HostButton::kLeft;
        if (name == "right") return HostButton::kRight;
        if (name == "middle") return HostButton::kMiddle;
        throw AutomationError(AutomationServer::kInvalidParams, "button must be left, right or middle");
    }

    void RequireUnlocked() const {
        if (emu_.Get<cerfcore::HostPointerInputLock>().Held())
            throw AutomationError(AutomationServer::kRefused, kLockedText);
    }

    cerfcore::PointerKind ActiveKind() {
        cerfcore::PointerSource* active = emu_.Get<cerfcore::PointerRouter>().Active();
        if (active == nullptr) throw AutomationError(AutomationServer::kRefused, kNoPointerText);
        return active->Kind();
    }

    void Point(const AutomationParams& params, int& x, int& y) {
        auto&          window = emu_.Get<FrontendWindow>();
        const int64_t  px     = params.Integer("x");
        const int64_t  py     = params.Integer("y");
        const uint32_t w      = window.GuestSurfaceWidth();
        const uint32_t h      = window.GuestSurfaceHeight();
        if (px < 0 || py < 0 || px >= int64_t(w) || py >= int64_t(h))
            throw AutomationError(AutomationServer::kInvalidParams,
                                  "the point is outside the guest screen of " + std::to_string(w) + "x" +
                                      std::to_string(h));
        x = static_cast<int>(px);
        y = static_cast<int>(py);
    }

    void Send(const AutomationCall& call, HostPointerEvent event) {
        RequireUnlocked();
        if (ActiveKind() == cerfcore::PointerKind::Relative)
            throw AutomationError(AutomationServer::kRefused, kRelativeText);
        event.inside = true;
        auto& router = emu_.Get<cerfcore::PointerRouter>();
        router.ReleaseLost(event);
        if (!router.Route(event)) throw AutomationError(AutomationServer::kRefused, kNotTakenText);
        Held& held = held_[call.Connection()];
        held.buttons = event.held;
        held.x       = event.x;
        held.y       = event.y;
        call.Reply(AutomationJson::object());
    }

    void Button(const AutomationCall& call, bool press) {
        const AutomationParams params(call.Params());
        HostPointerEvent       event;
        event.kind   = press ? Kind::kDown : Kind::kUp;
        event.button = ButtonOf(params);
        Point(params, event.x, event.y);
        const uint32_t bit  = cerfcore::HostButtonBit(event.button);
        const uint32_t held = held_[call.Connection()].buttons;
        event.held          = press ? (held | bit) : (held & ~bit);
        Send(call, event);
    }

    void Move(const AutomationCall& call) {
        const AutomationParams params(call.Params());
        HostPointerEvent       event;
        event.kind = Kind::kMove;
        Point(params, event.x, event.y);
        event.held = held_[call.Connection()].buttons;
        Send(call, event);
    }

    void Wheel(const AutomationCall& call) {
        const AutomationParams params(call.Params());
        HostPointerEvent       event;
        event.kind  = Kind::kWheel;
        event.wheel = static_cast<int>(params.Integer("delta"));
        Point(params, event.x, event.y);
        event.held = held_[call.Connection()].buttons;
        Send(call, event);
    }

    void Relative(const AutomationCall& call) {
        const AutomationParams params(call.Params());
        RequireUnlocked();
        if (ActiveKind() != cerfcore::PointerKind::Relative)
            throw AutomationError(AutomationServer::kRefused, kAbsoluteText);
        uint32_t buttons = 0;
        if (params.Find("buttons") != nullptr) {
            for (const std::string& name : params.Strings("buttons")) {
                if (name == "left") buttons |= cerfcore::kRelMouseLeft;
                else if (name == "right") buttons |= cerfcore::kRelMouseRight;
                else throw AutomationError(AutomationServer::kInvalidParams, "buttons may hold left and right only");
            }
        }
        emu_.Get<cerfcore::PointerRouter>().OnRelativeMove(static_cast<int>(params.Integer("dx")),
                                                          static_cast<int>(params.Integer("dy")), buttons);
        held_[call.Connection()].relative = buttons;
        call.Reply(AutomationJson::object());
    }

    void Release(uint64_t connection) {
        const auto it = held_.find(connection);
        if (it == held_.end()) return;
        const Held held = it->second;
        held_.erase(it);
        auto& router = emu_.Get<cerfcore::PointerRouter>();
        if (held.buttons != 0) {
            HostPointerEvent event;
            event.kind   = Kind::kMove;
            event.x      = held.x;
            event.y      = held.y;
            event.inside = true;
            event.held   = 0;
            router.ReleaseLost(event);
        }
        if (held.relative != 0) router.OnRelativeMove(0, 0, router.RelativeButtons() & ~held.relative);
    }

    std::map<uint64_t, Held> held_;
};

}

REGISTER_SERVICE(AutomationPointerCommands);

}
