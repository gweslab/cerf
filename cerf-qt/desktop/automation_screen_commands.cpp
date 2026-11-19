#include "automation_params.h"
#include "automation_server.h"

#include "../automation_option.h"
#include "../frontend_window.h"
#include "../hud_selection.h"
#include "../image_exporter.h"
#include "../view_rotation.h"

#include <cerfcore/core/byte_order.h>
#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/cerf_paths.h>
#include <cerfcore/core/service.h>
#include <cerfcore/host/frame_renderer.h>

#include <QByteArray>

#include <cstdint>
#include <string>
#include <vector>

namespace cerffrontend {

namespace {

constexpr char kNoFrameText[] = "the guest shows no frame yet";

class AutomationScreenCommands : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    bool ShouldRegister() override { return AutomationRequested(emu_.Argc(), emu_.Argv()); }

    void OnReady() override {
        auto& server = emu_.Get<AutomationServer>();
        server.AddMethod("screen.size", "Gives the size of the guest screen, in the coordinates that pointer input uses.",
                         {}, "object", [this](const AutomationCall& call) { Size(call); });
        server.AddMethod("screen.pixels",
                         "Reads the pixels of the guest screen, or of a rectangle of it. The pixels are base64 text "
                         "of 4 bytes per pixel in the order blue, green, red, unused.",
                         {{"x", "int", false, "left edge, default 0"},
                          {"y", "int", false, "top edge, default 0"},
                          {"width", "int", false, "default: to the right edge"},
                          {"height", "int", false, "default: to the bottom edge"}},
                         "object", [this](const AutomationCall& call) { Pixels(call); });
        server.AddMethod("screen.png", "Writes the guest screen to a PNG file.",
                         {{"path", "string", true, "absolute path of the PNG file"}}, "object",
                         [this](const AutomationCall& call) { Png(call); });
        server.AddMethod("view.tab", "Shows a tab of the emulator window.",
                         {{"tab", "string", true, "boot, hw or fb"}}, "empty object",
                         [this](const AutomationCall& call) { Tab(call); });
        server.AddMethod("view.fullscreen", "Turns full screen on or off.", {{"on", "bool", true, "the new state"}},
                         "empty object", [this](const AutomationCall& call) { Fullscreen(call); });
        server.AddMethod("view.hud", "Shows or hides the HUD of the device.", {{"shown", "bool", true, "the new state"}},
                         "empty object", [this](const AutomationCall& call) { Hud(call); });
        server.AddMethod("view.rotation", "Turns the shown frame by quarter turns. The guest sees no change.",
                         {{"quarter", "int", true, "0, 1, 2 or 3 quarter turns"}}, "empty object",
                         [this](const AutomationCall& call) { Rotation(call); });
    }

private:
    void Capture(std::vector<uint32_t>& pixels, uint32_t& w, uint32_t& h) {
        if (!emu_.Get<FrontendWindow>().CaptureGuestSurface(pixels, w, h))
            throw AutomationError(AutomationServer::kRefused, kNoFrameText);
    }

    void Size(const AutomationCall& call) {
        auto& window = emu_.Get<FrontendWindow>();
        call.Reply(AutomationJson{{"width", window.GuestSurfaceWidth()},
                                  {"height", window.GuestSurfaceHeight()},
                                  {"has_frame", emu_.Get<cerfcore::FrameRenderer>().HasFrame()}});
    }

    void Pixels(const AutomationCall& call) {
        const AutomationParams params(call.Params());
        std::vector<uint32_t>  pixels;
        uint32_t               w = 0, h = 0;
        Capture(pixels, w, h);
        const int64_t x  = params.OptionalInteger("x").value_or(0);
        const int64_t y  = params.OptionalInteger("y").value_or(0);
        const int64_t cw = params.OptionalInteger("width").value_or(int64_t(w) - x);
        const int64_t ch = params.OptionalInteger("height").value_or(int64_t(h) - y);
        if (x < 0 || y < 0 || cw <= 0 || ch <= 0 || x + cw > int64_t(w) || y + ch > int64_t(h))
            throw AutomationError(AutomationServer::kInvalidParams,
                                  "the rectangle is outside the guest screen of " + std::to_string(w) + "x" +
                                      std::to_string(h));
        QByteArray bytes(static_cast<qsizetype>(cw * ch * 4), '\0');
        auto*      out = reinterpret_cast<uint8_t*>(bytes.data());
        for (int64_t row = 0; row < ch; ++row)
            for (int64_t col = 0; col < cw; ++col)
                cerfcore::cerf::le::Put32(out + (row * cw + col) * 4, pixels[size_t((y + row) * w + (x + col))]);
        call.Reply(AutomationJson{{"width", cw},
                                  {"height", ch},
                                  {"format", "bgrx32"},
                                  {"pixels", bytes.toBase64().toStdString()}});
    }

    void Png(const AutomationCall& call) {
        const std::string path = AutomationParams(call.Params()).String("path");
        if (!cerfcore::IsAbsoluteHostPath(path))
            throw AutomationError(AutomationServer::kInvalidParams, "path must be absolute");
        std::vector<uint32_t> pixels;
        uint32_t              w = 0, h = 0;
        Capture(pixels, w, h);
        if (!emu_.Get<ImageExporter>().WritePng(pixels, w, h, path))
            throw AutomationError(AutomationServer::kRefused, "the PNG file was not written: " + path);
        call.Reply(AutomationJson{{"width", w}, {"height", h}});
    }

    void Tab(const AutomationCall& call) {
        const std::string name = AutomationParams(call.Params()).String("tab");
        FrontendWindow::Tab tab = FrontendWindow::Tab::Framebuffer;
        if (name == "boot") tab = FrontendWindow::Tab::Boot;
        else if (name == "hw") tab = FrontendWindow::Tab::Hw;
        else if (name != "fb") throw AutomationError(AutomationServer::kInvalidParams, "tab must be boot, hw or fb");
        emu_.Get<FrontendWindow>().SetTab(tab, true);
        call.Reply(AutomationJson::object());
    }

    void Fullscreen(const AutomationCall& call) {
        auto& window = emu_.Get<FrontendWindow>();
        if (window.IsFullscreen() != AutomationParams(call.Params()).Boolean("on")) window.ToggleFullscreen();
        call.Reply(AutomationJson::object());
    }

    void Hud(const AutomationCall& call) {
        auto&      hud   = emu_.Get<HudSelection>();
        const bool shown = AutomationParams(call.Params()).Boolean("shown");
        if (shown && !hud.CanShow()) throw AutomationError(AutomationServer::kRefused, "this device has no HUD");
        hud.SetShown(shown);
        call.Reply(AutomationJson::object());
    }

    void Rotation(const AutomationCall& call) {
        const int64_t quarter = AutomationParams(call.Params()).Integer("quarter");
        if (quarter < 0 || quarter > 3)
            throw AutomationError(AutomationServer::kInvalidParams, "quarter must be 0, 1, 2 or 3");
        auto& rotation = emu_.Get<ViewRotation>();
        rotation.Rotate(static_cast<int>((quarter - rotation.Quarter() + 4) % 4));
        call.Reply(AutomationJson::object());
    }
};

}

REGISTER_SERVICE(AutomationScreenCommands);

}
