#include "emulator_window_host.h"
#include "external_display_container.h"
#include "external_display_sources.h"
#include "frontend_window.h"
#include "qt_ui_thread.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/external_display.h>

#include <atomic>
#include <functional>
#include <memory>
#include <string>
#include <utility>

namespace {

class QtExternalDisplay : public cerfcore::ExternalDisplay {
public:
    QtExternalDisplay(cerfcore::CerfEmulator& emu, cerfcore::FrameSource& source, std::string title,
                      std::function<void()> on_eject)
        : emu_(emu), source_(source), title_(std::move(title)), on_eject_(std::move(on_eject)) {}

    ~QtExternalDisplay() override { Close(); }

    void Open(uint32_t surf_w, uint32_t surf_h) override {
        if (open_.exchange(true, std::memory_order_acq_rel)) return;
        source_id_ = emu_.Get<ExternalDisplaySources>().Add(source_, on_eject_);
        RunOnUi([&emu = emu_, ui = ui_, id = source_id_, title = title_, surf_w, surf_h] {
            ui->container = emu.Get<EmulatorWindowHost>().OpenExternalDisplay(id, title, surf_w, surf_h);
        });
    }

    void Close() override {
        if (!open_.exchange(false, std::memory_order_acq_rel)) return;
        emu_.Get<ExternalDisplaySources>().Remove(source_id_);
        RunOnUi([ui = ui_] { ui->container.reset(); });
    }

    void SetSurfaceSize(uint32_t w, uint32_t h) override {
        RunOnUi([ui = ui_, w, h] {
            if (ui->container) ui->container->SetSurfaceSize(w, h);
        });
    }

private:
    struct UiItems {
        std::unique_ptr<ExternalDisplayContainer> container;
    };

    void RunOnUi(std::function<void()> job) {
        if (OnUiThread()) {
            job();
            return;
        }
        emu_.Get<cerffrontend::FrontendWindow>().RunOnUiThread(std::move(job));
    }

    cerfcore::CerfEmulator&  emu_;
    cerfcore::FrameSource&   source_;
    std::string              title_;
    std::function<void()>    on_eject_;
    int                      source_id_ = 0;
    std::shared_ptr<UiItems> ui_ = std::make_shared<UiItems>();
    std::atomic<bool>        open_{false};
};

class QtExternalDisplayFactory : public cerfcore::ExternalDisplayFactory {
public:
    using cerfcore::ExternalDisplayFactory::ExternalDisplayFactory;

    std::unique_ptr<cerfcore::ExternalDisplay> Create(cerfcore::FrameSource& source, const std::string& title,
                                                      std::function<void()> on_eject) override {
        return std::make_unique<QtExternalDisplay>(emu_, source, title, std::move(on_eject));
    }
};

}

REGISTER_SERVICE_AS(QtExternalDisplayFactory, cerfcore::ExternalDisplayFactory);
