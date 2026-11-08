#include "../external_display_sources.h"
#include "../frontend_window.h"
#include "../qt_ui_thread.h"
#include "external_display_view.h"
#include "mobile_emulator_window.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/host/external_display.h>

#include <QPointer>
#include <QQuickItem>

#include <atomic>
#include <functional>
#include <memory>
#include <utility>

namespace {

class MobileExternalDisplay : public cerfcore::ExternalDisplay {
public:
    MobileExternalDisplay(cerfcore::CerfEmulator& emu, cerfcore::FrameSource& source, std::function<void()> on_eject)
        : emu_(emu), source_(source), on_eject_(std::move(on_eject)) {}

    ~MobileExternalDisplay() override { Close(); }

    void Open(uint32_t surf_w, uint32_t surf_h) override {
        if (open_.exchange(true, std::memory_order_acq_rel)) return;
        source_id_ = emu_.Get<ExternalDisplaySources>().Add(source_, on_eject_);
        RunOnUi([&emu = emu_, ui = ui_, id = source_id_, surf_w, surf_h] {
            ui->box = emu.Get<MobileEmulatorWindow>().CreateExternalDisplay();
            ExternalDisplayView* view =
                qobject_cast<ExternalDisplayView*>(ui->box->property("view").value<QObject*>());
            ui->view = view;
            view->Attach(id, emu, surf_w, surf_h);
        });
    }

    void Close() override {
        if (!open_.exchange(false, std::memory_order_acq_rel)) return;
        emu_.Get<ExternalDisplaySources>().Remove(source_id_);
        RunOnUi([ui = ui_] {
            if (ui->view) ui->view->Detach();
            if (ui->box) delete ui->box.data();
        });
    }

    void SetSurfaceSize(uint32_t w, uint32_t h) override {
        RunOnUi([ui = ui_, w, h] {
            if (ui->view) ui->view->SetSurfaceSize(w, h);
        });
    }

private:
    struct UiItems {
        QPointer<QQuickItem>          box;
        QPointer<ExternalDisplayView> view;
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
    std::function<void()>    on_eject_;
    int                      source_id_ = 0;
    std::shared_ptr<UiItems> ui_ = std::make_shared<UiItems>();
    std::atomic<bool>        open_{false};
};

class MobileExternalDisplayFactory : public cerfcore::ExternalDisplayFactory {
public:
    using cerfcore::ExternalDisplayFactory::ExternalDisplayFactory;

    std::unique_ptr<cerfcore::ExternalDisplay> Create(cerfcore::FrameSource& source, const std::string&,
                                                      std::function<void()> on_eject) override {
        return std::make_unique<MobileExternalDisplay>(emu_, source, std::move(on_eject));
    }
};

}

REGISTER_SERVICE_AS(MobileExternalDisplayFactory, cerfcore::ExternalDisplayFactory);
