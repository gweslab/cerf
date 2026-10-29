#include "../external_display_sources.h"
#include "../qt_ui_thread_calls.h"
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
        emu_.Get<QtUiThreadCalls>().Run([this, surf_w, surf_h] {
            box_  = emu_.Get<MobileEmulatorWindow>().CreateExternalDisplay();
            view_ = qobject_cast<ExternalDisplayView*>(box_->property("view").value<QObject*>());
            view_->Attach(source_id_, emu_, surf_w, surf_h);
        });
    }

    void Close() override {
        if (!open_.exchange(false, std::memory_order_acq_rel)) return;
        emu_.Get<QtUiThreadCalls>().Run([this] {
            if (view_) view_->Detach();
            if (box_) delete box_.data();
            box_  = nullptr;
            view_ = nullptr;
        });
        emu_.Get<ExternalDisplaySources>().Remove(source_id_);
    }

    void SetSurfaceSize(uint32_t w, uint32_t h) override {
        emu_.Get<QtUiThreadCalls>().Run([this, w, h] {
            if (view_) view_->SetSurfaceSize(w, h);
        });
    }

private:
    cerfcore::CerfEmulator&       emu_;
    cerfcore::FrameSource&        source_;
    std::function<void()>         on_eject_;
    int                           source_id_ = 0;
    QPointer<QQuickItem>          box_;
    QPointer<ExternalDisplayView> view_;
    std::atomic<bool>             open_{false};
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
