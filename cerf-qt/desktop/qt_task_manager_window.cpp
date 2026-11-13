#include <cerfcore/host/task_manager_view.h>

#include "qt_focus_policy.h"
#include "task_manager_controller.h"

#include "../cerfman/manager_engine.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/device_config.h>

#include <QPointer>
#include <QQuickWindow>
#include <QVariantMap>

namespace {

class QtTaskManagerWindow : public cerfcore::TaskManagerView {
public:
    using cerfcore::TaskManagerView::TaskManagerView;

    bool ShouldRegister() override { return emu_.Get<cerfcore::DeviceConfig>().guest_additions; }

    void Show() override {
        if (window_) {
            emu_.Get<QtFocusPolicy>().Raise(*window_);
            return;
        }
        auto* controller = new TaskManagerController(emu_);
        window_          = qobject_cast<QQuickWindow*>(emu_.Get<ManagerEngine>().Open(
            QStringLiteral("TaskManagerWindow"),
            QVariantMap{{QStringLiteral("controller"), QVariant::fromValue<QObject*>(controller)}}));
        controller->setParent(window_);
        emu_.Get<QtFocusPolicy>().Show(*window_);
    }

private:
    QPointer<QQuickWindow> window_;
};

}

REGISTER_SERVICE_AS(QtTaskManagerWindow, cerfcore::TaskManagerView);
