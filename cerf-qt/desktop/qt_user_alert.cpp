#include <cerfcore/host/user_alert.h>

#include "../qt_ui_thread_calls.h"
#include "qt_main_window.h"

#include <cerfcore/core/cerf_emulator.h>

#include <QMessageBox>

namespace {

class QtUserAlert : public cerfcore::UserAlert {
public:
    using cerfcore::UserAlert::UserAlert;

    void Show(cerfcore::AlertLevel level, cerfcore::AlertPlacement placement,
              const std::string& title, const std::string& text) override {
        emu_.Get<QtUiThreadCalls>().Run(
            [this, level, placement, title, text] { ShowOnGuiThread(level, placement, title, text); });
    }

    void Post(cerfcore::AlertLevel level, const std::string& title, const std::string& text,
              std::function<void()> after) override {
        emu_.Get<QtMainWindow>().RunOnUiThread([this, level, title, text, after] {
            ShowOnGuiThread(level, cerfcore::AlertPlacement::kStandalone, title, text);
            if (after) after();
        });
    }

private:
    void ShowOnGuiThread(cerfcore::AlertLevel level, cerfcore::AlertPlacement placement,
                         const std::string& title, const std::string& text) {
        QWidget* owner = placement == cerfcore::AlertPlacement::kOverWindow
                             ? emu_.Get<QtMainWindow>().Window()
                             : nullptr;
        QMessageBox box(level == cerfcore::AlertLevel::kError ? QMessageBox::Critical
                                                              : QMessageBox::Warning,
                        QString::fromStdString(title), QString::fromStdString(text),
                        QMessageBox::Ok, owner);
        if (placement == cerfcore::AlertPlacement::kTopmost)
            box.setWindowFlag(Qt::WindowStaysOnTopHint);
        box.exec();
    }
};

}

REGISTER_SERVICE_AS(QtUserAlert, cerfcore::UserAlert);
