#include "../cerfman/manager_app.h"
#include "../frontend_launch.h"
#include "../install_root_files.h"
#include "../qt_back_gesture.h"
#include "../qt_message_log.h"
#include "android_default_font.h"
#include "android_installation.h"
#include "android_input_pacing.h"
#include "android_system_bars.h"
#include "android_view_focus.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/log.h>

#include <QGuiApplication>

int main(int argc, char* argv[]) {
    RouteQtMessagesToLog();
    QGuiApplication app(argc, argv);
    QtBackGesture   back_gesture(app);
    FollowFocusWindowWithViewFocus(app);
    cerffrontend::FrontendLaunch::OpenLog(cerfcore::Log::Cat::Manager, cerffrontend::kManagerLogFileName);
    PaceInputEvents();
    AndroidSystemBars::Install(app);
    if (!ProvisionInstallation()) return cerfcore::CERF_FATAL_RUNTIME_ERROR;
    RestoreDefaultFontCoverage();
    return ManagerApp::Run(argc, argv,
                           [](cerfcore::CerfEmulator& manager) { return manager.Get<ManagerApp>().RunManager(false); });
}
