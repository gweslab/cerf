#include <cerfcore/host/shutdown_host.h>

#include "qt_main_window.h"
#include "qt_shutdown_dialog.h"

#include <cerfcore/core/cerf_emulator.h>
#include "../shutdown_prompt.h"

namespace {

class QtShutdownHost : public cerfcore::ShutdownHost {
public:
    using cerfcore::ShutdownHost::ShutdownHost;

    void RunPromptJob(std::function<void()> job) override {
        emu_.Get<QtMainWindow>().RunOnUiThread(std::move(job));
    }

    cerfcore::ShutdownChoice Ask(cerfcore::ShutdownTrigger trigger) override {
        return emu_.Get<QtShutdownDialog>().Show(trigger);
    }

    void DismissAsCancel() override { emu_.Get<QtShutdownDialog>().DismissAsCancel(); }

    void BeginTeardown() override { emu_.Get<QtMainWindow>().BeginShutdownTeardown(); }

    void CancelTeardown() override {
        emu_.Get<cerffrontend::ShutdownPrompt>().CancelCloseRequest();
    }
};

}

REGISTER_SERVICE_AS(QtShutdownHost, cerfcore::ShutdownHost);
