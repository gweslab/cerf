#include "qt_main_window.h"
#include "qt_show_socket.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/instance_gate.h>
#include <cerfcore/core/log.h>
#include <cerfcore/core/service.h>
#include <cerfcore/platform/host_process.h>

#include <QSocketNotifier>

#include <sys/socket.h>

namespace {

class QtShowRequest : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void OnReady() override {
        pid_      = cerfcore::host_platform::CurrentProcessId();
        int error = 0;
        fd_       = OpenShowSocket(pid_, error);
        if (fd_ < 0) {
            LOG(Caution, "QtShowRequest: show socket failed (errno %d), the manager cannot raise this "
                         "window\n",
                error);
            return;
        }
        notifier_ = new QSocketNotifier(fd_, QSocketNotifier::Read);
        QObject::connect(notifier_, &QSocketNotifier::activated, notifier_, gate_.Bind([this] { Drain(); }));
    }

    void OnShutdown() override { Close(); }

private:
    void Drain() {
        char buf[64];
        bool any = false;
        while (recv(fd_, buf, sizeof(buf), 0) >= 0) any = true;
        if (!any) return;
        LOG(Lcd, "QtShowRequest: show request, raising the window\n");
        emu_.Get<QtMainWindow>().Raise();
    }

    void Close() {
        delete notifier_;
        notifier_ = nullptr;
        if (fd_ >= 0) CloseShowSocket(fd_, pid_);
        fd_ = -1;
    }

    const cerfcore::InstanceGate gate_{emu_};
    int                          fd_       = -1;
    uint32_t                     pid_      = 0;
    QSocketNotifier*             notifier_ = nullptr;
};

}

REGISTER_SERVICE(QtShowRequest);
