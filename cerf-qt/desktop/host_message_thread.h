#pragma once

#include <windows.h>

#include <functional>
#include <thread>

namespace cerfcore {
class InstanceThreads;
}

namespace cerffrontend {

class HostMessageThread {
public:
    using MessageHandler = std::function<void(const MSG&)>;

    HostMessageThread() = default;
    ~HostMessageThread();
    HostMessageThread(const HostMessageThread&)            = delete;
    HostMessageThread& operator=(const HostMessageThread&) = delete;

    void  Start(cerfcore::InstanceThreads& threads, MessageHandler on_message);
    void  Stop();
    void  Post(UINT message, WPARAM wparam = 0, LPARAM lparam = 0) const;
    DWORD ThreadId() const { return thread_id_; }

private:
    void Run(const MessageHandler& on_message);

    DWORD       thread_id_   = 0;
    HANDLE      ready_event_ = nullptr;
    std::thread thread_;
};

}
