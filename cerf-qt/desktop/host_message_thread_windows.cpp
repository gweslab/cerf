#define NOMINMAX
#include "host_message_thread.h"

#include <cerfcore/core/instance_threads.h>

namespace cerffrontend {

HostMessageThread::~HostMessageThread() {
    if (ready_event_) CloseHandle(ready_event_);
}

void HostMessageThread::Start(cerfcore::InstanceThreads& threads, MessageHandler on_message) {
    ready_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    thread_      = threads.Start([this, on_message] { Run(on_message); }, [this] { SetEvent(ready_event_); });
    WaitForSingleObject(ready_event_, INFINITE);
}

void HostMessageThread::Stop() {
    if (thread_id_) PostThreadMessageW(thread_id_, WM_QUIT, 0, 0);
    if (thread_.joinable()) thread_.join();
    thread_id_ = 0;
}

void HostMessageThread::Post(UINT message, WPARAM wparam, LPARAM lparam) const {
    if (thread_id_) PostThreadMessageW(thread_id_, message, wparam, lparam);
}

void HostMessageThread::Run(const MessageHandler& on_message) {
    thread_id_ = GetCurrentThreadId();
    MSG msg;
    PeekMessageW(&msg, nullptr, WM_USER, WM_USER, PM_NOREMOVE);
    SetEvent(ready_event_);
    while (GetMessageW(&msg, nullptr, 0, 0) > 0) on_message(msg);
}

}
