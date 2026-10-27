#define NOMINMAX
#include <windows.h>

#include "discord_ipc_transport.h"

#include <cwchar>

namespace cerffrontend {

struct DiscordIpcTransport::Impl {
    HANDLE pipe       = INVALID_HANDLE_VALUE;
    HANDLE io_event   = nullptr;
    HANDLE stop_event = nullptr;

    int WaitIo() {
        HANDLE hs[2] = { io_event, stop_event };
        DWORD  w     = WaitForMultipleObjects(2, hs, FALSE, INFINITE);
        if (w == WAIT_OBJECT_0)     return 0;
        if (w == WAIT_OBJECT_0 + 1) return 1;
        return -1;
    }

    bool Transfer(uint8_t* read_buf, const uint8_t* write_buf, DWORD need) {
        DWORD done = 0;
        while (done < need) {
            ResetEvent(io_event);
            OVERLAPPED ov = {};
            ov.hEvent     = io_event;
            DWORD n       = 0;
            BOOL  ok      = write_buf ? WriteFile(pipe, write_buf + done, need - done, &n, &ov)
                                      : ReadFile(pipe, read_buf + done, need - done, &n, &ov);
            if (!ok) {
                if (GetLastError() != ERROR_IO_PENDING) return false;
                if (WaitIo() != 0) {
                    CancelIoEx(pipe, &ov);
                    GetOverlappedResult(pipe, &ov, &n, TRUE);
                    return false;
                }
                if (!GetOverlappedResult(pipe, &ov, &n, FALSE)) return false;
            }
            if (n == 0) return false;
            done += n;
        }
        return true;
    }
};

DiscordIpcTransport::DiscordIpcTransport() : impl_(std::make_unique<Impl>()) {
    impl_->stop_event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
    impl_->io_event   = CreateEventW(nullptr, TRUE, FALSE, nullptr);
}

DiscordIpcTransport::~DiscordIpcTransport() {
    if (impl_->pipe != INVALID_HANDLE_VALUE) CloseHandle(impl_->pipe);
    if (impl_->io_event) CloseHandle(impl_->io_event);
    if (impl_->stop_event) CloseHandle(impl_->stop_event);
}

bool DiscordIpcTransport::Connect(std::string& endpoint) {
    for (int i = 0; i < 10; i++) {
        wchar_t name[64];
        swprintf_s(name, L"\\\\.\\pipe\\discord-ipc-%d", i);
        HANDLE h = CreateFileW(name, GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING,
                               FILE_FLAG_OVERLAPPED, nullptr);
        if (h != INVALID_HANDLE_VALUE) {
            impl_->pipe = h;
            endpoint    = "\\\\.\\pipe\\discord-ipc-" + std::to_string(i);
            return true;
        }
    }
    return false;
}

bool DiscordIpcTransport::Write(const uint8_t* buf, size_t len) {
    return impl_->Transfer(nullptr, buf, static_cast<DWORD>(len));
}

bool DiscordIpcTransport::Read(uint8_t* buf, size_t len) {
    return impl_->Transfer(buf, nullptr, static_cast<DWORD>(len));
}

void DiscordIpcTransport::RequestStop() {
    if (impl_->stop_event) SetEvent(impl_->stop_event);
}

}
