#define NOMINMAX
#include <windows.h>

#include "../boot/rom_parser_service.h"
#include "../core/cerf_emulator.h"
#include "../core/device_config.h"
#include "../core/log.h"
#include "../core/string_utils.h"
#include "window_title.h"

#include <nlohmann/json.hpp>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <string>
#include <thread>
#include <vector>

namespace {

using nlohmann::json;

constexpr char kClientId[]   = "1525612431022493856";
constexpr char kInviteUrl[]  = "https://discord.gg/QREE9Y2v2d";
constexpr char kLargeImage[] = "cerf";

constexpr int32_t kOpHandshake = 0;
constexpr int32_t kOpFrame     = 1;
constexpr int32_t kOpPing      = 3;
constexpr int32_t kOpPong      = 4;

class DiscordPresence : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override {
        return emu_.Get<DeviceConfig>().discord_rich_presence;
    }

    void OnReady() override {
        details_    = WideToUtf8(emu_.Get<WindowTitle>().Compose());
        state_      = ResolveOsVersion();
        start_secs_ = static_cast<int64_t>(::time(nullptr));

        stop_event_ = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        io_event_   = CreateEventW(nullptr, TRUE, FALSE, nullptr);
        worker_     = std::thread([this] { Run(); });
    }

    void OnShutdown() override {
        if (stop_event_) SetEvent(stop_event_);
        if (worker_.joinable()) worker_.join();
        if (pipe_ != INVALID_HANDLE_VALUE) CloseHandle(pipe_);
        if (io_event_)   CloseHandle(io_event_);
        if (stop_event_) CloseHandle(stop_event_);
        pipe_       = INVALID_HANDLE_VALUE;
        io_event_   = nullptr;
        stop_event_ = nullptr;
    }

private:
    std::string ResolveOsVersion() {
        auto* rp = emu_.TryGet<RomParserService>();
        if (!rp) return {};
        uint16_t major = 0, minor = 0;
        if (!rp->KernelSubsystemVersion(major, minor)) return {};
        char buf[48];
        std::snprintf(buf, sizeof buf, "Windows CE %u.%u", major, minor);
        return buf;
    }

    std::string BuildActivity() {
        json a;
        a["details"] = details_;
        if (!state_.empty()) a["state"] = state_;
        a["timestamps"]["start"] = start_secs_;
        a["assets"]["large_image"] = kLargeImage;
        a["assets"]["large_text"]  = "CE Runtime Foundation";
        a["buttons"] = json::array();
        a["buttons"].push_back({ {"label", "Join Discord"}, {"url", kInviteUrl} });

        json frame;
        frame["cmd"]   = "SET_ACTIVITY";
        frame["nonce"] = std::to_string(GetCurrentProcessId()) + "-cerf";
        frame["args"]["pid"]      = static_cast<int>(GetCurrentProcessId());
        frame["args"]["activity"] = a;
        return frame.dump();
    }

    bool Connect() {
        for (int i = 0; i < 10; i++) {
            char name[64];
            std::snprintf(name, sizeof name, "\\\\.\\pipe\\discord-ipc-%d", i);
            HANDLE h = CreateFileA(name, GENERIC_READ | GENERIC_WRITE, 0, nullptr,
                                   OPEN_EXISTING, FILE_FLAG_OVERLAPPED, nullptr);
            if (h != INVALID_HANDLE_VALUE) {
                pipe_ = h;
                LOG(Discord, "connected via %s\n", name);
                return true;
            }
        }
        return false;
    }

    int WaitIo() {
        HANDLE hs[2] = { io_event_, stop_event_ };
        DWORD w = WaitForMultipleObjects(2, hs, FALSE, INFINITE);
        if (w == WAIT_OBJECT_0)     return 0;
        if (w == WAIT_OBJECT_0 + 1) return 1;
        return -1;
    }

    bool Transfer(bool write, uint8_t* buf, DWORD need) {
        DWORD done = 0;
        while (done < need) {
            ResetEvent(io_event_);
            OVERLAPPED ov = {};
            ov.hEvent = io_event_;
            DWORD n = 0;
            BOOL ok = write ? WriteFile(pipe_, buf + done, need - done, &n, &ov)
                            : ReadFile (pipe_, buf + done, need - done, &n, &ov);
            if (!ok) {
                if (GetLastError() != ERROR_IO_PENDING) return false;
                if (WaitIo() != 0) {
                    CancelIoEx(pipe_, &ov);
                    GetOverlappedResult(pipe_, &ov, &n, TRUE);
                    return false;
                }
                if (!GetOverlappedResult(pipe_, &ov, &n, FALSE)) return false;
            }
            if (n == 0) return false;
            done += n;
        }
        return true;
    }

    bool WriteFrame(int32_t opcode, const std::string& payload) {
        std::vector<uint8_t> buf(8 + payload.size());
        int32_t len = static_cast<int32_t>(payload.size());
        std::memcpy(buf.data() + 0, &opcode, 4);
        std::memcpy(buf.data() + 4, &len,    4);
        std::memcpy(buf.data() + 8, payload.data(), payload.size());
        return Transfer(true, buf.data(), static_cast<DWORD>(buf.size()));
    }

    bool ReadFrame(int32_t& opcode, std::string& payload) {
        uint8_t hdr[8];
        if (!Transfer(false, hdr, 8)) return false;
        int32_t len = 0;
        std::memcpy(&opcode, hdr + 0, 4);
        std::memcpy(&len,    hdr + 4, 4);
        if (len < 0 || len > (1 << 20)) return false;
        payload.resize(static_cast<size_t>(len));
        if (len && !Transfer(false, reinterpret_cast<uint8_t*>(payload.data()),
                             static_cast<DWORD>(len)))
            return false;
        return true;
    }

    void Run() {
        if (!Connect()) {
            LOG(Discord, "no Discord IPC pipe (client not running)\n");
            return;
        }

        json hs;
        hs["v"]         = 1;
        hs["client_id"] = kClientId;
        if (!WriteFrame(kOpHandshake, hs.dump())) {
            LOG(Discord, "handshake write failed\n");
            return;
        }

        int32_t op = 0;
        std::string pl;
        if (!ReadFrame(op, pl)) {
            LOG(Discord, "no handshake reply\n");
            return;
        }
        LOG(Discord, "handshake reply op=%d: %.512s\n", op, pl.c_str());

        if (!WriteFrame(kOpFrame, BuildActivity())) {
            LOG(Discord, "SET_ACTIVITY write failed\n");
            return;
        }
        LOG(Discord, "presence sent: '%s' | '%s'\n",
            details_.c_str(), state_.c_str());

        while (ReadFrame(op, pl)) {
            LOG(Discord, "reply op=%d: %.512s\n", op, pl.c_str());
            if (op == kOpPing && !WriteFrame(kOpPong, pl)) break;
        }
        LOG(Discord, "presence connection closed\n");
    }

    std::string details_;
    std::string state_;
    int64_t     start_secs_ = 0;

    std::thread worker_;
    HANDLE      pipe_       = INVALID_HANDLE_VALUE;
    HANDLE      io_event_   = nullptr;
    HANDLE      stop_event_ = nullptr;
};

REGISTER_SERVICE(DiscordPresence);

}
