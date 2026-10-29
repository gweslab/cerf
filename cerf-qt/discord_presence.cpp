#include "discord_ipc_transport.h"

#include "frontend_config.h"
#include "product_links.h"
#include "window_title.h"

#include <cerfcore/boot/rom_parser_queries.h>
#include <cerfcore/core/byte_order.h>
#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/instance_threads.h>
#include <cerfcore/core/log.h>
#include <cerfcore/platform/host_process.h>

#include <nlohmann/json.hpp>

#include <cstdint>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <memory>
#include <string>
#include <thread>
#include <vector>

namespace cerffrontend {

namespace {

using nlohmann::json;

constexpr char kClientId[]   = "1525612431022493856";
constexpr char kLargeImage[] = "cerf";

constexpr int32_t kOpHandshake = 0;
constexpr int32_t kOpFrame     = 1;
constexpr int32_t kOpPing      = 3;
constexpr int32_t kOpPong      = 4;

class DiscordPresence : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    bool ShouldRegister() override { return emu_.Get<FrontendConfig>().DiscordRichPresence(); }

    void OnReady() override {
        details_    = emu_.Get<WindowTitle>().Compose();
        state_      = ResolveOsVersion();
        start_secs_ = static_cast<int64_t>(::time(nullptr));
        transport_  = std::make_unique<DiscordIpcTransport>();
        worker_     = emu_.Get<cerfcore::InstanceThreads>().Start([this] { Run(); });
    }

    void OnShutdown() override {
        if (transport_) transport_->RequestStop();
        if (worker_.joinable()) worker_.join();
        transport_.reset();
    }

private:
    std::string ResolveOsVersion() {
        auto* rp = emu_.TryGet<cerfcore::RomParserQueries>();
        if (!rp) return {};
        uint16_t major = 0, minor = 0;
        if (!rp->KernelSubsystemVersion(major, minor)) return {};
        char buf[48];
        std::snprintf(buf, sizeof buf, "Windows CE %u.%u", major, minor);
        return buf;
    }

    std::string BuildActivity() {
        const uint32_t pid = cerfcore::host_platform::CurrentProcessId();
        json a;
        a["details"] = details_;
        if (!state_.empty()) a["state"] = state_;
        a["timestamps"]["start"]   = start_secs_;
        a["assets"]["large_image"] = kLargeImage;
        a["assets"]["large_text"]  = kProductName;
        a["buttons"]               = json::array();
        a["buttons"].push_back({ {"label", "Join Discord"}, {"url", kDiscordUrl} });

        json frame;
        frame["cmd"]              = "SET_ACTIVITY";
        frame["nonce"]            = std::to_string(pid) + "-cerf";
        frame["args"]["pid"]      = static_cast<int>(pid);
        frame["args"]["activity"] = a;
        return frame.dump();
    }

    bool WriteFrame(int32_t opcode, const std::string& payload) {
        std::vector<uint8_t> buf(8 + payload.size());
        cerfcore::cerf::le::Put32(buf.data() + 0, static_cast<uint32_t>(opcode));
        cerfcore::cerf::le::Put32(buf.data() + 4, static_cast<uint32_t>(payload.size()));
        std::memcpy(buf.data() + 8, payload.data(), payload.size());
        return transport_->Write(buf.data(), buf.size());
    }

    bool ReadFrame(int32_t& opcode, std::string& payload) {
        uint8_t hdr[8];
        if (!transport_->Read(hdr, 8)) return false;
        opcode            = static_cast<int32_t>(cerfcore::cerf::le::U32(hdr, 0));
        const int32_t len = static_cast<int32_t>(cerfcore::cerf::le::U32(hdr, 4));
        if (len < 0 || len > (1 << 20)) return false;
        payload.resize(static_cast<size_t>(len));
        if (len && !transport_->Read(reinterpret_cast<uint8_t*>(payload.data()), static_cast<size_t>(len)))
            return false;
        return true;
    }

    void Run() {
        std::string endpoint;
        if (!transport_->Connect(endpoint)) {
            LOG(Discord, "no Discord IPC endpoint (client not running)\n");
            return;
        }
        LOG(Discord, "connected via %s\n", endpoint.c_str());

        json hs;
        hs["v"]         = 1;
        hs["client_id"] = kClientId;
        if (!WriteFrame(kOpHandshake, hs.dump())) {
            LOG(Discord, "handshake write failed\n");
            return;
        }

        int32_t     op = 0;
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
        LOG(Discord, "presence sent: '%s' | '%s'\n", details_.c_str(), state_.c_str());

        while (ReadFrame(op, pl)) {
            LOG(Discord, "reply op=%d: %.512s\n", op, pl.c_str());
            if (op == kOpPing && !WriteFrame(kOpPong, pl)) break;
        }
        LOG(Discord, "presence connection closed\n");
    }

    std::string details_;
    std::string state_;
    int64_t     start_secs_ = 0;

    std::unique_ptr<DiscordIpcTransport> transport_;
    std::thread                          worker_;
};

REGISTER_SERVICE(DiscordPresence);

}

}
