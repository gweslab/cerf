#pragma once

#include <cstddef>
#include <cstdint>
#include <memory>
#include <string>

namespace cerffrontend {

class DiscordIpcTransport {
public:
    DiscordIpcTransport();
    ~DiscordIpcTransport();
    DiscordIpcTransport(const DiscordIpcTransport&)            = delete;
    DiscordIpcTransport& operator=(const DiscordIpcTransport&) = delete;

    bool Connect(std::string& endpoint);
    bool Write(const uint8_t* buf, size_t len);
    bool Read(uint8_t* buf, size_t len);
    void RequestStop();

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

}
