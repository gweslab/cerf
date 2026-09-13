#pragma once

#include "../../core/service.h"

#include <cstdint>

class Msm8255RpcServer;

struct Msm8255OncrpcCall {
    uint32_t body;
    uint32_t xid;
    uint32_t proc;
};

class Msm8255OncrpcCodec : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;

    Msm8255OncrpcCall ParseCall(const Msm8255RpcServer& server, uint32_t in_pa,
                                uint32_t size);
    void RequireCallBytes(const Msm8255RpcServer& server, uint32_t proc,
                          uint32_t size, uint32_t want);
    uint32_t SkipXdrString(uint32_t body, uint32_t size, uint32_t off,
                           uint32_t which);
    uint32_t WriteAcceptedReply(uint32_t out_pa, uint32_t out_cap,
                                uint32_t self_pid, uint32_t src_cid,
                                uint32_t peer_pid, uint32_t peer_cid,
                                uint32_t xid, const uint32_t* results,
                                uint32_t result_words);
};
