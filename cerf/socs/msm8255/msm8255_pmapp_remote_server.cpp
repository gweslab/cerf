#include "msm8255_oncrpc_codec.h"
#include "msm8255_rpc_server.h"
#include "msm8255_rpc_server_registry.h"
#include "msm8255_rpcrouter_wire.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"

#include <cstdint>

namespace {

constexpr uint32_t kPmappProg = 0x30000060u;
constexpr uint32_t kPmappVers = 0x00050001u;
constexpr uint32_t kPmappCid  = 5u;

constexpr uint32_t kProcVregAssert        = 3u;
constexpr uint32_t kProcVregQuery         = 4u;
constexpr uint32_t kProcDisplayClockConfig = 21u;

constexpr uint32_t kAssertPayloadBytes      = kPacmarkBytes + kCallArgsOff + 12u;
constexpr uint32_t kQueryPayloadBytes       = kPacmarkBytes + kCallArgsOff + 8u;
constexpr uint32_t kDisplayClockPayloadBytes = kPacmarkBytes + kCallArgsOff + 4u;

constexpr uint32_t kAssertResultWords      = 0u;
constexpr uint32_t kQueryResultWords       = 2u;
constexpr uint32_t kDisplayClockResultWords = 1u;

constexpr uint32_t kXdrTrue  = 1u;
constexpr uint32_t kXdrFalse = 0u;

/* Linux arch/arm/mach-msm rpc_pmapp.c: modem_to_linux_err answers success for a
   zero reply word and maps every PM_ERR_FLAG_* bit to a failure. */
constexpr uint32_t kErrFlagNone = 0u;

class Msm8255PmappRemoteServer : public Msm8255RpcServer {
public:
    using Msm8255RpcServer::Msm8255RpcServer;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::MSM8255;
    }

    void OnReady() override {
        emu_.Get<Msm8255RpcServerRegistry>().Register(this);
    }

    uint32_t ServerProg() const override { return kPmappProg; }
    uint32_t ServerVers() const override { return kPmappVers; }
    uint32_t ServerCid() const override { return kPmappCid; }

    uint32_t AnswerCall(uint32_t in_pa, uint32_t size, uint32_t out_pa,
                        uint32_t out_cap, uint32_t self_pid, uint32_t peer_pid,
                        uint32_t peer_cid) override;
};

uint32_t Msm8255PmappRemoteServer::AnswerCall(uint32_t in_pa, uint32_t size,
                                              uint32_t out_pa, uint32_t out_cap,
                                              uint32_t self_pid,
                                              uint32_t peer_pid,
                                              uint32_t peer_cid) {
    auto& codec = emu_.Get<Msm8255OncrpcCodec>();

    const Msm8255OncrpcCall call = codec.ParseCall(*this, in_pa, size);

    if (call.proc == kProcVregAssert) {
        codec.RequireCallBytes(*this, call.proc, size, kAssertPayloadBytes);
        return codec.WriteAcceptedReply(out_pa, out_cap, self_pid, kPmappCid,
                                        peer_pid, peer_cid, call.xid, nullptr,
                                        kAssertResultWords);
    }

    if (call.proc == kProcDisplayClockConfig) {
        codec.RequireCallBytes(*this, call.proc, size,
                               kDisplayClockPayloadBytes);
        const uint32_t results[kDisplayClockResultWords] = {kErrFlagNone};
        return codec.WriteAcceptedReply(out_pa, out_cap, self_pid, kPmappCid,
                                        peer_pid, peer_cid, call.xid, results,
                                        kDisplayClockResultWords);
    }

    if (call.proc != kProcVregQuery) {
        emu_.Get<Fatal>().Die(
            "msm8255 pmapp remote server: rpc procedure %u with a %u-byte "
            "payload is not modeled", call.proc, size);
    }
    codec.RequireCallBytes(*this, call.proc, size, kQueryPayloadBytes);

    const uint32_t results[kQueryResultWords] = {kXdrTrue, kXdrFalse};
    return codec.WriteAcceptedReply(out_pa, out_cap, self_pid, kPmappCid,
                                    peer_pid, peer_cid, call.xid, results,
                                    kQueryResultWords);
}

}

REGISTER_SERVICE(Msm8255PmappRemoteServer);
