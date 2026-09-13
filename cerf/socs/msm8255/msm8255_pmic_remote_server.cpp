#include "msm8255_oncrpc_codec.h"
#include "msm8255_rpc_server.h"
#include "msm8255_rpc_server_registry.h"
#include "msm8255_rpcrouter_wire.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../cpu/emulated_memory.h"

#include <cstdint>

namespace {

constexpr uint32_t kPmicProg = 0x30000061u;
constexpr uint32_t kPmicVers = 0x00030001u;
constexpr uint32_t kPmicCid  = 4u;

constexpr uint32_t kProcVregSetLevel = 3u;

constexpr uint32_t kArgVregIdOff = kCallArgsOff + 0u;
constexpr uint32_t kArgLevelOff  = kCallArgsOff + 4u;

constexpr uint32_t kVregSetLevelPayloadBytes =
    kPacmarkBytes + kCallArgsOff + 8u;

constexpr uint32_t kResultWords = 1u;

/* Linux arch/arm/mach-msm pmic.c: modem_to_linux_err answers success for a
   zero reply word and maps every PM_ERR_FLAG_* bit to a failure. */
constexpr uint32_t kErrFlagNone = 0u;

/* Linux arch/arm/mach-msm include/mach/pmic.h: the count of distinct values in
   enum vreg_id, whose first is PM_VREG_MSMA_ID. */
constexpr uint32_t kVregIdCount = 40u;

constexpr uint32_t kLevelMax = 0x7FFFu;

class Msm8255PmicRemoteServer : public Msm8255RpcServer {
public:
    using Msm8255RpcServer::Msm8255RpcServer;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::MSM8255;
    }

    void OnReady() override {
        emu_.Get<Msm8255RpcServerRegistry>().Register(this);
    }

    uint32_t ServerProg() const override { return kPmicProg; }
    uint32_t ServerVers() const override { return kPmicVers; }
    uint32_t ServerCid() const override { return kPmicCid; }

    uint32_t AnswerCall(uint32_t in_pa, uint32_t size, uint32_t out_pa,
                        uint32_t out_cap, uint32_t self_pid, uint32_t peer_pid,
                        uint32_t peer_cid) override;

private:
    uint32_t VregSetLevelStatus(uint32_t vreg_id, uint32_t level_mv);
};

uint32_t Msm8255PmicRemoteServer::VregSetLevelStatus(uint32_t vreg_id,
                                                     uint32_t level_mv) {
    if (vreg_id >= kVregIdCount) {
        emu_.Get<Fatal>().Die(
            "msm8255 pmic remote server: vreg id %u is not one of the %u this "
            "server models", vreg_id, kVregIdCount);
    }
    if (level_mv > kLevelMax) {
        emu_.Get<Fatal>().Die(
            "msm8255 pmic remote server: vreg id %u requests level 0x%08X, "
            "which is outside the range this server models",
            vreg_id, level_mv);
    }
    return kErrFlagNone;
}

uint32_t Msm8255PmicRemoteServer::AnswerCall(uint32_t in_pa, uint32_t size,
                                             uint32_t out_pa, uint32_t out_cap,
                                             uint32_t self_pid,
                                             uint32_t peer_pid,
                                             uint32_t peer_cid) {
    auto& mem   = emu_.Get<EmulatedMemory>();
    auto& codec = emu_.Get<Msm8255OncrpcCodec>();

    const Msm8255OncrpcCall call = codec.ParseCall(*this, in_pa, size);

    if (call.proc != kProcVregSetLevel) {
        emu_.Get<Fatal>().Die(
            "msm8255 pmic remote server: rpc procedure %u with a %u-byte "
            "payload is not modeled", call.proc, size);
    }
    codec.RequireCallBytes(*this, call.proc, size, kVregSetLevelPayloadBytes);

    const uint32_t vreg_id  = Be32(mem.ReadWord(call.body + kArgVregIdOff));
    const uint32_t level_mv = Be32(mem.ReadWord(call.body + kArgLevelOff));

    const uint32_t results[kResultWords] = {
        VregSetLevelStatus(vreg_id, level_mv)};
    return codec.WriteAcceptedReply(out_pa, out_cap, self_pid, kPmicCid,
                                    peer_pid, peer_cid, call.xid, results,
                                    kResultWords);
}

}

REGISTER_SERVICE(Msm8255PmicRemoteServer);
