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

constexpr uint32_t kClkProg = 0x3000000Fu;
constexpr uint32_t kClkVers = 0x00030001u;
constexpr uint32_t kClkCid  = 3u;

constexpr uint32_t kProcClockEnable   = 5u;
constexpr uint32_t kProcClockDisable  = 6u;
constexpr uint32_t kProcConfigMdhClk  = 24u;

constexpr uint32_t kClockPayloadBytes = kPacmarkBytes + kCallArgsOff + 4u;
constexpr uint32_t kClockResultWords  = 0u;

constexpr uint32_t kArgIndexOff = kCallArgsOff + 0u;
constexpr uint32_t kArgMinOff   = kCallArgsOff + 4u;
constexpr uint32_t kArgMaxOff   = kCallArgsOff + 8u;

constexpr uint32_t kConfigMdhPayloadBytes =
    kPacmarkBytes + kCallArgsOff + 12u;

constexpr uint32_t kResultWords = 1u;

constexpr uint32_t kRateUnavailable = 0u;

/* Linux arch/arm/mach-msm clock-7x30-vendor.c: the driving rates of
   clk_tbl_mdh, the table both pmdh_clk and emdh_clk carry, converted from
   hertz to the kilohertz this call speaks. */
constexpr uint32_t kMdhRatesKhz[] = {49150u,  92160u,  122880u, 184320u,
                                     245760u, 368640u, 384000u, 445500u};

constexpr uint32_t kMdhRateCount =
    sizeof(kMdhRatesKhz) / sizeof(kMdhRatesKhz[0]);

constexpr uint32_t kMdhIndexCount = 2u;

class Msm8255ClkregimRemoteServer : public Msm8255RpcServer {
public:
    using Msm8255RpcServer::Msm8255RpcServer;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::MSM8255;
    }

    void OnReady() override {
        emu_.Get<Msm8255RpcServerRegistry>().Register(this);
    }

    uint32_t ServerProg() const override { return kClkProg; }
    uint32_t ServerVers() const override { return kClkVers; }
    uint32_t ServerCid() const override { return kClkCid; }

    uint32_t AnswerCall(uint32_t in_pa, uint32_t size, uint32_t out_pa,
                        uint32_t out_cap, uint32_t self_pid, uint32_t peer_pid,
                        uint32_t peer_cid) override;

private:
    uint32_t GrantMdhRateKhz(uint32_t index, uint32_t min_khz,
                             uint32_t max_khz);
};

uint32_t Msm8255ClkregimRemoteServer::GrantMdhRateKhz(uint32_t index,
                                                       uint32_t min_khz,
                                                       uint32_t max_khz) {
    if (index >= kMdhIndexCount) {
        emu_.Get<Fatal>().Die(
            "msm8255 clkregim remote server: mdh clock index %u is outside the "
            "%u the rate table serves", index, kMdhIndexCount);
    }

    uint32_t granted = kRateUnavailable;
    for (uint32_t i = 0; i < kMdhRateCount; ++i) {
        const uint32_t rate = kMdhRatesKhz[i];
        if (rate >= min_khz && rate <= max_khz && rate > granted) {
            granted = rate;
        }
    }
    return granted;
}

uint32_t Msm8255ClkregimRemoteServer::AnswerCall(
    uint32_t in_pa, uint32_t size, uint32_t out_pa, uint32_t out_cap,
    uint32_t self_pid, uint32_t peer_pid, uint32_t peer_cid) {
    auto& mem   = emu_.Get<EmulatedMemory>();
    auto& codec = emu_.Get<Msm8255OncrpcCodec>();

    const Msm8255OncrpcCall call = codec.ParseCall(*this, in_pa, size);

    if (call.proc == kProcClockEnable || call.proc == kProcClockDisable) {
        codec.RequireCallBytes(*this, call.proc, size, kClockPayloadBytes);
        return codec.WriteAcceptedReply(out_pa, out_cap, self_pid, kClkCid,
                                        peer_pid, peer_cid, call.xid, nullptr,
                                        kClockResultWords);
    }

    if (call.proc != kProcConfigMdhClk) {
        emu_.Get<Fatal>().Die(
            "msm8255 clkregim remote server: rpc procedure %u with a %u-byte "
            "payload is not modeled", call.proc, size);
    }
    codec.RequireCallBytes(*this, call.proc, size, kConfigMdhPayloadBytes);

    const uint32_t index   = Be32(mem.ReadWord(call.body + kArgIndexOff));
    const uint32_t min_khz = Be32(mem.ReadWord(call.body + kArgMinOff));
    const uint32_t max_khz = Be32(mem.ReadWord(call.body + kArgMaxOff));

    const uint32_t results[kResultWords] = {
        GrantMdhRateKhz(index, min_khz, max_khz)};
    return codec.WriteAcceptedReply(out_pa, out_cap, self_pid, kClkCid,
                                    peer_pid, peer_cid, call.xid, results,
                                    kResultWords);
}

}

REGISTER_SERVICE(Msm8255ClkregimRemoteServer);
