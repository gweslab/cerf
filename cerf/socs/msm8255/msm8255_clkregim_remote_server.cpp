#include "msm8255_clock_rates.h"
#include "msm8255_clock_reset.h"
#include "msm8255_oncrpc_codec.h"
#include "msm8255_rpc_server.h"
#include "msm8255_rpc_server_registry.h"
#include "msm8255_rpcrouter_wire.h"
#include "msm8255_value_set.h"

#include "../../boards/board_context.h"
#include "msm8255_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../cpu/emulated_memory.h"
#include "../../state/state_stream.h"

#include <atomic>
#include <cstdint>

namespace {

constexpr uint32_t kClkProg = 0x3000000Fu;
constexpr uint32_t kClkVers = 0x00030001u;
constexpr uint32_t kClkCid  = 3u;

constexpr uint32_t kProcClockReset     = 2u;
constexpr uint32_t kProcClockEnable    = 5u;
constexpr uint32_t kProcClockDisable   = 6u;
constexpr uint32_t kProcClockIsEnabled = 8u;
constexpr uint32_t kProcSelSdc1Clk     = 16u;
constexpr uint32_t kProcSelSdc2Clk     = 17u;
constexpr uint32_t kProcSelSdc3Clk     = 18u;
constexpr uint32_t kProcSelSdc4Clk     = 19u;
constexpr uint32_t kProcConfigMdhClk   = 24u;
constexpr uint32_t kProcGetClkFreqKhz  = 28u;
constexpr uint32_t kProcRailDisable    = 33u;
constexpr uint32_t kProcRailEnable     = 34u;
constexpr uint32_t kProcSelClkFreqHz   = 42u;

constexpr uint32_t kSdcClkSelValues[] = {0u, 6u, 7u, 9u};

constexpr uint32_t kSdcClkSelCount =
    sizeof(kSdcClkSelValues) / sizeof(kSdcClkSelValues[0]);

constexpr uint32_t kClockPayloadBytes = kPacmarkBytes + kCallArgsOff + 4u;
constexpr uint32_t kClockResultWords  = 0u;

constexpr uint32_t kArg0Off = kCallArgsOff + 0u;
constexpr uint32_t kArg1Off = kCallArgsOff + 4u;
constexpr uint32_t kArg2Off = kCallArgsOff + 8u;

constexpr uint32_t kThreeArgPayloadBytes =
    kPacmarkBytes + kCallArgsOff + 12u;

constexpr uint32_t kResultWords = 1u;

constexpr uint32_t kXdrTrue  = 1u;
constexpr uint32_t kXdrFalse = 0u;

constexpr uint32_t kCountAmbiguous = 0xFFFFFFFFu;

constexpr uint32_t kClockIdCount   = 375u;
constexpr uint32_t kClockWordCount = (kClockIdCount + 31u) / 32u;

constexpr uint32_t kRailClock[] = {0u,  187u, 110u, 61u, 39u,
                                   52u, 112u, 92u,  29u, 189u};

constexpr uint32_t kRailCount = sizeof(kRailClock) / sizeof(kRailClock[0]);

constexpr uint32_t kNoClock = 0u;

class Msm8255ClkregimRemoteServer : public Msm8255RpcServer {
public:
    using Msm8255RpcServer::Msm8255RpcServer;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Msm8255;
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

    void SaveState(StateWriter& w) override {
        emu_.Get<Msm8255ClockRates>().SaveState(w);
        for (const auto& word : clock_known_) {
            w.Write<uint32_t>("word", word.load(std::memory_order_acquire));
        }
        for (const auto& held : clock_refcount_) {
            w.Write<uint32_t>("held", held.load(std::memory_order_acquire));
        }
    }

    void RestoreState(StateReader& r) override {
        emu_.Get<Msm8255ClockRates>().RestoreState(r);
        for (auto& word : clock_known_) {
            uint32_t bits = 0u;
            r.Read("word", bits);
            word.store(bits, std::memory_order_release);
        }
        for (auto& held : clock_refcount_) {
            uint32_t count = 0u;
            r.Read("held", count);
            held.store(count, std::memory_order_release);
        }
    }

private:
    uint32_t CheckedClock(uint32_t clock);
    void     CheckedSdcClkSel(uint32_t sel);
    void     MarkClockKnown(uint32_t clock);
    bool     IsClockKnown(uint32_t clock) const;
    void     RecordClockEnable(uint32_t clock, bool on);
    uint32_t RailClock(uint32_t rail);
    uint32_t ReportClockEnabled(uint32_t clock);

    std::atomic<uint32_t> clock_known_[kClockWordCount]  = {};
    std::atomic<uint32_t> clock_refcount_[kClockIdCount] = {};
};

uint32_t Msm8255ClkregimRemoteServer::CheckedClock(uint32_t clock) {
    if (clock >= kClockIdCount) {
        emu_.Get<Fatal>().Die(
            "msm8255 clkregim remote server: clock %u is outside the %u ids "
            "this program carries", clock, kClockIdCount);
    }
    return clock;
}

void Msm8255ClkregimRemoteServer::CheckedSdcClkSel(uint32_t sel) {
    if (Msm8255ValueSetContains(kSdcClkSelValues, kSdcClkSelCount, sel)) {
        return;
    }
    emu_.Get<Fatal>().Die(
        "msm8255 clkregim remote server: sdc clock selection %u is outside the "
        "%u this program answers", sel, kSdcClkSelCount);
}

void Msm8255ClkregimRemoteServer::MarkClockKnown(uint32_t clock) {
    const uint32_t bit = 1u << (clock % 32u);
    clock_known_[clock / 32u].fetch_or(bit, std::memory_order_acq_rel);
}

bool Msm8255ClkregimRemoteServer::IsClockKnown(uint32_t clock) const {
    const uint32_t bit = 1u << (clock % 32u);
    return (clock_known_[clock / 32u].load(std::memory_order_acquire) & bit) !=
           0u;
}

void Msm8255ClkregimRemoteServer::RecordClockEnable(uint32_t clock, bool on) {
    const uint32_t id = CheckedClock(clock);
    MarkClockKnown(id);
    const uint32_t held = clock_refcount_[id].load(std::memory_order_acquire);
    if (held == kCountAmbiguous) {
        return;
    }
    if (on) {
        clock_refcount_[id].store(held + 1u, std::memory_order_release);
        return;
    }
    clock_refcount_[id].store(held > 1u ? kCountAmbiguous : 0u,
                              std::memory_order_release);
}

uint32_t Msm8255ClkregimRemoteServer::RailClock(uint32_t rail) {
    if (rail >= kRailCount) {
        emu_.Get<Fatal>().Die(
            "msm8255 clkregim remote server: rail %u is outside the %u this "
            "program carries", rail, kRailCount);
    }
    const uint32_t clock = kRailClock[rail];
    if (clock == kNoClock) {
        emu_.Get<Fatal>().Die(
            "msm8255 clkregim remote server: rail %u names no clock", rail);
    }
    return clock;
}

uint32_t Msm8255ClkregimRemoteServer::ReportClockEnabled(uint32_t clock) {
    const uint32_t id   = CheckedClock(clock);
    const uint32_t held = clock_refcount_[id].load(std::memory_order_acquire);
    if (held == kCountAmbiguous) {
        emu_.Get<Fatal>().Die(
            "msm8255 clkregim remote server: clock %u was disabled from a hold "
            "count this program cannot resolve", clock);
    }
    if (!IsClockKnown(id)) {
        emu_.Get<Fatal>().Die(
            "msm8255 clkregim remote server: clock %u has no modeled enable "
            "state to report", clock);
    }
    return held != 0u ? kXdrTrue : kXdrFalse;
}

uint32_t Msm8255ClkregimRemoteServer::AnswerCall(
    uint32_t in_pa, uint32_t size, uint32_t out_pa, uint32_t out_cap,
    uint32_t self_pid, uint32_t peer_pid, uint32_t peer_cid) {
    auto& mem   = emu_.Get<EmulatedMemory>();
    auto& codec = emu_.Get<Msm8255OncrpcCodec>();

    const Msm8255OncrpcCall call = codec.ParseCall(*this, in_pa, size);

    if (call.proc == kProcClockEnable || call.proc == kProcClockDisable ||
        call.proc == kProcRailEnable || call.proc == kProcRailDisable) {
        codec.RequireCallBytes(*this, call.proc, size, kClockPayloadBytes);
        const uint32_t arg = Be32(mem.ReadWord(call.body + kArg0Off));
        const bool by_rail = call.proc == kProcRailEnable ||
                             call.proc == kProcRailDisable;
        const bool on      = call.proc == kProcClockEnable ||
                             call.proc == kProcRailEnable;
        RecordClockEnable(by_rail ? RailClock(arg) : arg, on);
        return codec.WriteAcceptedReply(out_pa, out_cap, self_pid, kClkCid,
                                        peer_pid, peer_cid, call.xid, nullptr,
                                        kClockResultWords);
    }

    if (call.proc == kProcSelSdc1Clk || call.proc == kProcSelSdc2Clk ||
        call.proc == kProcSelSdc3Clk || call.proc == kProcSelSdc4Clk) {
        codec.RequireCallBytes(*this, call.proc, size, kClockPayloadBytes);
        CheckedSdcClkSel(Be32(mem.ReadWord(call.body + kArg0Off)));
        return codec.WriteAcceptedReply(out_pa, out_cap, self_pid, kClkCid,
                                        peer_pid, peer_cid, call.xid, nullptr,
                                        kClockResultWords);
    }

    if (call.proc == kProcClockReset) {
        codec.RequireCallBytes(*this, call.proc, size, kClockPayloadBytes);
        emu_.Get<Msm8255ClockReset>().Reset(
            CheckedClock(Be32(mem.ReadWord(call.body + kArg0Off))));
        return codec.WriteAcceptedReply(out_pa, out_cap, self_pid, kClkCid,
                                        peer_pid, peer_cid, call.xid, nullptr,
                                        kClockResultWords);
    }

    if (call.proc == kProcClockIsEnabled) {
        codec.RequireCallBytes(*this, call.proc, size, kClockPayloadBytes);
        const uint32_t results[kResultWords] = {
            ReportClockEnabled(Be32(mem.ReadWord(call.body + kArg0Off)))};
        return codec.WriteAcceptedReply(out_pa, out_cap, self_pid, kClkCid,
                                        peer_pid, peer_cid, call.xid, results,
                                        kResultWords);
    }

    if (call.proc == kProcGetClkFreqKhz) {
        codec.RequireCallBytes(*this, call.proc, size, kClockPayloadBytes);
        const uint32_t results[kResultWords] = {
            emu_.Get<Msm8255ClockRates>().ReportClockFreqKhz(
                Be32(mem.ReadWord(call.body + kArg0Off)))};
        return codec.WriteAcceptedReply(out_pa, out_cap, self_pid, kClkCid,
                                        peer_pid, peer_cid, call.xid, results,
                                        kResultWords);
    }

    if (call.proc != kProcConfigMdhClk && call.proc != kProcSelClkFreqHz) {
        if (size >= kClockPayloadBytes) {
            emu_.Get<Fatal>().Die(
                "msm8255 clkregim remote server: rpc procedure %u with a "
                "%u-byte payload carrying first argument %u is not modeled",
                call.proc, size,
                Be32(mem.ReadWord(call.body + kArg0Off)));
        }
        emu_.Get<Fatal>().Die(
            "msm8255 clkregim remote server: rpc procedure %u with a %u-byte "
            "payload carrying no argument is not modeled", call.proc, size);
    }
    codec.RequireCallBytes(*this, call.proc, size, kThreeArgPayloadBytes);

    const uint32_t arg0 = Be32(mem.ReadWord(call.body + kArg0Off));
    const uint32_t arg1 = Be32(mem.ReadWord(call.body + kArg1Off));
    const uint32_t arg2 = Be32(mem.ReadWord(call.body + kArg2Off));

    auto& rates = emu_.Get<Msm8255ClockRates>();

    const uint32_t results[kResultWords] = {
        call.proc == kProcConfigMdhClk
            ? rates.GrantMdhRateKhz(arg0, arg1, arg2)
            : rates.GrantClockFreqHz(arg0, arg1, arg2)};
    return codec.WriteAcceptedReply(out_pa, out_cap, self_pid, kClkCid,
                                    peer_pid, peer_cid, call.xid, results,
                                    kResultWords);
}

}

REGISTER_SERVICE(Msm8255ClkregimRemoteServer);
