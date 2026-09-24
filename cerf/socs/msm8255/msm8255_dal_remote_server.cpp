#include "msm8255_dal_remote_server.h"

#include "../../boards/board_context.h"
#include "msm8255_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../cpu/emulated_memory.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"

#include <cstdint>

namespace {

constexpr uint32_t kHdrBytes = 20u;

constexpr uint32_t kLenMask   = 0x0000FFFFu;
constexpr uint32_t kTagShift  = 16u;
constexpr uint32_t kTagMask    = 0x000000FFu;
constexpr uint32_t kFirstFlag = 1u << 24;

constexpr uint32_t kMsgIdShift    = 24u;
constexpr uint32_t kMsgIdKeepMask = 0x00FFFFFFu;
constexpr uint32_t kResponseFlag  = 0x80u;

constexpr uint32_t kTag = 0x11u;

constexpr uint32_t kMsgIdAttach = 1u;

constexpr uint32_t kAttachRequestBytes = 116u;

constexpr uint32_t kReplyBytes    = 84u;
constexpr uint32_t kReplyTailBytes = kReplyBytes - kHdrBytes;

constexpr uint32_t kOffWord0 = 0u;
constexpr uint32_t kOffWord1 = 4u;

constexpr uint32_t kOffCallCallerContext = 8u;

constexpr uint32_t kOffReplyHandle        =  8u;
constexpr uint32_t kOffReplyCallerContext = 12u;
constexpr uint32_t kOffReplyStatus        = 16u;

constexpr uint32_t kNoHandle = 0u;
constexpr uint32_t kNoPort   = 0xFFFFFFFFu;

}

bool Msm8255DalRemoteServer::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Msm8255;
}

void Msm8255DalRemoteServer::OnReady() {
    emu_.Get<GuestCpuReset>().RegisterResetListener(
        [this](ResetLineKind) { port_announced_ = false; });
}

uint32_t Msm8255DalRemoteServer::Answer(uint32_t in_pa, uint32_t in_avail,
                                        uint32_t out_pa, uint32_t out_cap,
                                        uint32_t& consumed) {
    auto& mem = emu_.Get<EmulatedMemory>();

    if (in_avail < kHdrBytes) {
        emu_.Get<Fatal>().Die(
            "msm8255 dal remote server: %u bytes are queued, which is short of "
            "the %u-byte message header", in_avail, kHdrBytes);
    }

    const uint32_t word0 = mem.ReadWord(in_pa + kOffWord0);
    const uint32_t word1 = mem.ReadWord(in_pa + kOffWord1);
    const uint32_t len   = word0 & kLenMask;
    const uint32_t tag   = (word0 >> kTagShift) & kTagMask;
    const uint32_t msg   = word1 >> kMsgIdShift;

    if (tag != kTag) {
        emu_.Get<Fatal>().Die(
            "msm8255 dal remote server: the message carries tag 0x%02X, and "
            "only 0x%02X is modeled", tag, kTag);
    }
    if (len != kAttachRequestBytes) {
        emu_.Get<Fatal>().Die(
            "msm8255 dal remote server: the message declares %u bytes, and only "
            "the %u-byte form is modeled", len, kAttachRequestBytes);
    }
    if (len > in_avail) {
        emu_.Get<Fatal>().Die(
            "msm8255 dal remote server: the message declares %u bytes and %u "
            "are queued", len, in_avail);
    }
    if (msg != kMsgIdAttach) {
        emu_.Get<Fatal>().Die(
            "msm8255 dal remote server: message id %u is not modeled", msg);
    }
    consumed = len;

    if (out_cap < kReplyBytes) {
        emu_.Get<Fatal>().Die(
            "msm8255 dal remote server: the reply needs %u bytes and the "
            "window at 0x%08X has %u", kReplyBytes, out_pa, out_cap);
    }

    uint32_t reply0 = kReplyBytes | (kTag << kTagShift);
    if (!port_announced_) {
        port_announced_ = true;
        reply0 |= kFirstFlag;
    }

    mem.WriteWord(out_pa + kOffWord0, reply0);
    mem.WriteWord(out_pa + kOffWord1,
                  (word1 & kMsgIdKeepMask) |
                      ((msg | kResponseFlag) << kMsgIdShift));
    mem.WriteWord(out_pa + kOffReplyHandle, kNoHandle);
    mem.WriteWord(out_pa + kOffReplyCallerContext,
                  mem.ReadWord(in_pa + kOffCallCallerContext));
    mem.WriteWord(out_pa + kOffReplyStatus, kNoPort);
    for (uint32_t off = 0; off < kReplyTailBytes; off += 4u) {
        mem.WriteWord(out_pa + kHdrBytes + off, 0u);
    }
    return kReplyBytes;
}

void Msm8255DalRemoteServer::SaveState(StateWriter& w) {
    w.Write<uint32_t>("port_announced", port_announced_ ? 1u : 0u);
}

void Msm8255DalRemoteServer::RestoreState(StateReader& r) {
    uint32_t announced = 0;
    r.Read("port_announced", announced);
    port_announced_ = announced != 0u;
}

REGISTER_SERVICE(Msm8255DalRemoteServer);
