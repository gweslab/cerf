#include "msm8255_oncrpc_codec.h"

#include "msm8255_rpc_router_peer.h"
#include "msm8255_rpc_server.h"
#include "msm8255_rpcrouter_wire.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../cpu/emulated_memory.h"

#include <cstdint>
#include <typeinfo>

bool Msm8255OncrpcCodec::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSoc() == SocFamily::MSM8255;
}

Msm8255OncrpcCall Msm8255OncrpcCodec::ParseCall(const Msm8255RpcServer& server,
                                                uint32_t in_pa, uint32_t size) {
    auto& mem = emu_.Get<EmulatedMemory>();

    if (size < kPacmarkBytes + kCallArgsOff) {
        emu_.Get<Fatal>().Die(
            "Service '%s': rpc payload is %u bytes, which is short of the "
            "%u-byte call header",
            typeid(server).name(), size, kPacmarkBytes + kCallArgsOff);
    }

    emu_.Get<Msm8255RpcRouterPeer>().ValidatePacmark(
        mem.ReadWord(in_pa + kHdrBytes), size - kPacmarkBytes);

    const uint32_t body = in_pa + kHdrBytes + kPacmarkBytes;
    const uint32_t xid  = Be32(mem.ReadWord(body + kCallXidOff));
    const uint32_t type = Be32(mem.ReadWord(body + kCallTypeOff));
    const uint32_t rpcv = Be32(mem.ReadWord(body + kCallRpcVersOff));
    const uint32_t prog = Be32(mem.ReadWord(body + kCallProgOff));
    const uint32_t vers = Be32(mem.ReadWord(body + kCallVersOff));
    const uint32_t proc = Be32(mem.ReadWord(body + kCallProcOff));

    if (type != kOncrpcCall || rpcv != kOncrpcVersion) {
        emu_.Get<Fatal>().Die(
            "Service '%s': rpc message type %u version %u is not modeled",
            typeid(server).name(), type, rpcv);
    }
    if (prog != server.ServerProg() || vers != server.ServerVers()) {
        emu_.Get<Fatal>().Die(
            "Service '%s': rpc call prog 0x%08X vers 0x%08X is not modeled",
            typeid(server).name(), prog, vers);
    }

    const uint32_t cred_flavor = Be32(mem.ReadWord(body + kCallCredFlavorOff));
    const uint32_t cred_len    = Be32(mem.ReadWord(body + kCallCredLenOff));
    const uint32_t verf_flavor = Be32(mem.ReadWord(body + kCallVerfFlavorOff));
    const uint32_t verf_len    = Be32(mem.ReadWord(body + kCallVerfLenOff));
    if (cred_flavor != kAuthNone || cred_len != 0u ||
        verf_flavor != kAuthNone || verf_len != 0u) {
        emu_.Get<Fatal>().Die(
            "Service '%s': rpc call carries cred flavor %u length %u and verf "
            "flavor %u length %u, and only an unauthenticated call is modeled",
            typeid(server).name(), cred_flavor, cred_len, verf_flavor,
            verf_len);
    }

    return {body, xid, proc};
}

void Msm8255OncrpcCodec::RequireCallBytes(const Msm8255RpcServer& server,
                                          uint32_t proc, uint32_t size,
                                          uint32_t want) {
    if (size == want) {
        return;
    }
    emu_.Get<Fatal>().Die(
        "Service '%s': procedure %u carries %u payload bytes and the modeled "
        "argument list is %u",
        typeid(server).name(), proc, size, want);
}

/* RFC 4506 section 4.11: a string is its byte count as an unsigned integer,
   then that many bytes, then 0 to 3 zero bytes so the total is a multiple of
   four. */
uint32_t Msm8255OncrpcCodec::SkipXdrString(uint32_t body, uint32_t size,
                                           uint32_t off, uint32_t which) {
    auto& mem = emu_.Get<EmulatedMemory>();

    if (size < kPacmarkBytes + off + 4u) {
        emu_.Get<Fatal>().Die(
            "msm8255 oncrpc codec: the rpc call is %u bytes, which is short of "
            "the %u that carry the length of its string argument %u", size,
            kPacmarkBytes + off + 4u, which);
    }

    const uint32_t len = Be32(mem.ReadWord(body + off));
    if (len == 0u) {
        emu_.Get<Fatal>().Die(
            "msm8255 oncrpc codec: string argument %u of the rpc call is empty, "
            "and only a named one is modeled", which);
    }
    if (len > kRouterMsgSizeMax) {
        emu_.Get<Fatal>().Die(
            "msm8255 oncrpc codec: string argument %u of the rpc call is %u "
            "bytes, which does not fit a %u-byte router message", which, len,
            kRouterMsgSizeMax);
    }

    return off + 4u + ((len + 3u) & ~3u);
}

/* RFC 5531 section 9: an accepted reply is xid, msg_type, reply_stat, the verf
   opaque_auth pair, accept_stat, then the procedure results. */
uint32_t Msm8255OncrpcCodec::WriteAcceptedReply(
    uint32_t out_pa, uint32_t out_cap, uint32_t self_pid, uint32_t src_cid,
    uint32_t peer_pid, uint32_t peer_cid, uint32_t xid,
    const uint32_t* results, uint32_t result_words) {
    auto& mem    = emu_.Get<EmulatedMemory>();
    auto& router = emu_.Get<Msm8255RpcRouterPeer>();

    const uint32_t body_bytes = kReplyResultsOff + 4u * result_words;
    if (out_cap < kHdrBytes + kPacmarkBytes + body_bytes) {
        emu_.Get<Fatal>().Die(
            "msm8255 oncrpc codec: a %u-result reply needs %u bytes and the "
            "window at 0x%08X has %u", result_words,
            kHdrBytes + kPacmarkBytes + body_bytes, out_pa, out_cap);
    }
    router.WriteHeader(out_pa, kCtrlCmdData, self_pid, src_cid,
                       kPacmarkBytes + body_bytes, peer_pid, peer_cid);
    mem.WriteWord(out_pa + kHdrBytes, router.NextPacmark(body_bytes));

    const uint32_t out = out_pa + kHdrBytes + kPacmarkBytes;
    mem.WriteWord(out + kReplyXidOff,        Be32(xid));
    mem.WriteWord(out + kReplyTypeOff,       Be32(kOncrpcReply));
    mem.WriteWord(out + kReplyStatOff,       Be32(kMsgAccepted));
    mem.WriteWord(out + kReplyVerfFlavorOff, Be32(kAuthNone));
    mem.WriteWord(out + kReplyVerfLenOff,    Be32(0u));
    mem.WriteWord(out + kReplyAcceptStatOff, Be32(kAcceptSuccess));
    for (uint32_t i = 0; i < result_words; ++i) {
        mem.WriteWord(out + kReplyResultsOff + 4u * i, Be32(results[i]));
    }
    return kHdrBytes + kPacmarkBytes + body_bytes;
}

REGISTER_SERVICE(Msm8255OncrpcCodec);
