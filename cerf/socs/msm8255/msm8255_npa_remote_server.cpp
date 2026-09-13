#include "msm8255_npa_remote_server.h"

#include "msm8255_oncrpc_codec.h"
#include "msm8255_rpc_router_peer.h"
#include "msm8255_rpc_server_registry.h"
#include "msm8255_rpcrouter_wire.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../cpu/emulated_memory.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"

#include <cstdint>

namespace {

constexpr uint32_t kNpaProg   = 0x300000A4u;
constexpr uint32_t kNpaVers   = 0x00010001u;
constexpr uint32_t kNpaCid    = 1u;
constexpr uint32_t kNpaResult = 0u;

constexpr uint32_t kProcDefineNode     = 2u;
constexpr uint32_t kProcCreateClient   = 3u;
constexpr uint32_t kProcIssueRequest   = 6u;
constexpr uint32_t kProcDefineResource = 22u;

constexpr uint32_t kClientTypeMax = 9u;

/* RFC 4506 section 4.4: bool is enum { FALSE = 0, TRUE = 1 }. Section 4.19
   makes an optional-data field a union whose discriminant is such a bool. */
constexpr uint32_t kXdrTrue  = 1u;
constexpr uint32_t kXdrFalse = 0u;

constexpr uint32_t kDefineResultWords       = 1u;
constexpr uint32_t kCreateClientResultWords = 3u;
constexpr uint32_t kIssueRequestResultWords = 2u;

constexpr uint32_t kIssueRequestPayloadBytes = kPacmarkBytes + kCallArgsOff + 12u;

constexpr uint32_t kReqArgHandleOff   = kCallArgsOff +  0u;
constexpr uint32_t kReqArgValueOff    = kCallArgsOff +  4u;
constexpr uint32_t kReqArgSuppliedOff = kCallArgsOff +  8u;

constexpr uint32_t kCallPayloadBytes = 64u;

/* RFC 5531 section 9: reply_body is a union whose discriminant is reply_stat,
   so xid, msg_type and reply_stat appear on both of its arms. */
constexpr uint32_t kReplyCommonBytes = kReplyStatOff + 4u;

/* RFC 5531 section 9: accepted_reply is the verifier followed by a union whose
   discriminant is accept_stat, whose SUCCESS arm alone carries results and
   whose PROG_UNAVAIL, PROC_UNAVAIL, GARBAGE_ARGS and SYSTEM_ERR arms are void. */
constexpr uint32_t kReplyAcceptedBytes = kReplyAcceptStatOff + 4u;

constexpr uint32_t kCallArg0Off    = kCallArgsOff +  0u;
constexpr uint32_t kCallArg1Off    = kCallArgsOff +  4u;
constexpr uint32_t kCallArg2Off    = kCallArgsOff +  8u;
constexpr uint32_t kCallArgCbOff   = kCallArgsOff + 12u;
constexpr uint32_t kCallArgNodeOff = kCallArgsOff + 16u;

constexpr uint32_t kDefineArg0       = 1u;
constexpr uint32_t kNoCallbackHandle = 0xFFFFFFFFu;

constexpr uint32_t kCbProg      = 0x310000A4u;
constexpr uint32_t kCbProc      = 1u;
constexpr uint32_t kCbClientCid = 2u;
constexpr uint32_t kCbBodyBytes = 60u;
constexpr uint32_t kCbReplyBytes = 28u;

constexpr uint32_t kCbArgIndexOff = kCallArgsOff +  0u;
constexpr uint32_t kCbArgNodeOff  = kCallArgsOff +  4u;
constexpr uint32_t kCbArgSpareOff = kCallArgsOff +  8u;
constexpr uint32_t kCbArgCountOff = kCallArgsOff + 12u;
constexpr uint32_t kCbArgLastOff  = kCallArgsOff + 16u;

}

bool Msm8255NpaRemoteServer::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSoc() == SocFamily::MSM8255;
}

void Msm8255NpaRemoteServer::OnReady() {
    emu_.Get<Msm8255RpcServerRegistry>().Register(this);
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        next_xid_       = 1;
        cb_xid_         = 0;
        cb_proc_        = 0;
        cb_outstanding_ = false;

        last_client_handle_ = 0;
    });
}

uint32_t Msm8255NpaRemoteServer::ServerProg() const { return kNpaProg; }
uint32_t Msm8255NpaRemoteServer::ServerVers() const { return kNpaVers; }
uint32_t Msm8255NpaRemoteServer::ServerCid() const { return kNpaCid; }
bool Msm8255NpaRemoteServer::CallbackClientCid(uint32_t& cid) const {
    cid = kCbClientCid;
    return true;
}

uint32_t Msm8255NpaRemoteServer::AnswerCall(uint32_t in_pa, uint32_t size,
                                            uint32_t out_pa, uint32_t out_cap,
                                            uint32_t self_pid,
                                            uint32_t peer_pid,
                                            uint32_t peer_cid) {
    auto& codec = emu_.Get<Msm8255OncrpcCodec>();

    const Msm8255OncrpcCall call = codec.ParseCall(*this, in_pa, size);

    if (call.proc != kProcDefineNode && call.proc != kProcDefineResource &&
        call.proc != kProcCreateClient && call.proc != kProcIssueRequest) {
        emu_.Get<Fatal>().Die(
            "msm8255 npa remote server: rpc procedure %u with a %u-byte payload "
            "is not modeled", call.proc, size);
    }

    if (call.proc == kProcCreateClient) {
        return AnswerCreateClient(call.body, size, out_pa, out_cap, self_pid,
                                  peer_pid, peer_cid, call.xid);
    }
    if (call.proc == kProcIssueRequest) {
        return AnswerIssueRequest(call.body, size, out_pa, out_cap, self_pid,
                                  peer_pid, peer_cid, call.xid);
    }

    uint32_t callback = 0u;
    uint32_t node     = 0u;
    if (call.proc == kProcDefineNode) {
        ReadDefineNodeArgs(call.body, size, callback, node);
    } else {
        ReadDefineResourceArgs(call.body, size, callback, node);
    }

    const uint32_t results[kDefineResultWords] = {kNpaResult};
    uint32_t written = codec.WriteAcceptedReply(
        out_pa, out_cap, self_pid, kNpaCid, peer_pid, peer_cid, call.xid,
        results, kDefineResultWords);
    if (callback != kNoCallbackHandle) {
        written += EmitCallback(out_pa, out_cap, written, self_pid, call.proc,
                                callback, node);
    }
    return written;
}

void Msm8255NpaRemoteServer::ReadDefineNodeArgs(uint32_t body, uint32_t size,
                                                uint32_t& callback,
                                                uint32_t& object) {
    auto& mem = emu_.Get<EmulatedMemory>();

    emu_.Get<Msm8255OncrpcCodec>().RequireCallBytes(*this, kProcDefineNode,
                                                    size, kCallPayloadBytes);

    const uint32_t arg0 = Be32(mem.ReadWord(body + kCallArg0Off));
    const uint32_t arg1 = Be32(mem.ReadWord(body + kCallArg1Off));
    const uint32_t arg2 = Be32(mem.ReadWord(body + kCallArg2Off));
    if (arg0 != kDefineArg0 || arg1 != 0u || arg2 != 0u) {
        emu_.Get<Fatal>().Die(
            "msm8255 npa remote server: rpc call arguments %u %u %u are not the "
            "request this peer models", arg0, arg1, arg2);
    }

    callback = Be32(mem.ReadWord(body + kCallArgCbOff));
    object   = Be32(mem.ReadWord(body + kCallArgNodeOff));
}

void Msm8255NpaRemoteServer::ReadDefineResourceArgs(uint32_t body,
                                                    uint32_t size,
                                                    uint32_t& callback,
                                                    uint32_t& object) {
    auto& mem = emu_.Get<EmulatedMemory>();

    const uint32_t off =
        emu_.Get<Msm8255OncrpcCodec>().SkipXdrString(body, size, kCallArgsOff,
                                                     1u);
    const uint32_t want = kPacmarkBytes + off + 8u;
    emu_.Get<Msm8255OncrpcCodec>().RequireCallBytes(*this, kProcDefineResource,
                                                    size, want);

    callback = Be32(mem.ReadWord(body + off));
    object   = Be32(mem.ReadWord(body + off + 4u));
}

void Msm8255NpaRemoteServer::ReadCreateClientArgs(uint32_t body, uint32_t size,
                                                  uint32_t& type,
                                                  uint32_t& supplied) {
    auto& mem = emu_.Get<EmulatedMemory>();

    auto& codec = emu_.Get<Msm8255OncrpcCodec>();

    const uint32_t resource = codec.SkipXdrString(body, size, kCallArgsOff, 1u);
    const uint32_t client   = codec.SkipXdrString(body, size, resource, 2u);
    const uint32_t want     = kPacmarkBytes + client + 8u;
    codec.RequireCallBytes(*this, kProcCreateClient, size, want);

    type     = Be32(mem.ReadWord(body + client));
    supplied = Be32(mem.ReadWord(body + client + 4u));
    if (type > kClientTypeMax) {
        emu_.Get<Fatal>().Die(
            "msm8255 npa remote server: the create-client call asks for client "
            "type %u, and the guest encodes only types 0 through %u", type,
            kClientTypeMax);
    }
    if (supplied != kXdrTrue) {
        emu_.Get<Fatal>().Die(
            "msm8255 npa remote server: the create-client call passes %u for the "
            "out-pointer it supplied, and only a supplied one is modeled",
            supplied);
    }
}

uint32_t Msm8255NpaRemoteServer::AnswerCreateClient(
    uint32_t body, uint32_t size, uint32_t out_pa, uint32_t out_cap,
    uint32_t self_pid, uint32_t peer_pid, uint32_t peer_cid, uint32_t xid) {
    uint32_t type     = 0u;
    uint32_t supplied = 0u;
    ReadCreateClientArgs(body, size, type, supplied);

    const uint32_t handle = ++last_client_handle_;
    const uint32_t results[kCreateClientResultWords] = {kNpaResult, kXdrTrue,
                                                        handle};
    const uint32_t written =
        emu_.Get<Msm8255OncrpcCodec>().WriteAcceptedReply(
            out_pa, out_cap, self_pid, kNpaCid, peer_pid, peer_cid, xid,
            results, kCreateClientResultWords);
    return written;
}

uint32_t Msm8255NpaRemoteServer::AnswerIssueRequest(
    uint32_t body, uint32_t size, uint32_t out_pa, uint32_t out_cap,
    uint32_t self_pid, uint32_t peer_pid, uint32_t peer_cid, uint32_t xid) {
    auto& mem = emu_.Get<EmulatedMemory>();

    emu_.Get<Msm8255OncrpcCodec>().RequireCallBytes(
        *this, kProcIssueRequest, size, kIssueRequestPayloadBytes);

    const uint32_t handle   = Be32(mem.ReadWord(body + kReqArgHandleOff));
    const uint32_t value    = Be32(mem.ReadWord(body + kReqArgValueOff));
    const uint32_t supplied = Be32(mem.ReadWord(body + kReqArgSuppliedOff));

    if (handle == 0u || handle > last_client_handle_) {
        emu_.Get<Fatal>().Die(
            "msm8255 npa remote server: the issue-request call names client "
            "handle %u, and this peer has issued %u", handle,
            last_client_handle_);
    }
    if (value != 0u) {
        emu_.Get<Fatal>().Die(
            "msm8255 npa remote server: client handle %u requests %u of its "
            "resource, and this peer drives no resource that can meet a "
            "non-zero request", handle, value);
    }
    if (supplied != kXdrFalse) {
        emu_.Get<Fatal>().Die(
            "msm8255 npa remote server: the issue-request call passes %u for "
            "the out-pointer it supplied, and only an absent one is modeled",
            supplied);
    }

    const uint32_t results[kIssueRequestResultWords] = {kNpaResult, kXdrFalse};
    const uint32_t written =
        emu_.Get<Msm8255OncrpcCodec>().WriteAcceptedReply(
            out_pa, out_cap, self_pid, kNpaCid, peer_pid, peer_cid, xid,
            results, kIssueRequestResultWords);
    return written;
}

uint32_t Msm8255NpaRemoteServer::EmitCallback(uint32_t out_pa,
                                              uint32_t out_cap,
                                              uint32_t reserved,
                                              uint32_t self_pid,
                                              uint32_t proc,
                                              uint32_t cb_index,
                                              uint32_t node) {
    auto& mem    = emu_.Get<EmulatedMemory>();
    auto& router = emu_.Get<Msm8255RpcRouterPeer>();

    const uint32_t bytes = kHdrBytes + kPacmarkBytes + kCbBodyBytes;
    if (out_cap < reserved + bytes) {
        emu_.Get<Fatal>().Die(
            "msm8255 npa remote server: the modem fifo has %u contiguous bytes "
            "free, and the procedure %u callback needs %u after the %u already "
            "written", out_cap, proc, bytes, reserved);
    }

    uint32_t srv_pid = 0;
    uint32_t srv_cid = 0;
    if (!router.AnnouncedServer(srv_pid, srv_cid)) {
        emu_.Get<Fatal>().Die(
            "msm8255 npa remote server: the guest registered callback index %u "
            "before announcing the server endpoint that receives it", cb_index);
    }
    if (cb_outstanding_) {
        emu_.Get<Fatal>().Die(
            "msm8255 npa remote server: the callback xid %u this peer issued for "
            "procedure %u is still unanswered, and more than one outstanding "
            "callback is not modeled", cb_xid_, cb_proc_);
    }

    cb_xid_         = ++next_xid_;
    cb_proc_        = proc;
    cb_outstanding_ = true;

    const uint32_t at = out_pa + reserved;
    router.WriteHeader(at, kCtrlCmdData, self_pid, kCbClientCid,
                       kPacmarkBytes + kCbBodyBytes, srv_pid, srv_cid);
    mem.WriteWord(at + kHdrBytes, router.NextPacmark(kCbBodyBytes));

    const uint32_t out = at + kHdrBytes + kPacmarkBytes;
    mem.WriteWord(out + kCallXidOff,        Be32(cb_xid_));
    mem.WriteWord(out + kCallTypeOff,       Be32(kOncrpcCall));
    mem.WriteWord(out + kCallRpcVersOff,    Be32(kOncrpcVersion));
    mem.WriteWord(out + kCallProgOff,       Be32(kCbProg));
    mem.WriteWord(out + kCallVersOff,       Be32(kNpaVers));
    mem.WriteWord(out + kCallProcOff,       Be32(kCbProc));
    mem.WriteWord(out + kCallCredFlavorOff, Be32(kAuthNone));
    mem.WriteWord(out + kCallCredLenOff,    Be32(0u));
    mem.WriteWord(out + kCallVerfFlavorOff, Be32(kAuthNone));
    mem.WriteWord(out + kCallVerfLenOff,    Be32(0u));
    mem.WriteWord(out + kCbArgIndexOff,     Be32(cb_index));
    mem.WriteWord(out + kCbArgNodeOff,      Be32(node));
    mem.WriteWord(out + kCbArgSpareOff,     Be32(0u));
    mem.WriteWord(out + kCbArgCountOff,     Be32(0u));
    mem.WriteWord(out + kCbArgLastOff,      Be32(0u));
    return bytes;
}

uint32_t Msm8255NpaRemoteServer::ConsumeCallbackReply(uint32_t in_pa,
                                                      uint32_t size,
                                                      uint32_t out_pa,
                                                      uint32_t out_cap) {
    (void)out_pa;
    (void)out_cap;

    auto& mem    = emu_.Get<EmulatedMemory>();
    auto& router = emu_.Get<Msm8255RpcRouterPeer>();

    if (size < kPacmarkBytes + kReplyCommonBytes) {
        emu_.Get<Fatal>().Die(
            "msm8255 npa remote server: the callback reply is %u bytes, which "
            "is short of the %u bytes every reply carries", size,
            kPacmarkBytes + kReplyCommonBytes);
    }

    router.ValidatePacmark(mem.ReadWord(in_pa + kHdrBytes),
                           size - kPacmarkBytes);

    const uint32_t body = in_pa + kHdrBytes + kPacmarkBytes;
    const uint32_t xid  = Be32(mem.ReadWord(body + kReplyXidOff));
    const uint32_t type = Be32(mem.ReadWord(body + kReplyTypeOff));
    const uint32_t stat = Be32(mem.ReadWord(body + kReplyStatOff));

    if (type != kOncrpcReply) {
        emu_.Get<Fatal>().Die(
            "msm8255 npa remote server: the guest sent rpc message type %u to "
            "the callback client, and only a reply is modeled", type);
    }
    if (stat != kMsgAccepted) {
        emu_.Get<Fatal>().Die(
            "msm8255 npa remote server: the callback reply carries reply_stat "
            "%u, and only an accepted reply is modeled", stat);
    }
    if (!cb_outstanding_) {
        emu_.Get<Fatal>().Die(
            "msm8255 npa remote server: the guest answered a callback that this "
            "peer never issued");
    }
    if (xid != cb_xid_) {
        emu_.Get<Fatal>().Die(
            "msm8255 npa remote server: the callback reply carries xid %u and "
            "the outstanding callback is xid %u", xid, cb_xid_);
    }
    if (size < kPacmarkBytes + kReplyAcceptedBytes) {
        emu_.Get<Fatal>().Die(
            "msm8255 npa remote server: the accepted callback reply is %u "
            "bytes, which is short of the %u that carry its verifier and "
            "accept_stat", size, kPacmarkBytes + kReplyAcceptedBytes);
    }

    const uint32_t vfl  = Be32(mem.ReadWord(body + kReplyVerfFlavorOff));
    const uint32_t vlen = Be32(mem.ReadWord(body + kReplyVerfLenOff));
    const uint32_t acc  = Be32(mem.ReadWord(body + kReplyAcceptStatOff));
    if (vfl != kAuthNone || vlen != 0u) {
        emu_.Get<Fatal>().Die(
            "msm8255 npa remote server: the callback reply verifier is flavor "
            "%u length %u, and only the null verifier is modeled", vfl, vlen);
    }
    if (acc != kAcceptSuccess) {
        emu_.Get<Fatal>().Die(
            "msm8255 npa remote server: the guest answered this peer's callback "
            "for procedure %u with accept_stat %u, and only success is modeled",
            cb_proc_, acc);
    }
    if (size != kPacmarkBytes + kCbReplyBytes) {
        emu_.Get<Fatal>().Die(
            "msm8255 npa remote server: the successful callback reply is %u "
            "bytes, and only the %u-byte form is modeled", size,
            kPacmarkBytes + kCbReplyBytes);
    }

    const uint32_t rc = Be32(mem.ReadWord(body + kReplyResultsOff));
    if (rc != kNpaResult) {
        emu_.Get<Fatal>().Die(
            "msm8255 npa remote server: the guest's callback for procedure %u "
            "returned %u", cb_proc_, rc);
    }

    cb_outstanding_ = false;
    return 0u;
}

void Msm8255NpaRemoteServer::SaveState(StateWriter& w) {
    w.Write<uint32_t>(next_xid_);
    w.Write<uint32_t>(cb_xid_);
    w.Write<uint32_t>(cb_proc_);
    w.Write<uint32_t>(cb_outstanding_ ? 1u : 0u);
    w.Write<uint32_t>(last_client_handle_);
}

void Msm8255NpaRemoteServer::RestoreState(StateReader& r) {
    uint32_t outstanding = 0;
    r.Read(next_xid_);
    r.Read(cb_xid_);
    r.Read(cb_proc_);
    r.Read(outstanding);
    r.Read(last_client_handle_);
    cb_outstanding_ = outstanding != 0u;
}

REGISTER_SERVICE(Msm8255NpaRemoteServer);
