#include "msm8255_rpc_router_peer.h"

#include "msm8255_rpc_server.h"
#include "msm8255_rpc_server_registry.h"
#include "msm8255_rpcrouter_wire.h"

#include "../../boards/board_context.h"
#include "msm8255_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../cpu/emulated_memory.h"
#include "../../state/state_stream.h"
#include "../guest_cpu_reset.h"

#include <cstdint>

bool Msm8255RpcRouterPeer::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Msm8255;
}

void Msm8255RpcRouterPeer::OnReady() {
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        next_mid_  = 1;
        srv_pid_   = 0;
        srv_cid_   = 0;
        srv_known_ = false;
    });
}

uint32_t Msm8255RpcRouterPeer::Answer(uint32_t in_pa, uint32_t in_avail,
                                      uint32_t out_pa, uint32_t out_cap,
                                      uint32_t& consumed) {
    auto& mem      = emu_.Get<EmulatedMemory>();
    auto& registry = emu_.Get<Msm8255RpcServerRegistry>();

    if (in_avail < kHdrBytes) {
        emu_.Get<Fatal>().Die(
            "msm8255 rpc router peer: %u bytes are queued, which is short of "
            "the %u-byte router header", in_avail, kHdrBytes);
    }

    /* Linux arch/arm/mach-msm smd_rpcrouter.c do_read_data tests the header
       version before it reads any other header field, and bounds the declared
       size against RPCROUTER_MSGSIZE_MAX after that. */
    const uint32_t version = mem.ReadWord(in_pa + kHdrVersionOff);
    if (version != kRouterVersion) {
        emu_.Get<Fatal>().Die(
            "msm8255 rpc router peer: router version %u is not modeled",
            version);
    }

    const uint32_t size = mem.ReadWord(in_pa + kHdrSizeOff);
    if (size > kRouterMsgSizeMax) {
        emu_.Get<Fatal>().Die(
            "msm8255 rpc router peer: the header declares %u payload bytes and "
            "the router carries at most %u", size, kRouterMsgSizeMax);
    }
    if (in_avail < kHdrBytes + size) {
        emu_.Get<Fatal>().Die(
            "msm8255 rpc router peer: the header declares %u payload bytes and "
            "only %u are queued", size, in_avail - kHdrBytes);
    }
    consumed = kHdrBytes + size;

    const uint32_t dst_cid = mem.ReadWord(in_pa + kHdrDstCidOff);
    if (dst_cid != kRouterAddress) {
        for (auto* server : registry.Servers()) {
            uint32_t cb_cid  = 0;
            uint32_t written = 0;
            if (server->CallbackClientCid(cb_cid) && dst_cid == cb_cid) {
                written = server->ConsumeCallbackReply(in_pa, size, out_pa,
                                                       out_cap);
            } else if (dst_cid == server->ServerCid()) {
                written = server->AnswerCall(
                    in_pa, size, out_pa, out_cap,
                    mem.ReadWord(in_pa + kHdrDstPidOff),
                    mem.ReadWord(in_pa + kHdrSrcPidOff),
                    mem.ReadWord(in_pa + kHdrSrcCidOff));
            } else {
                continue;
            }
            return written +
                   AnswerConfirmRx(in_pa, out_pa, out_cap, written);
        }
        emu_.Get<Fatal>().Die(
            "msm8255 rpc router peer: the guest addressed cid 0x%08X, and none "
            "of the %u announced endpoints claims it",
            dst_cid, (uint32_t)registry.Servers().size());
    }

    if (size != kCtrlMsgBytes) {
        emu_.Get<Fatal>().Die(
            "msm8255 rpc router peer: router-addressed payload is %u bytes, and "
            "only the %u-byte control message is modeled", size, kCtrlMsgBytes);
    }

    const uint32_t confirm_rx = mem.ReadWord(in_pa + kHdrConfirmRxOff);
    if (confirm_rx != 0u) {
        emu_.Get<Fatal>().Die(
            "msm8255 rpc router peer: the guest asked for receive confirmation "
            "on a control message, which the router model never does");
    }

    const uint32_t type = mem.ReadWord(in_pa + kHdrTypeOff);
    const uint32_t cmd  = mem.ReadWord(in_pa + kHdrBytes);
    if (type != cmd) {
        emu_.Get<Fatal>().Die(
            "msm8255 rpc router peer: header type %u disagrees with payload "
            "command %u", type, cmd);
    }

    if (type == kCtrlCmdNewServer) {
        const uint32_t vers = mem.ReadWord(in_pa + kHdrBytes + kSrvVersOff);
        if (vers == 0u) {
            emu_.Get<Fatal>().Die(
                "msm8255 rpc router peer: the guest announced a server with "
                "version 0, which the router model rejects");
        }
        RecordAnnouncedServer(mem.ReadWord(in_pa + kHdrBytes + kSrvPidOff),
                              mem.ReadWord(in_pa + kHdrBytes + kSrvCidOff));
        return 0u;
    }

    if (type != kCtrlCmdHello) {
        emu_.Get<Fatal>().Die(
            "msm8255 rpc router peer: router control command %u is not modeled",
            type);
    }

    const uint32_t msg_bytes = kHdrBytes + kCtrlMsgBytes;
    const uint32_t announced = (uint32_t)registry.Servers().size();
    const uint32_t reply_bytes = (1u + announced) * msg_bytes;
    if (out_cap < reply_bytes) {
        emu_.Get<Fatal>().Die(
            "msm8255 rpc router peer: the modem fifo has %u bytes free, and "
            "the hello reply plus %u server announcements need %u",
            out_cap, announced, reply_bytes);
    }

    const uint32_t src_pid = mem.ReadWord(in_pa + kHdrSrcPidOff);
    const uint32_t dst_pid = mem.ReadWord(in_pa + kHdrDstPidOff);

    /* Linux arch/arm/mach-msm smd_rpcrouter.c: the hello arm answers with a
       hello of its own, then announces one new-server message per server the
       answering processor hosts. */
    WriteCtrlMsg(out_pa, kCtrlCmdHello, dst_pid, src_pid, 0u, 0u, 0u, 0u);
    uint32_t written = msg_bytes;
    for (auto* server : registry.Servers()) {
        WriteCtrlMsg(out_pa + written, kCtrlCmdNewServer, dst_pid, src_pid,
                     server->ServerProg(), server->ServerVers(), dst_pid,
                     server->ServerCid());
        written += msg_bytes;
    }
    return written;
}

void Msm8255RpcRouterPeer::ValidatePacmark(uint32_t pacmark,
                                           uint32_t body_bytes) {
    if ((pacmark & kPacmarkLenMask) != body_bytes) {
        emu_.Get<Fatal>().Die(
            "msm8255 rpc router peer: pacmark 0x%08X declares %u payload bytes "
            "and the router header declares %u", pacmark,
            pacmark & kPacmarkLenMask, body_bytes);
    }
    if ((pacmark & kPacmarkFirst) == 0u || (pacmark & kPacmarkLast) == 0u) {
        emu_.Get<Fatal>().Die(
            "msm8255 rpc router peer: pacmark 0x%08X is a fragment, and only a "
            "whole single-fragment message is modeled", pacmark);
    }
}

/* Linux arch/arm/mach-msm smd_rpcrouter.c msm_rpc_write: the sender allocates a
   fresh pacmark mid per message, from one counter masked to eight bits. */
uint32_t Msm8255RpcRouterPeer::NextPacmark(uint32_t body_bytes) {
    const uint32_t mid = ++next_mid_ & kPacmarkMidMask;
    return (body_bytes & kPacmarkLenMask) | (mid << kPacmarkMidShift) |
           kPacmarkFirst | kPacmarkLast;
}

/* Linux arch/arm/mach-msm smd_rpcrouter.c do_read_data: every data packet that
   asks for confirmation is answered with a resume-tx naming that packet's own
   destination, not only the ones the receiver replies to. */
uint32_t Msm8255RpcRouterPeer::AnswerConfirmRx(uint32_t in_pa, uint32_t out_pa,
                                               uint32_t out_cap,
                                               uint32_t reserved) {
    auto& mem = emu_.Get<EmulatedMemory>();

    const uint32_t confirm_rx = mem.ReadWord(in_pa + kHdrConfirmRxOff);
    if (confirm_rx == 0u) {
        return 0u;
    }
    if (confirm_rx != 1u) {
        emu_.Get<Fatal>().Die(
            "msm8255 rpc router peer: the message carries confirm_rx %u, and "
            "only the cleared and set forms are modeled", confirm_rx);
    }

    const uint32_t bytes = kHdrBytes + kCtrlMsgBytes;
    if (out_cap < reserved + bytes) {
        emu_.Get<Fatal>().Die(
            "msm8255 rpc router peer: the modem fifo has %u bytes free, and "
            "the resume-tx needs %u after the %u already reserved",
            out_cap, bytes, reserved);
    }
    const uint32_t self_pid = mem.ReadWord(in_pa + kHdrDstPidOff);
    WriteResumeTx(out_pa + reserved, self_pid,
                  mem.ReadWord(in_pa + kHdrSrcPidOff), self_pid,
                  mem.ReadWord(in_pa + kHdrDstCidOff));
    return bytes;
}

void Msm8255RpcRouterPeer::RecordAnnouncedServer(uint32_t pid, uint32_t cid) {
    if (srv_known_ && (pid != srv_pid_ || cid != srv_cid_)) {
        emu_.Get<Fatal>().Die(
            "msm8255 rpc router peer: the guest announced a second server "
            "endpoint at pid %u cid %u while pid %u cid %u is already known, "
            "and routing to more than one endpoint is not modeled",
            pid, cid, srv_pid_, srv_cid_);
    }
    srv_pid_   = pid;
    srv_cid_   = cid;
    srv_known_ = true;
}

bool Msm8255RpcRouterPeer::AnnouncedServer(uint32_t& pid, uint32_t& cid) const {
    pid = srv_pid_;
    cid = srv_cid_;
    return srv_known_;
}

void Msm8255RpcRouterPeer::WriteHeader(uint32_t out_pa, uint32_t type,
                                       uint32_t src_pid, uint32_t src_cid,
                                       uint32_t size, uint32_t dst_pid,
                                       uint32_t dst_cid) {
    auto& mem = emu_.Get<EmulatedMemory>();

    mem.WriteWord(out_pa + kHdrVersionOff,   kRouterVersion);
    mem.WriteWord(out_pa + kHdrTypeOff,      type);
    mem.WriteWord(out_pa + kHdrSrcPidOff,    src_pid);
    mem.WriteWord(out_pa + kHdrSrcCidOff,    src_cid);
    mem.WriteWord(out_pa + kHdrConfirmRxOff, 0u);
    mem.WriteWord(out_pa + kHdrSizeOff,      size);
    mem.WriteWord(out_pa + kHdrDstPidOff,    dst_pid);
    mem.WriteWord(out_pa + kHdrDstCidOff,    dst_cid);
}

/* Linux arch/arm/mach-msm smd_rpcrouter.c rpcrouter_send_control_msg: a control
   message is addressed router to router and carries its command word twice, in
   the header type and in the first payload word. */
void Msm8255RpcRouterPeer::WriteCtrlHeader(uint32_t out_pa, uint32_t cmd,
                                           uint32_t self_pid,
                                           uint32_t peer_pid) {
    WriteHeader(out_pa, cmd, self_pid, kRouterAddress, kCtrlMsgBytes, peer_pid,
                kRouterAddress);
    emu_.Get<EmulatedMemory>().WriteWord(out_pa + kHdrBytes, cmd);
}

void Msm8255RpcRouterPeer::WriteResumeTx(uint32_t out_pa, uint32_t self_pid,
                                         uint32_t peer_pid, uint32_t cli_pid,
                                         uint32_t cli_cid) {
    auto& mem = emu_.Get<EmulatedMemory>();

    WriteCtrlHeader(out_pa, kCtrlCmdResumeTx, self_pid, peer_pid);

    mem.WriteWord(out_pa + kHdrBytes + kCliPidOff, cli_pid);
    mem.WriteWord(out_pa + kHdrBytes + kCliCidOff, cli_cid);
    for (uint32_t off = kCliCidOff + 4u; off < kCtrlMsgBytes; off += 4u) {
        mem.WriteWord(out_pa + kHdrBytes + off, 0u);
    }
}

void Msm8255RpcRouterPeer::WriteCtrlMsg(uint32_t out_pa, uint32_t cmd,
                                        uint32_t self_pid, uint32_t peer_pid,
                                        uint32_t prog, uint32_t vers,
                                        uint32_t srv_pid, uint32_t srv_cid) {
    auto& mem = emu_.Get<EmulatedMemory>();

    WriteCtrlHeader(out_pa, cmd, self_pid, peer_pid);

    mem.WriteWord(out_pa + kHdrBytes + kSrvProgOff, prog);
    mem.WriteWord(out_pa + kHdrBytes + kSrvVersOff, vers);
    mem.WriteWord(out_pa + kHdrBytes + kSrvPidOff,  srv_pid);
    mem.WriteWord(out_pa + kHdrBytes + kSrvCidOff,  srv_cid);
}

void Msm8255RpcRouterPeer::SaveState(StateWriter& w) {
    w.Write<uint32_t>("next_mid", next_mid_);
    w.Write<uint32_t>("srv_pid", srv_pid_);
    w.Write<uint32_t>("srv_cid", srv_cid_);
    w.Write<uint32_t>("srv_known", srv_known_ ? 1u : 0u);
}

void Msm8255RpcRouterPeer::RestoreState(StateReader& r) {
    uint32_t known = 0;
    r.Read("next_mid", next_mid_);
    r.Read("srv_pid", srv_pid_);
    r.Read("srv_cid", srv_cid_);
    r.Read("srv_known", known);
    srv_known_ = known != 0u;
}

REGISTER_SERVICE(Msm8255RpcRouterPeer);
