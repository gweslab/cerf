#pragma once

#include "../../core/byte_order.h"

#include <cstdint>

/* Linux arch/arm/mach-msm smd_rpcrouter.h: struct rr_header. */
inline constexpr uint32_t kHdrVersionOff   = 0u;
inline constexpr uint32_t kHdrTypeOff      = 4u;
inline constexpr uint32_t kHdrSrcPidOff    = 8u;
inline constexpr uint32_t kHdrSrcCidOff    = 12u;
inline constexpr uint32_t kHdrConfirmRxOff = 16u;
inline constexpr uint32_t kHdrSizeOff      = 20u;
inline constexpr uint32_t kHdrDstPidOff    = 24u;
inline constexpr uint32_t kHdrDstCidOff    = 28u;
inline constexpr uint32_t kHdrBytes        = 32u;

/* Linux arch/arm/mach-msm smd_rpcrouter.h: union rr_control_msg, whose widest
   arm is the five-word srv form and whose cli arm is {cmd, pid, cid}. */
inline constexpr uint32_t kCtrlMsgBytes = 20u;
inline constexpr uint32_t kSrvProgOff   = 4u;
inline constexpr uint32_t kSrvVersOff   = 8u;
inline constexpr uint32_t kSrvPidOff    = 12u;
inline constexpr uint32_t kSrvCidOff    = 16u;
inline constexpr uint32_t kCliPidOff    = 4u;
inline constexpr uint32_t kCliCidOff    = 8u;

/* Linux arch/arm/mach-msm smd_rpcrouter.h: the PACMARK constructor and its
   PACMARK_LEN, PACMARK_MID and PACMARK_LAST accessors. */
inline constexpr uint32_t kPacmarkLenMask  = 0x0000FFFFu;
inline constexpr uint32_t kPacmarkMidShift = 16u;
inline constexpr uint32_t kPacmarkMidMask  = 0x000000FFu;
inline constexpr uint32_t kPacmarkFirst    = 1u << 30;
inline constexpr uint32_t kPacmarkLast     = 1u << 31;
inline constexpr uint32_t kPacmarkBytes    = 4u;

/* Linux arch/arm/mach-msm smd_rpcrouter.h: RPCROUTER_VERSION,
   RPCROUTER_ROUTER_ADDRESS, RPCROUTER_MSGSIZE_MAX and the RPCROUTER_CTRL_CMD_*
   command numbers. */
inline constexpr uint32_t kRouterMsgSizeMax  = 512u;
inline constexpr uint32_t kRouterVersion     = 1u;
inline constexpr uint32_t kRouterAddress     = 0xFFFFFFFEu;
inline constexpr uint32_t kCtrlCmdData       = 1u;
inline constexpr uint32_t kCtrlCmdHello      = 2u;
inline constexpr uint32_t kCtrlCmdNewServer  = 4u;
inline constexpr uint32_t kCtrlCmdResumeTx   = 7u;

/* RFC 5531 section 9 The RPC Message Protocol: enum msg_type CALL 0 REPLY 1,
   rpcvers MUST equal 2, enum reply_stat MSG_ACCEPTED 0, enum accept_stat
   SUCCESS 0; enum auth_flavor gives AUTH_NONE the value 0. */
inline constexpr uint32_t kOncrpcCall    = 0u;
inline constexpr uint32_t kOncrpcReply   = 1u;
inline constexpr uint32_t kOncrpcVersion = 2u;
inline constexpr uint32_t kMsgAccepted   = 0u;
inline constexpr uint32_t kAcceptSuccess = 0u;
inline constexpr uint32_t kAuthNone      = 0u;

/* RFC 5531 section 9: a call body is xid, msg_type, rpcvers, prog, vers, proc,
   then the cred and verf opaque_auth pairs, then the procedure arguments. */
inline constexpr uint32_t kCallXidOff        =  0u;
inline constexpr uint32_t kCallTypeOff       =  4u;
inline constexpr uint32_t kCallRpcVersOff    =  8u;
inline constexpr uint32_t kCallProgOff       = 12u;
inline constexpr uint32_t kCallVersOff       = 16u;
inline constexpr uint32_t kCallProcOff       = 20u;
inline constexpr uint32_t kCallCredFlavorOff = 24u;
inline constexpr uint32_t kCallCredLenOff    = 28u;
inline constexpr uint32_t kCallVerfFlavorOff = 32u;
inline constexpr uint32_t kCallVerfLenOff    = 36u;
inline constexpr uint32_t kCallArgsOff       = 40u;

/* RFC 5531 section 9: an accepted reply is xid, msg_type, reply_stat, the verf
   opaque_auth pair, accept_stat, then the procedure results. */
inline constexpr uint32_t kReplyXidOff        =  0u;
inline constexpr uint32_t kReplyTypeOff       =  4u;
inline constexpr uint32_t kReplyStatOff       =  8u;
inline constexpr uint32_t kReplyVerfFlavorOff = 12u;
inline constexpr uint32_t kReplyVerfLenOff    = 16u;
inline constexpr uint32_t kReplyAcceptStatOff = 20u;
inline constexpr uint32_t kReplyResultsOff    = 24u;

constexpr uint32_t Be32(uint32_t v) { return cerf::ByteSwap32(v); }
