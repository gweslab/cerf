#include "ford_sync2_ilp_signal_tables.h"
#include "ford_sync2_ilp_descriptors.h"
#include <iterator>
#include "ford_sync2_ilp_signals.h"

#include "../board_context.h"
#include "ford_sync_2_id.h"
#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../state/state_stream.h"

#include <cstddef>
#include <cstdint>
#include <vector>

REGISTER_SERVICE(FordSync2IlpSignals);

namespace {
using cerf::le::Append16;
using cerf::le::Append32;
using cerf::le::AppendN;
using cerf::le::U16;
using cerf::le::U32;
}

namespace {

using cerf_ford_sync2_ilp_detail::GroundedSignal;
using cerf_ford_sync2_ilp_detail::kGroundedSignals;


static_assert(sizeof(kGroundedSignals) / sizeof(kGroundedSignals[0]) ==
                  FordSync2IlpSignals::kSignalCount,
              "signal table size must match the reported_/pending_ array bound");

/* ford_sync_2 ipc_ilprot.dll sub_C08DCE54: the value occupies
   ((bits - 1) + 8) >> 3 bytes on the wire, little-endian. */
constexpr std::size_t WireWidth(uint8_t bits) {
    return (static_cast<std::size_t>(bits) + 7u) >> 3;
}

/* ford_sync_2 ipc_ilprot.dll sub_C08DC334 case 0x84: a response longer than the
   waiting slot's 0x40-byte buffer is discarded and the read returns no data. */
constexpr std::size_t kMaxReplyPayload = 0x40u;

}

bool FordSync2IlpSignals::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::FordSync2;
}

std::size_t FordSync2IlpSignals::IndexOf(uint32_t sigid) const {
    for (std::size_t i = 0; i < kSignalCount; ++i) {
        if (kGroundedSignals[i].sigid == sigid) return i;
    }
    return kSignalCount;
}

std::size_t FordSync2IlpSignals::GroundedSignalCount() const { return kSignalCount; }

uint32_t FordSync2IlpSignals::GroundedSignalIdAt(std::size_t i) const {
    return i < kSignalCount ? kGroundedSignals[i].sigid : 0u;
}

uint8_t FordSync2IlpSignals::GroundedSignalBitsAt(std::size_t i) const {
    return i < kSignalCount ? kGroundedSignals[i].bits : 0u;
}

/* ford_sync_2 ipc_ilprot.dll sub_C08DB2BC delivers to every node of the per-signal
   circular list whose TID at +0x34 matches, so one SigID carries one subscriber per
   registered filter and each needs its own indication. */
std::size_t FordSync2IlpSignals::NoteFilterRegistration(uint32_t sigid, uint16_t tid) {
    const std::size_t idx = IndexOf(sigid);
    if (idx == kSignalCount) return kNoSubscriber;
    const std::size_t n = sub_count_[idx].load(std::memory_order_relaxed);
    for (std::size_t s = 0; s < n; ++s) {
        if (sub_tid_[idx][s].load(std::memory_order_relaxed) == tid) return s;
    }
    if (n >= kMaxSubscribers) {
        if (!warned_sub_overflow_) {
            warned_sub_overflow_ = true;
            LOG(Caution, "[VMCU] ILP subscriber table full for SigID=0x%08X tid=%u\n",
                sigid, static_cast<unsigned>(tid));
        }
        return kNoSubscriber;
    }
    sub_tid_[idx][n].store(tid, std::memory_order_relaxed);
    sub_count_[idx].store(static_cast<uint8_t>(n + 1u), std::memory_order_relaxed);
    LOG(Board, "[VMCU] ILP filter SigID=0x%08X tid=%u subscriber=%zu\n", sigid,
        static_cast<unsigned>(tid), n);
    return n;
}

std::size_t FordSync2IlpSignals::HeadWriteWidth(uint32_t sigid) {
    using namespace cerf_ford_sync2_ilp_detail;
    const uint32_t index = sigid & 0xFFFFFFu;
    uint8_t bits = 0;
    switch (sigid >> 24) {
    case 0: if (index < std::size(kAssociation0Bits)) bits = kAssociation0Bits[index]; break;
    case 1: if (index < std::size(kAssociation1Bits)) bits = kAssociation1Bits[index]; break;
    case 2: if (index < std::size(kAssociation2Bits)) bits = kAssociation2Bits[index]; break;
    }
    return WireWidth(bits);
}

std::size_t FordSync2IlpSignals::SubscriberCount(uint32_t sigid) const {
    const std::size_t idx = IndexOf(sigid);
    return idx == kSignalCount
               ? 0u
               : static_cast<std::size_t>(sub_count_[idx].load(std::memory_order_relaxed));
}

bool FordSync2IlpSignals::IsReported(uint32_t sigid) const {
    const std::size_t idx = IndexOf(sigid);
    return idx != kSignalCount && reporting_[idx].load(std::memory_order_acquire);
}

uint64_t FordSync2IlpSignals::ReportedValue(uint32_t sigid) const {
    const std::size_t idx = IndexOf(sigid);
    return idx == kSignalCount ? 0u : reported_[idx].load(std::memory_order_relaxed);
}

void FordSync2IlpSignals::SetReportedValue(uint32_t sigid, uint64_t value) {
    const std::size_t idx = IndexOf(sigid);
    if (idx == kSignalCount) return;
    reported_[idx].store(value, std::memory_order_relaxed);
    reporting_[idx].store(true, std::memory_order_release);
    pending_[idx].store(true, std::memory_order_release);
}

void FordSync2IlpSignals::ClearReportedValue(uint32_t sigid) {
    const std::size_t idx = IndexOf(sigid);
    if (idx == kSignalCount) return;
    reporting_[idx].store(false, std::memory_order_release);
    pending_[idx].store(false, std::memory_order_release);
    reported_[idx].store(0u, std::memory_order_relaxed);
}

void FordSync2IlpSignals::AppendGetAssocReply(const uint8_t* req, std::size_t n,
                                              uint16_t tid, std::vector<uint8_t>& pkt) {
    /* ford_sync_2 ipc_ilprot.dll sub_C08DCFEC: request is [04][00][TID:2]
       [Count:2] then Count x [SigID32 LE]; the packer sub_C08DCCF0 emits the
       4-byte SigID only. */
    std::vector<uint8_t> body;
    uint16_t answered = 0u;
    std::size_t used = 6u;

    const uint16_t count =
        (n >= 6u) ? U16(req, 4) : uint16_t{0};
    for (uint16_t i = 0; i < count; ++i) {
        const std::size_t o = 6u + static_cast<std::size_t>(i) * 4u;
        if (o + 4u > n) break;
        const uint32_t sigid = U32(req, o);
        /* ford_sync_2 ipc_ilprot.dll sub_C08DE3A4 returns 0xC0000030 when matched
           != requested, so any omission fails the head's whole read and discards
           the values that were sent; its caller ford_sync_2 VNIAudioSvc.dll
           sub_C14EA7DC skips on that failure. */
        const std::size_t idx = IndexOf(sigid);
        if (idx != kSignalCount && !reporting_[idx].load(std::memory_order_acquire))
            continue;
        if (idx == kSignalCount) {
            bool seen = false;
            for (uint32_t s : logged_ungrounded_) {
                if (s == sigid) { seen = true; break; }
            }
            if (!seen) {
                logged_ungrounded_.push_back(sigid);
                LOG(Caution, "[VMCU] ungrounded ILP signal read SigID=0x%08X\n", sigid);
            }
            continue;
        }
        const std::size_t width = WireWidth(kGroundedSignals[idx].bits);
        if (used + 4u + width > kMaxReplyPayload) {
            if (!warned_reply_truncated_) {
                warned_reply_truncated_ = true;
                LOG(Caution,
                    "[VMCU] ILP read of %u signals overruns the 0x40-byte reply slot "
                    "after %u; the head fails the whole read\n",
                    static_cast<unsigned>(count), static_cast<unsigned>(answered));
            }
            break;
        }
        Append32(body, sigid);
        AppendN(body, reported_[idx].load(std::memory_order_relaxed), width);
        used += 4u + width;
        ++answered;
    }

    /* ford_sync_2 ipc_ilprot.dll sub_C08DE3A4: [0x84][StatusCode][TID:2]
       [NumSignals:2] then NumSignals x [SigID32 LE][value LE]. StatusCode
       0x00 / 0x20 / 0x88 are the accepted non-error codes; sub_C08DD3FC treats
       0x81 / 0x82 as the queue-underflow / queue-overflow errors. */
    pkt.push_back(0x84u);
    pkt.push_back(0x00u);
    Append16(pkt, tid);
    Append16(pkt, answered);
    pkt.insert(pkt.end(), body.begin(), body.end());
}

bool FordSync2IlpSignals::AppendSignalIndication(uint32_t sigid, std::size_t sub,
                                                 std::vector<uint8_t>& pkt) {
    const std::size_t idx = IndexOf(sigid);
    if (idx == kSignalCount) return false;
    if (!reporting_[idx].load(std::memory_order_acquire)) return false;
    if (sub >= static_cast<std::size_t>(sub_count_[idx].load(std::memory_order_relaxed)))
        return false;

    /* ford_sync_2 ipc_ilprot.dll sub_C08DD3FC passes bytes [2..3] to sub_C08DB2BC,
       which delivers only when they equal the TID sub_C08D9A10 stored at
       filter+0x34; a wrong TID is dropped silently unless ctx+0x744 (registry
       "VMCUSingleFilter") is set. sub_C08DC334 routes only above length 10. */
    const uint16_t tid = sub_tid_[idx][sub].load(std::memory_order_relaxed);
    pkt.push_back(0x0Au);
    /* StatusCode: ford_sync_2 ipc_ilprot.dll sub_C08DD3FC maps 0x00 / 0x81 / 0x82 to 2,
       0x20 to 0 and 0x88 to 1 in field +4 of the 24-byte record sub_C08DAF58 queues;
       ford_sync_2 VNIClimateSvc.dll CVNISignalListener::ReadSignals sub_C153A2E8
       consumes a record only when field +4 is 2, 3 or 4. */
    pkt.push_back(0x00u);
    Append16(pkt, tid);
    Append16(pkt, 1u);
    Append32(pkt, sigid);
    AppendN(pkt, reported_[idx].load(std::memory_order_relaxed),
            WireWidth(kGroundedSignals[idx].bits));
    return true;
}

void FordSync2IlpSignals::SaveState(StateWriter& w) const {
    w.Write<uint16_t>(static_cast<uint16_t>(kSignalCount));
    w.Write<uint16_t>(static_cast<uint16_t>(kMaxSubscribers));
    for (std::size_t i = 0; i < kSignalCount; ++i) {
        w.Write<uint8_t>(sub_count_[i].load(std::memory_order_relaxed));
        for (std::size_t s = 0; s < kMaxSubscribers; ++s) {
            w.Write<uint16_t>(sub_tid_[i][s].load(std::memory_order_relaxed));
        }
    }
    w.Write<uint32_t>(static_cast<uint32_t>(cycle_));
}

void FordSync2IlpSignals::RestoreState(StateReader& r) {
    uint16_t n = 0u, subs_per_signal = 0u;
    r.Read(n);
    r.Read(subs_per_signal);
    if (!r.Ok() || n != kSignalCount || subs_per_signal != kMaxSubscribers) {
        LOG(Caution, "[VMCU] invalid ILP subscription snapshot\n");
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    for (uint16_t i = 0; i < n; ++i) {
        uint8_t subs = 0u;
        r.Read(subs);
        for (uint16_t s = 0; s < subs_per_signal; ++s) {
            uint16_t tid = 0u;
            r.Read(tid);
            if (i < kSignalCount && s < kMaxSubscribers)
                sub_tid_[i][s].store(tid, std::memory_order_relaxed);
        }
        if (i >= kSignalCount) continue;
        if (subs > kMaxSubscribers) subs = static_cast<uint8_t>(kMaxSubscribers);
        reported_[i].store(0, std::memory_order_relaxed);
        reporting_[i].store(false, std::memory_order_relaxed);
        pending_[i].store(false, std::memory_order_relaxed);
        sub_count_[i].store(subs, std::memory_order_relaxed);
    }
    uint32_t cycle = 0u;
    r.Read(cycle);
    cycle_ = cycle % kSignalCount;
}

void FordSync2IlpSignals::RegisterComposite(std::initializer_list<uint32_t> ids) {
    for (const auto id : ids) {
        const auto index = IndexOf(id);
        if (index == kSignalCount || groups_[index] != 0) {
            LOG(Caution, "[VMCU] invalid ILP composite registration\n");
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
    }
    ++group_count_;
    for (const auto id : ids) groups_[IndexOf(id)] = group_count_;
}

unsigned FordSync2IlpSignals::CompositeGroup(uint32_t sigid) const {
    const auto index = IndexOf(sigid);
    return index == kSignalCount ? 0 : groups_[index];
}

void FordSync2IlpSignals::RepublishComposites() {
    for (std::size_t i = 0; i < kSignalCount; ++i) {
        if (CompositeGroup(kGroundedSignals[i].sigid) == 0u) continue;
        if (!reporting_[i].load(std::memory_order_acquire)) continue;
        pending_[i].store(true, std::memory_order_release);
    }
}

/* ford_sync_2 ipc_ilprot.dll sub_C08DD3FC reads NumSignals at bytes [4..5].
   sub_C08DB2BC permits per-entry TIDs to differ when registry VMCUSingleFilter is set. */
std::size_t FordSync2IlpSignals::AppendBatchedIndication(uint32_t* sigids, std::size_t n,
                                                          std::vector<uint8_t>& pkt) {
    std::size_t used = 6u, emitted = 0u;
    std::vector<uint8_t> body;
    uint16_t tid   = 0u;
    unsigned group = 0u;
    for (std::size_t k = 0; k < n; ++k) {
        if (sigids[k] == kTakenSignal) continue;
        const std::size_t idx = IndexOf(sigids[k]);
        if (idx == kSignalCount) continue;
        if (!reporting_[idx].load(std::memory_order_acquire)) continue;
        if (sub_count_[idx].load(std::memory_order_relaxed) == 0u) continue;
        const std::size_t width = WireWidth(kGroundedSignals[idx].bits);
        if (emitted != 0u && CompositeGroup(sigids[k]) != group) continue;
        if (used + 4u + width > kMaxReplyPayload) break;
        if (emitted == 0u) {
            tid   = sub_tid_[idx][0].load(std::memory_order_relaxed);
            group = CompositeGroup(sigids[k]);
        }
        const uint32_t sigid = sigids[k];
        sigids[k]            = kTakenSignal;
        Append32(body, sigid);
        AppendN(body, reported_[idx].load(std::memory_order_relaxed), width);
        used += 4u + width;
        ++emitted;
    }
    if (emitted == 0u) return 0u;
    pkt.push_back(0x0Au);
    pkt.push_back(0x00u);
    Append16(pkt, tid);
    Append16(pkt, static_cast<uint16_t>(emitted));
    pkt.insert(pkt.end(), body.begin(), body.end());
    return emitted;
}

std::size_t FordSync2IlpSignals::TakeChangedSignals(uint32_t* out, std::size_t max) {
    std::size_t n = 0;
    for (std::size_t i = 0; i < kSignalCount && n < max; ++i) {
        if (!pending_[i].load(std::memory_order_acquire)) continue;
        if (!reporting_[i].load(std::memory_order_acquire)) continue;
        if (sub_count_[i].load(std::memory_order_relaxed) == 0u) continue;
        out[n++] = kGroundedSignals[i].sigid;
    }
    return n;
}

uint32_t FordSync2IlpSignals::NextCyclicSignal() {
    for (std::size_t n = 0; n < kSignalCount; ++n) {
        const std::size_t i = (cycle_ + n) % kSignalCount;
        if (!reporting_[i].load(std::memory_order_acquire)) continue;
        if (sub_count_[i].load(std::memory_order_relaxed) == 0u) continue;
        cycle_ = (i + 1u) % kSignalCount;
        return kGroundedSignals[i].sigid;
    }
    return kTakenSignal;
}

void FordSync2IlpSignals::MarkPublished(uint32_t sigid) {
    const auto index = IndexOf(sigid);
    if (index != kSignalCount) pending_[index].store(false, std::memory_order_release);
}

bool FordSync2IlpSignals::IsComposite(uint32_t sigid) const {
    return CompositeGroup(sigid) != 0;
}
