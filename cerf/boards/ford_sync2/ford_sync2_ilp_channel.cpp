#include "ford_sync2_ilp_channel.h"
#include "ford_sync2_ilp_signals.h"
#include "ford_sync2_vmcu_peer.h"
#include "../board_context.h"
#include "ford_sync_2_id.h"
#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../host/emulation_pause.h"
#include "../../jit/jit_runner.h"
#include "../../state/emulation_freeze.h"
#include "../../state/state_stream.h"
#include <algorithm>
#include <utility>

REGISTER_SERVICE(FordSync2IlpChannel);

namespace {
using cerf::le::Put16;
using cerf::le::U16;
using cerf::le::U32;
using cerf::le::UN;
}

bool FordSync2IlpChannel::ShouldRegister() {
    auto* board = emu_.TryGet<BoardContext>();
    return board && board->GetBoardId() == BoardId::FordSync2;
}

bool FordSync2IlpChannel::DecodeSet(const uint8_t* data, std::size_t n,
                                    std::vector<Write>& writes, ParseError& error) {
    writes.clear();
    error = {};
    auto fail = [&](const char* reason, std::size_t offset, uint32_t id = 0) {
        error = {reason, offset, id}; writes.clear(); return false;
    };
    /* EA5T-14D544-BA.sec, ipc_ilprot.dll sub_C08DD274: SetSignalsAssoc builder. */
    if (n < 6 || n > 0x3F || data[0] != 2 || data[1] != 0) return fail("header", 0);
    const unsigned count = U16(data, 4);
    std::size_t offset = 6;
    for (unsigned i = 0; i < count; ++i) {
        if (n - offset < 4) return fail("truncated identifier", offset);
        const uint32_t id = U32(data, offset);
        const auto width = FordSync2IlpSignals::HeadWriteWidth(id);
        if (width == 0 || width > sizeof(uint64_t)) return fail("unknown width", offset, id);
        if (n - offset - 4 < width) return fail("truncated value", offset, id);
        writes.push_back({id, UN(data + offset + 4, width)});
        offset += 4 + width;
    }
    if (offset != n) return fail("trailing bytes", offset);
    return true;
}

void FordSync2IlpChannel::Send(const uint8_t* data, std::size_t n) {
    emu_.Get<FordSync2VmcuPeer>().InjectReliable(kCid, tx_seq_, data, n);
    ++sent_;
    tx_seq_ = static_cast<uint8_t>((tx_seq_ + 1) & 0x7F);
}

void FordSync2IlpChannel::Complete(uint8_t type, uint16_t tid, bool accepted) {
    /* EA5T-14D544-BA.sec, ipc_ilprot.dll sub_C08DC334, sub_C08DD9A0:
       the guest treats any nonzero Set completion as failure. CERF uses byte 1
       as a generic failure; no named physical VMCU rejection code is established.
       This application completion is separate from the transport ACK and status indications. */
    uint8_t reply[6] = {static_cast<uint8_t>(type | 0x80),
        static_cast<uint8_t>(accepted ? 0 : 1)};
    Put16(reply + 2, tid);
    Send(reply, type == 4 ? 6 : 4);
}

void FordSync2IlpChannel::HandleSet(const uint8_t* data, std::size_t n, uint16_t tid) {
    std::vector<Write> writes;
    ParseError error;
    if (!DecodeSet(data, n, writes, error)) {
        ++malformed_;
        LOG(Caution, "[VMCU] ILP rejected tid=%u: %s offset=%zu remaining=%zu id=0x%08X\n",
            tid, error.reason, error.offset, n - error.offset, error.id);
        Complete(2, tid, false);
        return;
    }
    const Device* owner = nullptr;
    bool unsupported = false;
    for (const auto& write : writes) {
        const Device* target = nullptr;
        for (const auto& device : devices_) {
            if (!device.owns || !device.owns(write.id)) continue;
            if (target) { unsupported = true; break; }
            target = &device;
        }
        if (!target || !target->apply || (owner && owner != target)) unsupported = true;
        if (target) owner = target;
        if (!target || logged_writes_ < 512) {
            if (logged_writes_ < 512) ++logged_writes_;
            LOG(Board, "[VMCU] ILP decoded tid=%u id=0x%08X value=%llu mapped=%u\n",
                tid, write.id, static_cast<unsigned long long>(write.value), target != nullptr);
        }
    }
    const auto result = unsupported ? Result::Unsupported :
        owner ? owner->apply(writes) : Result::Accepted;
    if (result == Result::Accepted) ++accepted_;
    else if (result == Result::Invalid) ++invalid_;
    else if (result == Result::Unavailable) ++unavailable_;
    else ++unsupported_;
    LOG(Board, "[VMCU] ILP completed tid=%u outcome=%u records=%zu\n", tid,
        static_cast<unsigned>(result), writes.size());
    Complete(2, tid, result == Result::Accepted);
    if (result == Result::Accepted) {
        Refresh();
        PublishPending();
    }
}

void FordSync2IlpChannel::HandleInbound(const uint8_t* data, std::size_t n) {
    ++received_;
    if (n < 4) { ++malformed_; return; }
    const uint16_t tid = U16(data, 2);
    if (data[0] == 2) { HandleSet(data, n, tid); return; }
    if (data[0] != 4 && data[0] != 5 && data[0] != 6) {
        LOG(Caution, "[VMCU] unmodelled ILP transaction type=%u tid=%u len=%zu\n", data[0], tid, n);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    auto& signals = emu_.Get<FordSync2IlpSignals>();
    Refresh();
    /* EA5T-14D544-BA.sec, ipc_ilprot.dll sub_C08D9A10, sub_C08D9468, sub_C08DCFEC. */
    if (data[1] != 0 || (data[0] == 5 ? n != 0x1A :
        n < 6 || n != 6u + 4u * U16(data, 4))) {
        ++malformed_; Complete(data[0], tid, false); return;
    }
    switch (data[0]) {
    case 5: {
        const uint32_t id = U32(data, 4);
        const auto sub = signals.NoteFilterRegistration(id, tid);
        /* EA5T-14D544-BA.sec, ipc_ilprot.dll sub_C08D9A10 accepts only status 0/0x40. */
        const bool retained = sub != FordSync2IlpSignals::kNoSubscriber;
        if (!retained) ++unavailable_;
        Complete(5, tid, retained);
        std::vector<uint8_t> body;
        if (retained && signals.AppendSignalIndication(id, sub, body))
            Send(body.data(), body.size());
        break;
    }
    case 6: Complete(6, tid, true); break;
    case 4: {
        std::vector<uint8_t> body;
        signals.AppendGetAssocReply(data, n, tid, body);
        Send(body.data(), body.size());
        break;
    }
    default:
        LOG(Caution, "[VMCU] unmodelled ILP transaction type=%u tid=%u len=%zu\n", data[0], tid, n);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
}

void FordSync2IlpChannel::PublishPending(bool cyclic) {
    auto& signals = emu_.Get<FordSync2IlpSignals>();
    uint32_t changed[FordSync2IlpSignals::kSignalCount];
    std::size_t count = signals.TakeChangedSignals(changed, std::size(changed));
    if (cyclic && count == 0) {
        const auto next = signals.NextCyclicSignal();
        if (next != FordSync2IlpSignals::kTakenSignal) { changed[0] = next; count = 1; }
    }
    for (std::size_t i = 0; i < count; ++i) {
        const auto id = changed[i];
        if (signals.IsComposite(id)) continue;
        for (std::size_t sub = 0; sub < signals.SubscriberCount(id); ++sub) {
            std::vector<uint8_t> body;
            if (signals.AppendSignalIndication(id, sub, body)) Send(body.data(), body.size());
        }
        signals.MarkPublished(id);
        changed[i] = FordSync2IlpSignals::kTakenSignal;
    }
    for (;;) {
        std::vector<uint8_t> body;
        std::vector<uint32_t> before(changed, changed + count);
        if (signals.AppendBatchedIndication(changed, count, body) == 0) break;
        Send(body.data(), body.size());
        for (std::size_t i = 0; i < count; ++i)
            if (before[i] != FordSync2IlpSignals::kTakenSignal && changed[i] == FordSync2IlpSignals::kTakenSignal)
                signals.MarkPublished(before[i]);
    }
}

void FordSync2IlpChannel::OnWatchdogPet() {
    Refresh();
    ++watchdog_pets_;
    for (const auto& device : devices_)
        if (device.watchdog) device.watchdog(watchdog_pets_);
    PublishPending(true);
}

void FordSync2IlpChannel::ApplyHostChange(const std::function<void()>& change) {
    auto& runner = emu_.Get<JitRunner>();
    const bool paused = emu_.Get<EmulationPause>().IsPaused();
    runner.Pause();
    {
        auto freeze = emu_.Get<EmulationFreeze>().WorkerSection();
        change();
        Refresh();
        PublishPending();
    }
    if (!paused) runner.Resume();
}

FordSync2IlpChannel::Counters FordSync2IlpChannel::ReadCounters() const {
    return {accepted_.load(), unsupported_.load(), invalid_.load(), unavailable_.load(), malformed_.load(),
        received_.load(), sent_.load()};
}

void FordSync2IlpChannel::RegisterDevice(Device device) {
    if (device.key.empty() || device.key.size() > 64 || devices_.size() >= 64 ||
        !device.refresh || !device.save || !device.restore || !device.reset ||
        std::any_of(devices_.begin(), devices_.end(), [&](const Device& d) { return d.key == device.key; })) {
        LOG(Caution, "[VMCU] invalid ILP device registration\n");
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    devices_.push_back(std::move(device));
    std::sort(devices_.begin(), devices_.end(), [](const Device& a, const Device& b) { return a.key < b.key; });
}

void FordSync2IlpChannel::Refresh(bool force) {
    for (const auto& device : devices_) device.refresh(force);
}

void FordSync2IlpChannel::SaveState(StateWriter& w) const {
    w.Write("tx_seq", tx_seq_); w.Write("watchdog_pets", watchdog_pets_);
    emu_.Get<FordSync2IlpSignals>().SaveState(w);
    w.Write<uint32_t>("devices_count", static_cast<uint32_t>(devices_.size()));
    for (const auto& device : devices_) {
        w.Write<uint32_t>("key_count", static_cast<uint32_t>(device.key.size()));
        w.WriteBytes("key", device.key.data(), device.key.size());
        device.save(w);
    }
}

void FordSync2IlpChannel::RestoreState(StateReader& r) {
    r.Read("tx_seq", tx_seq_); r.Read("watchdog_pets", watchdog_pets_);
    emu_.Get<FordSync2IlpSignals>().RestoreState(r);
    for (const auto& device : devices_) device.reset();
    uint32_t count = 0;
    r.Read("devices_count", count);
    if (count != devices_.size())
        r.Reject("[VMCU] the image has %u ILP devices, this build has %zu", count,
                 devices_.size());
    std::vector<std::string> seen;
    for (uint32_t i = 0; i < count; ++i) {
        uint32_t size = 0;
        r.Read("key_count", size);
        if (size == 0 || size > 64) r.Reject("[VMCU] ILP device key of %u bytes", size);
        std::string key(size, '\0');
        r.ReadBytes("key", key.data(), size);
        if (std::find(seen.begin(), seen.end(), key) != seen.end())
            r.Reject("[VMCU] ILP device '%s' appears twice", key.c_str());
        seen.push_back(key);
        const auto device = std::find_if(devices_.begin(), devices_.end(),
            [&](const auto& d) { return d.key == key; });
        if (device == devices_.end())
            r.Reject("[VMCU] ILP device '%s' is not in this build", key.c_str());
        device->restore(r);
    }
    Refresh(true);
}
