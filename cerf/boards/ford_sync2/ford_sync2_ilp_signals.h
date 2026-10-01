#pragma once

#include "../../core/service.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <vector>
#include <initializer_list>

class StateWriter;
class StateReader;

class FordSync2IlpSignals : public Service {
public:
    using Service::Service;

    bool ShouldRegister() override;

    void AppendGetAssocReply(const uint8_t* req, std::size_t n, uint16_t tid,
                             std::vector<uint8_t>& pkt);
    bool AppendSignalIndication(uint32_t sigid, std::size_t sub,
                                std::vector<uint8_t>& pkt);
    void        RepublishComposites();
    std::size_t AppendBatchedIndication(uint32_t* sigids, std::size_t n,
                                        std::vector<uint8_t>& pkt);

    std::size_t GroundedSignalCount() const;
    uint32_t    GroundedSignalIdAt(std::size_t i) const;
    uint8_t     GroundedSignalBitsAt(std::size_t i) const;

    static constexpr uint32_t    kTakenSignal    = 0xFFFFFFFFu;
    static constexpr std::size_t kNoSubscriber   = ~static_cast<std::size_t>(0);

    static std::size_t HeadWriteWidth(uint32_t sigid);

    std::size_t NoteFilterRegistration(uint32_t sigid, uint16_t tid);
    std::size_t SubscriberCount(uint32_t sigid) const;
    std::size_t TakeChangedSignals(uint32_t* out, std::size_t max);
    uint32_t    NextCyclicSignal();
    void MarkPublished(uint32_t sigid);
    bool IsComposite(uint32_t sigid) const;
    void RegisterComposite(std::initializer_list<uint32_t> ids);

    void SaveState(StateWriter& w) const;
    void RestoreState(StateReader& r);

    bool    IsReported(uint32_t sigid) const;
    uint64_t ReportedValue(uint32_t sigid) const;
    void    SetReportedValue(uint32_t sigid, uint64_t value);
    void    ClearReportedValue(uint32_t sigid);

    static constexpr std::size_t kSignalCount = 352u;

private:
    unsigned CompositeGroup(uint32_t sigid) const;
    unsigned groups_[kSignalCount] = {};
    unsigned group_count_ = 0;
    std::size_t IndexOf(uint32_t sigid) const;

    std::atomic<uint64_t> reported_[kSignalCount]   = {};
    std::atomic<bool>     reporting_[kSignalCount]  = {};
    std::atomic<bool>     pending_[kSignalCount]    = {};
    std::vector<uint16_t> sub_tids_[kSignalCount];
    bool                  warned_reply_truncated_ = false;

    std::size_t           cycle_ = 0u;
    std::vector<uint32_t> logged_ungrounded_;
};
