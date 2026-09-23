#include "cerf_virt_task_manager.h"
#include "cerf_virt_task_manager_regs.h"
#include "cerf_virt_addr_map.h"
#include "cerf_virt_utf16_window.h"

#include "../peripheral_dispatcher.h"
#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/device_config.h"
#include "../../core/log.h"

#include <cstring>

REGISTER_SERVICE(CerfVirtTaskManager);

using namespace CerfVirt;

namespace {
constexpr uint32_t kRunTextBytes = kTmRunMaxWchars * sizeof(uint16_t);
}

bool CerfVirtTaskManager::ShouldRegister() {
    return emu_.Get<DeviceConfig>().guest_additions;
}

void CerfVirtTaskManager::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
}

uint32_t CerfVirtTaskManager::MmioBase() const {
    return emu_.Get<BoardContext>().GuestAdditionsWindowBase() + kTaskManagerOffset;
}
uint32_t CerfVirtTaskManager::MmioSize() const { return kTaskManagerSize; }

uint32_t CerfVirtTaskManager::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    std::lock_guard<std::mutex> lk(mtx_);
    switch (off) {
        case kTmCmdGen:    return cmd_gen_;
        case kTmCmdCode:   return cmd_code_;
        case kTmCmdPid:    return cmd_pid_;
        case kTmCmdRunLen: return (uint32_t)cmd_run_text_.size();
        default: break;
    }
    if (off >= kTmCmdRunText && off + 4u <= kTmCmdRunText + kRunTextBytes) {
        return Utf16WindowWord(cmd_run_text_, (off - kTmCmdRunText) / 2u);
    }
    HaltUnsupportedAccess("ReadWord", addr, 0);
}

void CerfVirtTaskManager::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    std::lock_guard<std::mutex> lk(mtx_);
    switch (off) {
        case kTmRespCmdGen: resp_cmd_gen_ = value; return;
        case kTmRespStatus: resp_status_  = value; return;
        case kTmRespErr:    resp_err_     = value; return;
        case kTmRespCount:  resp_count_   = value; return;
        case kTmRespTotal:  resp_total_   = value; return;
        case kTmRecIndex:   rec_index_    = value; return;
        case kTmRecKick:    ConsumeRecordLocked();   return;
        case kTmRespKick:   ConsumeResponseLocked(); return;
        default: break;
    }
    if (off >= kTmRecData &&
        off + 4u <= kTmRecData + (uint32_t)sizeof(rec_words_)) {
        rec_words_[(off - kTmRecData) / 4] = value;
        return;
    }
    HaltUnsupportedAccess("WriteWord", addr, value);
}

void CerfVirtTaskManager::ConsumeRecordLocked() {
    if (in_flight_ && in_flight_code_ == kTmCmdList) {
        if (pending_rows_.size() >= kTmMaxProcRecords) return;
        if (rec_index_ != pending_rows_.size())
            LOG(Caution, "[TaskMgr] record index %u, expected %zu\n",
                rec_index_, pending_rows_.size());
        TaskManagerProcRecord r;
        std::memcpy(&r, rec_words_, sizeof(r));
        ProcEntry e;
        e.pid           = r.pid;
        e.parent_pid    = r.parent_pid;
        e.thread_count  = r.thread_count;
        e.base_priority = r.base_priority;
        e.mem_base      = r.mem_base;
        for (uint32_t i = 0; i < kTmProcNameWchars && r.name[i]; ++i)
            e.name.push_back((wchar_t)r.name[i]);
        pending_rows_.push_back(std::move(e));
        return;
    }
    if (in_flight_ && in_flight_code_ == kTmCmdListWindows) {
        if (pending_wins_.size() >= kTmMaxProcRecords) return;
        if (rec_index_ != pending_wins_.size())
            LOG(Caution, "[TaskMgr] window record index %u, expected %zu\n",
                rec_index_, pending_wins_.size());
        TaskManagerWindowRecord r;
        std::memcpy(&r, rec_words_, sizeof(r));
        WinEntry e;
        e.hwnd      = r.hwnd;
        e.pid       = r.pid;
        e.thread_id = r.thread_id;
        e.visible   = (r.flags & kTmWinFlagVisible) != 0;
        for (uint32_t i = 0; i < kTmWindowTitleWchars && r.title[i]; ++i)
            e.title.push_back((wchar_t)r.title[i]);
        pending_wins_.push_back(std::move(e));
        return;
    }
    LOG(Caution, "[TaskMgr] record kick outside a LIST (in_flight=%d "
        "code=%u)\n", (int)in_flight_, in_flight_code_);
}

void CerfVirtTaskManager::RequestProcessList() {
    std::lock_guard<std::mutex> lk(mtx_);
    if (list_live_) return;
    list_live_ = true;
    EnqueueLocked(kTmCmdList, 0, {});
}

void CerfVirtTaskManager::RequestWindowList() {
    std::lock_guard<std::mutex> lk(mtx_);
    if (list_live_) return;
    list_live_ = true;
    EnqueueLocked(kTmCmdListWindows, 0, {});
}

uint32_t CerfVirtTaskManager::RequestKill(uint32_t pid) {
    std::lock_guard<std::mutex> lk(mtx_);
    return EnqueueLocked(kTmCmdKill, pid, {});
}

uint32_t CerfVirtTaskManager::RequestSwitchTo(uint32_t pid) {
    std::lock_guard<std::mutex> lk(mtx_);
    return EnqueueLocked(kTmCmdSwitchTo, pid, {});
}

uint32_t CerfVirtTaskManager::RequestSwitchToWindow(uint32_t hwnd) {
    std::lock_guard<std::mutex> lk(mtx_);
    return EnqueueLocked(kTmCmdSwitchToWin, hwnd, {});
}

uint32_t CerfVirtTaskManager::RequestRun(const std::wstring& cmdline) {
    if (cmdline.empty() || cmdline.size() > kTmRunMaxWchars) {
        LOG(Caution, "[TaskMgr] run command rejected (len=%zu, max=%u)\n",
            cmdline.size(), kTmRunMaxWchars);
        return 0;
    }
    std::lock_guard<std::mutex> lk(mtx_);
    return EnqueueLocked(kTmCmdRun, 0, cmdline);
}

CerfVirtTaskManager::Snapshot CerfVirtTaskManager::GetSnapshot() {
    std::lock_guard<std::mutex> lk(mtx_);
    return snap_;
}

std::optional<CerfVirtTaskManager::ActionResult>
CerfVirtTaskManager::TakeActionResult() {
    std::lock_guard<std::mutex> lk(mtx_);
    auto r = last_action_;
    last_action_.reset();
    return r;
}

uint32_t CerfVirtTaskManager::EnqueueLocked(uint32_t code, uint32_t pid,
                                            std::wstring run_text) {
    const uint32_t ticket = ++next_ticket_;
    queue_.push_back({ ticket, code, pid, std::move(run_text) });
    PublishNextLocked();
    return ticket;
}

void CerfVirtTaskManager::PublishNextLocked() {
    if (in_flight_ || queue_.empty()) return;
    PendingCmd c = std::move(queue_.front());
    queue_.pop_front();
    in_flight_      = true;
    in_flight_code_ = c.code;
    if (c.code == kTmCmdList)        pending_rows_.clear();
    if (c.code == kTmCmdListWindows) pending_wins_.clear();
    cmd_code_       = c.code;
    cmd_pid_        = c.pid;
    cmd_run_text_   = std::move(c.run_text);
    cmd_gen_        = c.ticket;
}

void CerfVirtTaskManager::ConsumeResponseLocked() {
    if (!in_flight_ || resp_cmd_gen_ != cmd_gen_) {
        LOG(Caution, "[TaskMgr] unexpected response kick (gen=%u published=%u "
            "in_flight=%d)\n", resp_cmd_gen_, cmd_gen_, (int)in_flight_);
        return;
    }
    const bool ok = resp_status_ == 1u;

    if (in_flight_code_ == kTmCmdList) {
        list_live_ = false;
        if (ok) {
            if (resp_count_ != pending_rows_.size())
                LOG(Caution, "[TaskMgr] guest reported %u records, %zu "
                    "streamed\n", resp_count_, pending_rows_.size());
            snap_.procs = std::move(pending_rows_);
            pending_rows_.clear();
            snap_.guest_total = resp_total_;
            ++snap_.gen;
            if (resp_total_ > (uint32_t)snap_.procs.size())
                LOG(Caution, "[TaskMgr] guest snapshot truncated: %zu of %u "
                    "processes\n", snap_.procs.size(), resp_total_);
        } else {
            LOG(GuestAdditions, "[TaskMgr] LIST failed in guest (err=%u)\n",
                resp_err_);
            last_action_ = { cmd_gen_, in_flight_code_, false, resp_err_ };
        }
    } else if (in_flight_code_ == kTmCmdListWindows) {
        list_live_ = false;
        if (ok) {
            if (resp_count_ != pending_wins_.size())
                LOG(Caution, "[TaskMgr] guest reported %u windows, %zu "
                    "streamed\n", resp_count_, pending_wins_.size());
            snap_.wins = std::move(pending_wins_);
            pending_wins_.clear();
            ++snap_.gen;
            if (resp_total_ > (uint32_t)snap_.wins.size())
                LOG(Caution, "[TaskMgr] guest window snapshot truncated: %zu "
                    "of %u windows\n", snap_.wins.size(), resp_total_);
        } else {
            LOG(GuestAdditions, "[TaskMgr] LIST-WINDOWS failed in guest "
                "(err=%u)\n", resp_err_);
            last_action_ = { cmd_gen_, in_flight_code_, false, resp_err_ };
        }
    } else {
        LOG(GuestAdditions, "[TaskMgr] cmd %u (ticket %u) %s (err=%u)\n",
            in_flight_code_, cmd_gen_, ok ? "succeeded" : "FAILED", resp_err_);
        last_action_ = { cmd_gen_, in_flight_code_, ok, resp_err_ };
    }

    in_flight_ = false;
    PublishNextLocked();
}
