#include "task_manager_model.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/utf16.h>
#include <cerfcore/peripherals/cerf_virt/cerf_virt_task_manager_regs.h>

#include <cstdio>
#include <string>
#include <utility>

namespace cerffrontend {

REGISTER_SERVICE(TaskManagerModel);

namespace {

constexpr TaskManagerModel::Column kPidColumn = {"PID", 90};

const std::vector<TaskManagerModel::Column> kWindowColumns = {
    {"Title", 230}, {"HWND", 90}, kPidColumn, {"Visible", 60},
};

const std::vector<TaskManagerModel::Column> kProcessColumns = {
    {"Process", 150}, kPidColumn, {"Parent", 90}, {"Threads", 60}, {"Priority", 60},
    {"Mem base", 90},
};

const char* ActionName(uint32_t code) {
    switch (code) {
        case cerfcore::CerfVirt::kTmCmdKill:        return "kill";
        case cerfcore::CerfVirt::kTmCmdSwitchTo:
        case cerfcore::CerfVirt::kTmCmdSwitchToWin: return "switch to";
        case cerfcore::CerfVirt::kTmCmdRun:         return "run";
        case cerfcore::CerfVirt::kTmCmdList:
        case cerfcore::CerfVirt::kTmCmdListWindows: return "list";
        default:                                    return "command";
    }
}

std::string Format(const char* fmt, uint32_t a, uint32_t b = 0) {
    char buf[96];
    std::snprintf(buf, sizeof(buf), fmt, a, b);
    return buf;
}

std::string Hex(uint32_t v) { return Format("0x%08X", v); }

bool SameProcs(const std::vector<cerfcore::CerfVirtTaskManager::ProcEntry>& a,
               const std::vector<cerfcore::CerfVirtTaskManager::ProcEntry>& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        const auto& x = a[i];
        const auto& y = b[i];
        if (x.pid != y.pid || x.parent_pid != y.parent_pid || x.thread_count != y.thread_count ||
            x.base_priority != y.base_priority || x.mem_base != y.mem_base || x.name != y.name)
            return false;
    }
    return true;
}

bool SameWins(const std::vector<cerfcore::CerfVirtTaskManager::WinEntry>& a,
              const std::vector<cerfcore::CerfVirtTaskManager::WinEntry>& b) {
    if (a.size() != b.size()) return false;
    for (size_t i = 0; i < a.size(); ++i) {
        const auto& x = a[i];
        const auto& y = b[i];
        if (x.hwnd != y.hwnd || x.pid != y.pid || x.thread_id != y.thread_id ||
            x.visible != y.visible || x.title != y.title)
            return false;
    }
    return true;
}

}

const std::vector<TaskManagerModel::Column>& TaskManagerModel::Columns() const {
    return mode_ == Mode::kWindows ? kWindowColumns : kProcessColumns;
}

void TaskManagerModel::SetStatus(std::string text, StatusKind kind) {
    status_      = std::move(text);
    status_kind_ = kind;
    ++status_serial_;
}

void TaskManagerModel::RequestActiveList() {
    auto& svc = emu_.Get<cerfcore::CerfVirtTaskManager>();
    if (mode_ == Mode::kWindows) svc.RequestWindowList();
    else                         svc.RequestProcessList();
}

void TaskManagerModel::Open() {
    mode_       = Mode::kWindows;
    shown_gen_  = 0;
    guest_total_ = 0;
    procs_.clear();
    wins_.clear();
    rows_.clear();
    awaiting_first_ = true;
    RequestActiveList();
    SetStatus("Waiting for guest…", StatusKind::kInfo);
}

void TaskManagerModel::SetMode(Mode m) {
    if (m != mode_) {
        mode_      = m;
        shown_gen_ = 0;
        procs_.clear();
        wins_.clear();
        rows_.clear();
    }
    awaiting_first_ = true;
    RequestActiveList();
    SetStatus("Waiting for guest…", StatusKind::kInfo);
}

void TaskManagerModel::ConsumeActionResult() {
    auto r = emu_.Get<cerfcore::CerfVirtTaskManager>().TakeActionResult();
    if (!r) return;
    if (r->code == cerfcore::CerfVirt::kTmCmdRun) {
        if (r->ticket != run_ticket_) return;
        if (r->ok) SetStatus("success", StatusKind::kOk);
        else       SetStatus(Format("failed (error %u)", r->guest_err), StatusKind::kFail);
        return;
    }
    if (r->code == cerfcore::CerfVirt::kTmCmdList ||
        r->code == cerfcore::CerfVirt::kTmCmdListWindows) {
        if (!r->ok) SetStatus(Format("list failed (error %u)", r->guest_err), StatusKind::kFail);
        return;
    }
    if (r->ok) {
        SetStatus(std::string(ActionName(r->code)) + ": done", StatusKind::kOk);
        return;
    }
    SetStatus(std::string(ActionName(r->code)) + Format(" failed (error %u)", r->guest_err),
              StatusKind::kFail);
}

bool TaskManagerModel::Tick() {
    RequestActiveList();
    ConsumeActionResult();
    const cerfcore::CerfVirtTaskManager::Snapshot snap =
        emu_.Get<cerfcore::CerfVirtTaskManager>().GetSnapshot();
    if (!UpdateRows(snap)) return false;
    if (awaiting_first_) {
        SetStatus("", StatusKind::kInfo);
        awaiting_first_ = false;
    }
    return true;
}

bool TaskManagerModel::UpdateRows(const cerfcore::CerfVirtTaskManager::Snapshot& snap) {
    if (snap.gen == shown_gen_) return false;
    const bool first = shown_gen_ == 0;
    shown_gen_       = snap.gen;
    if (mode_ == Mode::kWindows) {
        if (!first && SameWins(snap.wins, wins_)) return false;
        wins_ = snap.wins;
    } else {
        if (!first && SameProcs(snap.procs, procs_)) return false;
        procs_       = snap.procs;
        guest_total_ = snap.guest_total;
    }
    FillRows();
    return true;
}

void TaskManagerModel::FillRows() {
    rows_.clear();
    if (mode_ == Mode::kWindows) {
        std::vector<cerfcore::CerfVirtTaskManager::WinEntry> picked;
        std::vector<int>                                     score;
        for (const auto& wd : wins_) {
            const int s = (wd.visible ? 2 : 0) + (wd.title.empty() ? 0 : 1);
            size_t    k = 0;
            for (; k < picked.size(); ++k)
                if (picked[k].pid == wd.pid) break;
            if (k == picked.size()) {
                picked.push_back(wd);
                score.push_back(s);
            } else if (s > score[k]) {
                picked[k] = wd;
                score[k]  = s;
            }
        }
        for (const auto& wd : picked) {
            Row row;
            row.key = wd.hwnd;
            row.cells = {wd.title.empty() ? std::string("(no title)") : cerfcore::Utf16ToUtf8(wd.title),
                         Hex(wd.hwnd), Hex(wd.pid), wd.visible ? "Yes" : "No"};
            rows_.push_back(std::move(row));
        }
        return;
    }
    for (const auto& p : procs_) {
        Row row;
        row.key   = p.pid;
        row.cells = {cerfcore::Utf16ToUtf8(p.name), Hex(p.pid), Hex(p.parent_pid),
                     std::to_string(p.thread_count), std::to_string(p.base_priority),
                     Hex(p.mem_base)};
        rows_.push_back(std::move(row));
    }
}

std::string TaskManagerModel::Title() const {
    if (mode_ == Mode::kWindows)
        return Format("Guest Task Manager - %u programs", static_cast<uint32_t>(rows_.size()));
    if (guest_total_ > procs_.size())
        return Format("Guest Task Manager - %u of %u processes", static_cast<uint32_t>(procs_.size()), guest_total_);
    return Format("Guest Task Manager - %u processes", static_cast<uint32_t>(procs_.size()));
}

bool TaskManagerModel::HasSelection(bool selected) {
    if (selected) return true;
    SetStatus(mode_ == Mode::kWindows ? "no window selected" : "no process selected", StatusKind::kFail);
    return false;
}

void TaskManagerModel::SwitchTo(bool selected, uint32_t key) {
    if (!HasSelection(selected)) return;
    auto& svc = emu_.Get<cerfcore::CerfVirtTaskManager>();
    if (mode_ == Mode::kWindows) svc.RequestSwitchToWindow(key);
    else                         svc.RequestSwitchTo(key);
    SetStatus("switching…", StatusKind::kInfo);
}

void TaskManagerModel::Kill(bool selected, uint32_t key) {
    if (!HasSelection(selected)) return;
    uint32_t pid = key;
    if (mode_ == Mode::kWindows) {
        pid = 0;
        for (const auto& wd : wins_)
            if (wd.hwnd == key) {
                pid = wd.pid;
                break;
            }
    }
    emu_.Get<cerfcore::CerfVirtTaskManager>().RequestKill(pid);
    SetStatus("killing…", StatusKind::kInfo);
}

void TaskManagerModel::Run(const std::u16string& command) {
    if (command.empty()) {
        SetStatus("enter a command", StatusKind::kFail);
        return;
    }
    run_ticket_ = emu_.Get<cerfcore::CerfVirtTaskManager>().RequestRun(command);
    if (run_ticket_ == 0) {
        SetStatus("failed", StatusKind::kFail);
        return;
    }
    SetStatus("running…", StatusKind::kInfo);
}

}
