#pragma once

#include <cerfcore/core/service.h>
#include <cerfcore/peripherals/cerf_virt/cerf_virt_task_manager.h>

#include <cstdint>
#include <string>
#include <vector>

namespace cerffrontend {

class TaskManagerModel : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    enum class Mode { kWindows, kProcesses };
    enum class StatusKind { kInfo, kOk, kFail };

    struct Column {
        const char* title;
        int         width;
    };

    struct Row {
        std::vector<std::string> cells;
        uint32_t                 key = 0;
    };

    static constexpr unsigned kRefreshMs = 500;
    static constexpr int      kClientW   = 560;
    static constexpr int      kClientH   = 420;
    static constexpr int      kMinTrackW = 480;
    static constexpr int      kMinTrackH = 320;

    void Open();
    void SetMode(Mode m);
    bool Tick();

    const std::vector<Column>& Columns() const;
    const std::vector<Row>&    Rows() const { return rows_; }
    std::string                Title() const;
    const std::string&         StatusText() const { return status_; }
    StatusKind                 Status() const { return status_kind_; }
    uint64_t                   StatusSerial() const { return status_serial_; }

    void SwitchTo(bool selected, uint32_t key);
    void Kill(bool selected, uint32_t key);
    void Run(const std::u16string& command);

private:
    void RequestActiveList();
    void SetStatus(std::string text, StatusKind kind);
    bool HasSelection(bool selected);
    void ConsumeActionResult();
    bool UpdateRows(const cerfcore::CerfVirtTaskManager::Snapshot& snap);
    void FillRows();

    Mode        mode_           = Mode::kWindows;
    bool        awaiting_first_ = true;
    uint32_t    run_ticket_     = 0;
    uint64_t    shown_gen_      = 0;
    uint32_t    guest_total_    = 0;
    std::string status_;
    StatusKind  status_kind_    = StatusKind::kInfo;
    uint64_t    status_serial_  = 0;

    std::vector<cerfcore::CerfVirtTaskManager::ProcEntry> procs_;
    std::vector<cerfcore::CerfVirtTaskManager::WinEntry>  wins_;
    std::vector<Row>                                      rows_;
};

}
