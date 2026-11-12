#include "task_manager_controller.h"

#include "task_manager_model.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/peripherals/cerf_virt/cerf_virt_task_manager_regs.h>

#include <QStringList>
#include <QVariantMap>

using Model = cerffrontend::TaskManagerModel;

TaskManagerController::TaskManagerController(cerfcore::CerfEmulator& emu)
    : gate_(emu), title_(QStringLiteral("Guest Task Manager")) {
    gate_.Run([](cerfcore::CerfEmulator& gate_emu) { gate_emu.Get<Model>().Open(); });
    FillColumns();
    SyncStatus();
    timer_.callOnTimeout(this, [this] { Tick(); });
    timer_.start(static_cast<int>(Model::kRefreshMs));
}

int TaskManagerController::RunLimit() const { return static_cast<int>(cerfcore::CerfVirt::kTmRunMaxWchars); }

int TaskManagerController::ClientWidth() const { return Model::kClientW; }

int TaskManagerController::ClientHeight() const { return Model::kClientH; }

int TaskManagerController::MinimumClientWidth() const { return Model::kMinTrackW; }

int TaskManagerController::MinimumClientHeight() const { return Model::kMinTrackH; }

void TaskManagerController::FillColumns() {
    gate_.Run([this](cerfcore::CerfEmulator& emu) {
        columns_.clear();
        for (const Model::Column& column : emu.Get<Model>().Columns())
            columns_.append(QVariantMap{{QStringLiteral("title"), QString::fromUtf8(column.title)},
                                        {QStringLiteral("width"), column.width}});
    });
    rows_.clear();
    emit columnsChanged();
    emit rowsChanged();
}

void TaskManagerController::FillRows() {
    gate_.Run([this](cerfcore::CerfEmulator& emu) {
        auto& model = emu.Get<Model>();
        rows_.clear();
        for (const Model::Row& row : model.Rows()) {
            QStringList cells;
            for (const std::string& cell : row.cells) cells.append(QString::fromStdString(cell));
            rows_.append(QVariantMap{{QStringLiteral("cells"), cells}, {QStringLiteral("key"), row.key}});
        }
        title_ = QString::fromStdString(model.Title());
    });
    emit rowsChanged();
}

void TaskManagerController::SyncStatus() {
    bool changed = false;
    gate_.Run([this, &changed](cerfcore::CerfEmulator& emu) {
        auto& model = emu.Get<Model>();
        if (model.StatusSerial() == status_serial_) return;
        status_serial_ = model.StatusSerial();
        status_        = QString::fromStdString(model.StatusText());
        status_ok_     = model.Status() == Model::StatusKind::kOk;
        status_failed_ = model.Status() == Model::StatusKind::kFail;
        changed        = true;
    });
    if (changed) emit statusChanged();
}

void TaskManagerController::Tick() {
    bool refreshed = false;
    gate_.Run([&refreshed](cerfcore::CerfEmulator& emu) { refreshed = emu.Get<Model>().Tick(); });
    if (refreshed) FillRows();
    SyncStatus();
}

void TaskManagerController::SetProcesses(bool processes) {
    gate_.Run([processes](cerfcore::CerfEmulator& emu) {
        emu.Get<Model>().SetMode(processes ? Model::Mode::kProcesses : Model::Mode::kWindows);
    });
    FillColumns();
    SyncStatus();
}

void TaskManagerController::SwitchTo(bool selected, const QVariant& key) {
    gate_.Run([selected, &key](cerfcore::CerfEmulator& emu) { emu.Get<Model>().SwitchTo(selected, key.toUInt()); });
    SyncStatus();
}

void TaskManagerController::Kill(bool selected, const QVariant& key) {
    gate_.Run([selected, &key](cerfcore::CerfEmulator& emu) { emu.Get<Model>().Kill(selected, key.toUInt()); });
    SyncStatus();
}

void TaskManagerController::Run(const QString& command) {
    gate_.Run([&command](cerfcore::CerfEmulator& emu) { emu.Get<Model>().Run(command.toStdU16String()); });
    SyncStatus();
}
