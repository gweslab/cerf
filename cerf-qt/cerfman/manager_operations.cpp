#include "manager_operations.h"

#include <cerfcore/core/cerf_emulator.h>
#include <cerfcore/core/instance_threads.h>
#include <cerfcore/core/log.h>

#include <QMetaObject>
#include <QStringList>

REGISTER_SERVICE(ManagerOperations);

OperationProgress ManagerOperations::Progress() {
    return OperationProgress(
        [this](const QString& label, qint64 done, std::optional<qint64> total) {
            QMetaObject::invokeMethod(
                this, [this, label, done, total] { ShowProgress(label, done, total); }, Qt::QueuedConnection);
        },
        cancelled_);
}

void ManagerOperations::OnShutdown() {
    cancelled_.store(true, std::memory_order_release);
    if (worker_.joinable()) worker_.join();
}

void ManagerOperations::SetBusy(bool busy, const QString& label) {
    busy_           = busy;
    label_          = label;
    done_           = 0;
    total_          = 0;
    progress_shown_ = false;
    emit busyChanged();
    emit progressChanged();
}

void ManagerOperations::ShowProgress(const QString& label, qint64 done, std::optional<qint64> total) {
    label_          = label;
    done_           = done;
    total_          = total.value_or(0);
    progress_shown_ = true;
    emit progressChanged();
}

void ManagerOperations::Start(std::function<void()> work) {
    if (worker_.joinable()) worker_.join();
    worker_ = emu_.Get<cerfcore::InstanceThreads>().Start(std::move(work));
}

bool ManagerOperations::RefuseWhileBusy() {
    if (!busy_) return false;
    emit message(QStringLiteral("Operation in progress"),
                 QStringLiteral("Wait until the current operation ends, then try again."));
    return true;
}

void ManagerOperations::Run(const QString& busy_label, Job job, const QString& success_status,
                            std::function<void(OperationResult)> after) {
    if (RefuseWhileBusy()) return;
    SetBusy(true, busy_label);
    Start([this, job = std::move(job), success_status, after = std::move(after)] {
        const OperationProgress progress = Progress();
        QString                 error;
        const OperationResult   result = job(progress, error);
        QMetaObject::invokeMethod(
            this,
            [this, result, error, success_status, after] {
                SetBusy(false, QString());
                if (result == OperationResult::kFailed) {
                    LOG(Manager, "operation failed: %s\n", qUtf8Printable(error));
                    emit message(QStringLiteral("Operation failed"), error);
                    emit status(QStringLiteral("Error."));
                } else if (result == OperationResult::kCancelled) {
                    emit status(QStringLiteral("Cancelled."));
                } else {
                    emit status(success_status);
                }
                if (after) after(result);
                emit devicesChanged();
            },
            Qt::QueuedConnection);
    });
}

void ManagerOperations::RunDeletion(const QString& subject, Job job) {
    Run(QStringLiteral("Deleting %1…").arg(subject), std::move(job), QStringLiteral("Deleted %1").arg(subject));
}

void ManagerOperations::RunSequence(std::vector<Step> steps) {
    if (RefuseWhileBusy()) return;
    SetBusy(true, QString());
    RunStep(std::make_shared<std::vector<Step>>(std::move(steps)), 0,
            std::make_shared<std::vector<QPair<QString, QString>>>());
}

void ManagerOperations::RunStep(std::shared_ptr<std::vector<Step>> steps, size_t index,
                                std::shared_ptr<std::vector<QPair<QString, QString>>> errors) {
    if (index >= steps->size()) {
        SetBusy(false, QString());
        if (!errors->empty()) {
            QStringList lines;
            for (const auto& [label, error] : *errors) lines.append(QStringLiteral("%1: %2").arg(label, error));
            emit message(QStringLiteral("Sequence completed with errors"), lines.join(QLatin1Char('\n')));
        }
        emit devicesChanged();
        return;
    }
    const Step& step = (*steps)[index];
    label_ = QStringLiteral("[%1/%2] %3…").arg(index + 1).arg(steps->size()).arg(step.label);
    emit progressChanged();
    Start([this, steps, index, errors] {
        const OperationProgress progress = Progress();
        QString                 error;
        const OperationResult   result = (*steps)[index].job(progress, error);
        QMetaObject::invokeMethod(
            this,
            [this, steps, index, errors, result, error] {
                if (result == OperationResult::kFailed)
                    errors->push_back(qMakePair((*steps)[index].label, error));
                else
                    emit devicesChanged();
                RunStep(steps, index + 1, errors);
            },
            Qt::QueuedConnection);
    });
}
