#pragma once

#include "manager_qml_engine.h"

#include <cerfcore/core/service.h>

#include <QObject>
#include <QString>
#include <QtQml/qqmlregistration.h>

#include <atomic>
#include <functional>
#include <optional>
#include <thread>
#include <vector>

class OperationProgress {
public:
    using Sink = std::function<void(const QString& label, qint64 done, std::optional<qint64> total)>;

    OperationProgress(Sink sink, const std::atomic<bool>& cancelled) : sink_(std::move(sink)), cancelled_(cancelled) {}

    void Report(const QString& label, qint64 done, std::optional<qint64> total) const { sink_(label, done, total); }
    bool Cancelled() const { return cancelled_.load(std::memory_order_acquire); }

private:
    Sink                     sink_;
    const std::atomic<bool>& cancelled_;
};

enum class OperationResult { kDone, kFailed, kCancelled };

class ManagerOperations : public QObject, public cerfcore::Service {
    Q_OBJECT
    QML_ELEMENT
    QML_SINGLETON
    Q_PROPERTY(bool busy READ Busy NOTIFY busyChanged)
    Q_PROPERTY(QString label READ Label NOTIFY progressChanged)
    Q_PROPERTY(double done READ Done NOTIFY progressChanged)
    Q_PROPERTY(double total READ Total NOTIFY progressChanged)
    Q_PROPERTY(bool progressShown READ ProgressShown NOTIFY progressChanged)

public:
    using Job = std::function<OperationResult(const OperationProgress& progress, QString& error)>;
    struct Step {
        QString label;
        Job     job;
    };

    explicit ManagerOperations(cerfcore::CerfEmulator& emu) : cerfcore::Service(emu) {}
    static ManagerOperations* create(QQmlEngine* qml, QJSEngine*) {
        return ManagerQmlEngine::Singleton<ManagerOperations>(qml);
    }

    void OnShutdown() override;

    bool    Busy() const { return busy_; }
    QString Label() const { return label_; }
    double  Done() const { return double(done_); }
    double  Total() const { return double(total_); }
    bool    ProgressShown() const { return progress_shown_; }

    Q_INVOKABLE bool RefuseWhileBusy();

    void Run(const QString& busy_label, Job job, const QString& success_status,
             std::function<void(OperationResult)> after = {});
    void RunSequence(std::vector<Step> steps);
    void RunDeletion(const QString& subject, Job job);

signals:
    void busyChanged();
    void progressChanged();
    void status(const QString& text);
    void message(const QString& title, const QString& text);
    void devicesChanged();

private:
    OperationProgress Progress();
    void ShowProgress(const QString& label, qint64 done, std::optional<qint64> total);
    void SetBusy(bool busy, const QString& label);
    void Start(std::function<void()> work);
    void RunStep(std::shared_ptr<std::vector<Step>> steps, size_t index,
                 std::shared_ptr<std::vector<QPair<QString, QString>>> errors);

    bool              busy_ = false;
    QString           label_;
    qint64            done_           = 0;
    qint64            total_          = 0;
    bool              progress_shown_ = false;
    std::thread       worker_;
    std::atomic<bool> cancelled_{false};
};
