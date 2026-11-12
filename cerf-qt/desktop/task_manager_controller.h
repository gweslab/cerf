#pragma once

#include <cerfcore/core/instance_gate.h>

#include <QObject>
#include <QString>
#include <QTimer>
#include <QVariant>
#include <QVariantList>

#include <cstdint>

class TaskManagerController : public QObject {
    Q_OBJECT
    Q_PROPERTY(QVariantList columns READ Columns NOTIFY columnsChanged)
    Q_PROPERTY(QVariantList rows READ Rows NOTIFY rowsChanged)
    Q_PROPERTY(QString title READ Title NOTIFY rowsChanged)
    Q_PROPERTY(QString statusText READ StatusText NOTIFY statusChanged)
    Q_PROPERTY(bool statusOk READ StatusOk NOTIFY statusChanged)
    Q_PROPERTY(bool statusFailed READ StatusFailed NOTIFY statusChanged)
    Q_PROPERTY(int runLimit READ RunLimit CONSTANT)
    Q_PROPERTY(int clientWidth READ ClientWidth CONSTANT)
    Q_PROPERTY(int clientHeight READ ClientHeight CONSTANT)
    Q_PROPERTY(int minimumClientWidth READ MinimumClientWidth CONSTANT)
    Q_PROPERTY(int minimumClientHeight READ MinimumClientHeight CONSTANT)

public:
    explicit TaskManagerController(cerfcore::CerfEmulator& emu);

    QVariantList Columns() const { return columns_; }
    QVariantList Rows() const { return rows_; }
    QString      Title() const { return title_; }
    QString      StatusText() const { return status_; }
    bool         StatusOk() const { return status_ok_; }
    bool         StatusFailed() const { return status_failed_; }
    int          RunLimit() const;
    int          ClientWidth() const;
    int          ClientHeight() const;
    int          MinimumClientWidth() const;
    int          MinimumClientHeight() const;

    Q_INVOKABLE void SetProcesses(bool processes);
    Q_INVOKABLE void SwitchTo(bool selected, const QVariant& key);
    Q_INVOKABLE void Kill(bool selected, const QVariant& key);
    Q_INVOKABLE void Run(const QString& command);

signals:
    void columnsChanged();
    void rowsChanged();
    void statusChanged();

private:
    void Tick();
    void FillColumns();
    void FillRows();
    void SyncStatus();

    cerfcore::InstanceGate gate_;
    QTimer                 timer_;
    QVariantList           columns_;
    QVariantList           rows_;
    QString                title_;
    QString                status_;
    bool                   status_ok_     = false;
    bool                   status_failed_ = false;
    uint64_t               status_serial_ = 0;
};
