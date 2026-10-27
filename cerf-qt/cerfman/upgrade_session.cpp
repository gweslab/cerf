#include "upgrade_session.h"

#include "wait_for_pid.h"

#include <cerfcore/core/log.h>

#include <QCoreApplication>
#include <QDir>
#include <QMetaObject>
#include <QProcess>

QVariantMap UpgradeSession::WindowProperties() {
    return {{QStringLiteral("model"), QVariant::fromValue<QObject*>(this)}};
}

bool UpgradeSession::StartStage(const QString& executable, const QString& folder, const QStringList& stage_args,
                                QString& error) const {
    QStringList args{
        QString::fromStdString(WaitForPidArgument(static_cast<uint32_t>(QCoreApplication::applicationPid())))};
    args.append(stage_args);
    if (QProcess::startDetached(executable, args, folder)) return true;
    error = QStringLiteral("%1 could not be started.").arg(QDir::toNativeSeparators(executable));
    return false;
}

void UpgradeSession::SetHeading(const QString& heading) {
    heading_ = heading;
    emit headingChanged();
}

void UpgradeSession::AnswerRetry(bool retry) {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        if (!waiting_) return;
        retry_   = retry;
        waiting_ = false;
    }
    answered_.notify_all();
}

void UpgradeSession::StopWaiting() {
    {
        std::lock_guard<std::mutex> lock(mutex_);
        stopping_ = true;
        waiting_  = false;
        retry_    = false;
    }
    answered_.notify_all();
}

void UpgradeSession::PostLog(const QString& line) {
    LOG(Manager, "%s\n", qUtf8Printable(line));
    QMetaObject::invokeMethod(this, [this, line] { emit logLine(line); }, Qt::QueuedConnection);
}

void UpgradeSession::PostProgress(qint64 done, qint64 total) {
    QMetaObject::invokeMethod(this, [this, done, total] { emit progress(double(done), double(total)); },
                              Qt::QueuedConnection);
}

void UpgradeSession::LogFailure(const QString& title, const QString& message) {
    LOG(Manager, "%s: %s\n", qUtf8Printable(title), qUtf8Printable(message));
}

void UpgradeSession::PostFailure(const QString& title, const QString& error, const QString& consequence) {
    const QString message = QStringLiteral("%1\n\n%2").arg(error, consequence);
    LogFailure(title, message);
    QMetaObject::invokeMethod(this, [this, title, message] { emit failed(title, message); }, Qt::QueuedConnection);
}

bool UpgradeSession::AskRetry(const QString& title, const QString& message) {
    std::unique_lock<std::mutex> lock(mutex_);
    if (stopping_) return false;
    waiting_ = true;
    retry_   = false;
    QMetaObject::invokeMethod(this, [this, title, message] { emit retryRequested(title, message); },
                              Qt::QueuedConnection);
    answered_.wait(lock, [this] { return !waiting_; });
    return retry_;
}
