#pragma once

#include <QObject>
#include <QString>
#include <QStringList>
#include <QVariantMap>

#include <condition_variable>
#include <mutex>

class UpgradeSession : public QObject {
    Q_OBJECT
    Q_PROPERTY(QString heading READ Heading NOTIFY headingChanged)

public:
    using QObject::QObject;

    static constexpr char kWindowType[] = "UpgradeWindow";

    QString     Heading() const { return heading_; }
    QVariantMap WindowProperties();

    Q_INVOKABLE void         AnswerRetry(bool retry);
    Q_INVOKABLE virtual void Close() = 0;

signals:
    void headingChanged();
    void logLine(const QString& line);
    void progress(double done, double total);
    void retryRequested(const QString& title, const QString& message);
    void failed(const QString& title, const QString& message);

protected:
    void SetHeading(const QString& heading);
    void PostLog(const QString& line);
    void PostProgress(qint64 done, qint64 total);
    void PostFailure(const QString& title, const QString& error, const QString& consequence);
    static void LogFailure(const QString& title, const QString& message);
    bool AskRetry(const QString& title, const QString& message);
    void StopWaiting();
    bool StartStage(const QString& executable, const QString& folder, const QStringList& stage_args,
                    QString& error) const;

private:
    QString                 heading_;
    std::mutex              mutex_;
    std::condition_variable answered_;
    bool                    waiting_  = false;
    bool                    retry_    = false;
    bool                    stopping_ = false;
};
