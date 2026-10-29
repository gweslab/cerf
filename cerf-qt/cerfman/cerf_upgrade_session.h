#pragma once

#include "cerf_release.h"
#include "upgrade_session.h"

#include <QByteArray>
#include <QString>

#include <atomic>
#include <thread>

namespace cerfcore {
class InstanceThreads;
}

class CerfUpgradeSession : public UpgradeSession {
    Q_OBJECT

public:
    CerfUpgradeSession(CerfRelease release, QByteArray user_agent, QObject* parent = nullptr);
    ~CerfUpgradeSession() override;

    void Start(cerfcore::InstanceThreads& threads);
    void Close() override { closed_ = true; }
    bool Closed() const { return closed_; }

private:
    void Work();
    bool Stage(QString& staged_frontend, QString& error);

    CerfRelease       release_;
    QByteArray        user_agent_;
    std::thread       worker_;
    std::atomic<bool> cancelled_{false};
    bool              closed_ = false;
};
