#pragma once

#include <QString>

#include <functional>

class InstallRetryGate {
public:
    using Log      = std::function<void(const QString& line)>;
    using AskRetry = std::function<bool(const QString& title, const QString& message)>;
    using Action   = std::function<bool(QString& failure)>;

    InstallRetryGate(Log log, AskRetry ask_retry) : log_(std::move(log)), ask_retry_(std::move(ask_retry)) {}

    void Report(const QString& line) const { log_(line); }

    bool Attempt(const QString& title, const QString& what, const Action& action, QString& failure) const;

private:
    Log      log_;
    AskRetry ask_retry_;
};
