#include "install_retry_gate.h"

#include "retry_attempt.h"

bool InstallRetryGate::Attempt(const QString& title, const QString& what, const Action& action,
                               QString& failure) const {
    return RetryAttempt(action,
                        [&](const QString& text) {
                            return ask_retry_(title, QStringLiteral("%1 failed:\n%2\n\nRetry?").arg(what, text));
                        },
                        failure);
}
