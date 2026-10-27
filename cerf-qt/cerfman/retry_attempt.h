#pragma once

template <typename Text, typename Action, typename AskRetry>
bool RetryAttempt(const Action& action, const AskRetry& ask_retry, Text& failure) {
    for (;;) {
        failure = Text();
        if (action(failure)) return true;
        if (!ask_retry(failure)) return false;
    }
}
