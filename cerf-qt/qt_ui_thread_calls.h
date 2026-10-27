#pragma once

#include <cerfcore/core/service.h>

#include <QObject>

#include <condition_variable>
#include <functional>
#include <mutex>

class QtUiThreadCalls : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    bool Run(std::function<void()> job);
    void Close();

private:
    std::mutex              mutex_;
    std::condition_variable finished_;
    bool                    closed_ = false;
    QObject                 context_;
};
