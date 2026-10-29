#pragma once

#include <cerfcore/core/service.h>

#include <functional>
#include <vector>

class QEventLoop;

class NestedEventLoops : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    void Run(QEventLoop& loop);
    bool Running() const { return !loops_.empty(); }
    void QuitAll(std::function<void()> after);

private:
    std::vector<QEventLoop*> loops_;
    std::function<void()>    after_;
    bool                     quitting_ = false;
};
