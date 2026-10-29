#pragma once

#include <cerfcore/core/service.h>

#include <functional>
#include <map>
#include <mutex>

namespace cerfcore {
class FrameSource;
}

class ExternalDisplaySources : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    int                   Add(cerfcore::FrameSource& source, std::function<void()> on_eject);
    void                   Remove(int id);
    cerfcore::FrameSource& Source(int id);
    void                   Eject(int id);

private:
    struct Entry {
        cerfcore::FrameSource* source;
        std::function<void()>  on_eject;
    };

    std::mutex           mutex_;
    std::map<int, Entry> entries_;
    int                  next_id_ = 1;
};
