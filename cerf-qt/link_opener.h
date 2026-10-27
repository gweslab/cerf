#pragma once

#include <cerfcore/core/service.h>

#include <string>

namespace cerffrontend {

class LinkOpener : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    virtual void Open(const std::string& url) = 0;
};

}
