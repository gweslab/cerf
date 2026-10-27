#pragma once

#include <cerfcore/core/service.h>

#include <string>

namespace cerffrontend {

class FrontendDialogs : public cerfcore::Service {
public:
    using cerfcore::Service::Service;

    virtual std::string ChooseStateFile(bool save, const std::string& default_path) = 0;
    virtual bool        ConfirmWarning(const std::string& title, const std::string& text) = 0;
};

}
