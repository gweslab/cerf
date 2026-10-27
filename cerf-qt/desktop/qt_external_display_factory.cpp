#include <cerfcore/host/external_display.h>

#include "qt_external_display.h"

#include <cerfcore/core/cerf_emulator.h>

#include <memory>

namespace {

class QtExternalDisplayFactory : public cerfcore::ExternalDisplayFactory {
public:
    using cerfcore::ExternalDisplayFactory::ExternalDisplayFactory;

    std::unique_ptr<cerfcore::ExternalDisplay> Create(cerfcore::FrameSource& source,
                                                      const std::string& title,
                                                      std::function<void()> on_eject) override {
        return std::make_unique<QtExternalDisplay>(emu_, source, QString::fromStdString(title),
                                                   std::move(on_eject));
    }
};

}

REGISTER_SERVICE_AS(QtExternalDisplayFactory, cerfcore::ExternalDisplayFactory);
