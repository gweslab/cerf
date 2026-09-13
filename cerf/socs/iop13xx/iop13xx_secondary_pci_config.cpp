#include "iop13xx_pci_config_controller.h"
namespace {
class Iop13xxSecondaryPciConfig final : public Iop13xxPciConfigController<0xFFDC832Cu, false> {
public:
    using Iop13xxPciConfigController::Iop13xxPciConfigController;

};
} // namespace
REGISTER_SERVICE(Iop13xxSecondaryPciConfig);
