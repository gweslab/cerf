#include "iop13xx_pci_config_controller.h"
namespace {
class Iop13xxPrimaryPciConfig final : public Iop13xxPciConfigController<0xFFDCD330u, true> {
public:
    using Iop13xxPciConfigController::Iop13xxPciConfigController;

};
} // namespace
REGISTER_SERVICE(Iop13xxPrimaryPciConfig);
