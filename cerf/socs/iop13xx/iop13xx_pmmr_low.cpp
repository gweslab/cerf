#include "iop13xx_cp6.h"
#include "iop13xx_pmmr_guard.h"
#include "../../socs/irq_controller.h"
#include "../../state/state_stream.h"
namespace {
class Iop13xxPmmrLow final : public Iop13xxPmmrRange<0xFFD80000u, 0x00002340u> {
public:
    using Iop13xxPmmrRange::Iop13xxPmmrRange;
    void SaveState(StateWriter& w) override { static_cast<Iop13xxCp6&>(emu_.Get<IrqController>()).SaveState(w); }
    void RestoreState(StateReader& r) override { static_cast<Iop13xxCp6&>(emu_.Get<IrqController>()).RestoreState(r); }
    void PostRestore() override { static_cast<Iop13xxCp6&>(emu_.Get<IrqController>()).PostRestoreState(); }

};
} // namespace
REGISTER_SERVICE(Iop13xxPmmrLow);
