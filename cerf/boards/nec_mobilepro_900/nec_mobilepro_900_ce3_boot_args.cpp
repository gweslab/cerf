#include "nec_mobilepro_900_boot_args.h"

#include "../../core/cerf_emulator.h"

namespace {

/* nec_mobilepro_900_hpc2000 XIP.BIN nk.exe: sub_84093EE0 (cause 0x1A860, state 0x1A86C), sub_84093FF0
   (MHz 0x1A85C), sub_84093F80 (0x1A838 -> 0x1A83C), sub_84093EAC (0x1A898), 0x84091330-0x840913BC,
   sub_8409403C / sub_840940C4 (nullsub_5 / nullsub_6 debug serial); ddi.dll sub_11B24DC (mode). */
constexpr NecMobilepro900BootArgsLayout kLayout = {
    0xA001E858u, 0xA001E85Cu, 0xA001E860u, 0xA001E86Cu,
    0xA001E838u, 0xA001E83Cu, 0x0001A898u,
    false, 0u, false,
    false, 0u, 0u,
    false, false,
};

class NecMobilepro900Ce3BootArgs : public NecMobilepro900BootArgs {
public:
    using NecMobilepro900BootArgs::NecMobilepro900BootArgs;

    bool ShouldRegister() override { return BoardMatchesKernelMajor(3); }

    const NecMobilepro900BootArgsLayout& Layout() const override { return kLayout; }
};

}

REGISTER_SERVICE_AS(NecMobilepro900Ce3BootArgs, NecMobilepro900BootArgs);
