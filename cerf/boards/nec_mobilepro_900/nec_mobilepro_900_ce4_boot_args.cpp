#include "nec_mobilepro_900_boot_args.h"

#include "../../core/cerf_emulator.h"

namespace {

/* nec_mobilepro_900_ce4_2 SABOOT.NB0 nk.exe: sub_9006D324 (mode, MHz), sub_9007DC4C (cause, state),
   sub_9007DCF4 (0x1A838 -> 0x1A83C), sub_9007DC14 (0x1A890), sub_9007DD9C (0x1A844), 0x900615D4-
   0x900615E0 (watchdog cause), sub_9006AF28 (0x1A86C, 0x1A864), 0x90061354-0x900613DC (FFUART). */
constexpr NecMobilepro900BootArgsLayout kLayout = {
    0xA001E854u, 0xA001E858u, 0xA001E85Cu, 0xA001E868u,
    0xA001E838u, 0xA001E83Cu, 0x0001A890u,
    true, 0xA001E844u, true,
    true, 0xA001E86Cu, 0xA001E864u,
    true, true,
};

class NecMobilepro900Ce4BootArgs : public NecMobilepro900BootArgs {
public:
    using NecMobilepro900BootArgs::NecMobilepro900BootArgs;

    bool ShouldRegister() override { return BoardMatchesKernelMajor(4); }

    const NecMobilepro900BootArgsLayout& Layout() const override { return kLayout; }
};

}

REGISTER_SERVICE_AS(NecMobilepro900Ce4BootArgs, NecMobilepro900BootArgs);
