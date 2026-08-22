#include "../os_timer.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../pxa2xx/pxa2xx_intc.h"

namespace {

/* Intel PXA27x Developer's Manual 280000-001 Table 25-2 (page 25-5): "IP[29]
   Operating system timers OS timer equals Match register 3" .. "IP[26] OS timer
   equals Match register 0". */
constexpr uint32_t kIntcOst0Bit = 26u;

class Pxa27xOsTimer : public OsTimer {
public:
    using OsTimer::OsTimer;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSoc() == SocFamily::PXA27x;
    }

    /* Table 22-12 (page 22-19) "OS Timers Register Summary": "0x40A0_0000
       OSMR0", "0x40A0_0010 OSCR0", "0x40A0_001C OIER". */
    uint32_t MmioBase() const override { return 0x40A00000u; }

    /* symbol_mk500 dump.bin OAL 0x801BFC38 builds 0xA6C00010, the uncached
       alias of PA 0x40A0_0010 OSCR0, then reads it as "LDRB r0,[r1]" /
       "LDRB r3,[r1,#1]" / "LDRB r2,[r1,#2]" / "LDRB r1,[r1,#3]" reassembled by
       "ORR r3,r0,r3,LSL#8" / "ORR r3,r3,r2,LSL#16" / "ORR r1,r3,r1,LSL#24".
       Intel PXA27x Developer's Manual 280000-001 Section 2.8 (page 2-9): "some
       units allow byte or half-word accesses. Refer to the unit chapter to
       determine what accesses are allowed"; Section 22.6 Table 22-12 (page
       22-19) states no access width for the OS timers. */
    uint8_t ReadByte(uint32_t addr) override {
        return static_cast<uint8_t>(LaneByte(addr));
    }

    FastReadFn FastReader() override { return &Pxa27xOsTimer::FastReadThunk; }

protected:
    void SetMatchLevel(uint32_t level4) override {
        static_cast<Pxa2xxIntc&>(emu_.Get<IrqController>())
            .SetSourceLevel(0xFu << kIntcOst0Bit,
                            (level4 & 0xFu) << kIntcOst0Bit);
    }

private:
    uint32_t LaneByte(uint32_t addr) {
        const uint32_t word  = ReadWord(addr & ~0x3u);
        const uint32_t shift = (addr & 0x3u) * 8u;
        return (word >> shift) & 0xFFu;
    }

    static uint32_t FastReadThunk(void* ctx, uint32_t off, uint32_t width) {
        auto*          self = static_cast<Pxa27xOsTimer*>(ctx);
        const uint32_t addr = self->MmioBase() + off;
        if (width == 4u) return self->ReadWord(addr);
        if (width == 1u) return self->LaneByte(addr);
        self->HaltUnsupportedAccess("FastRead", addr, 0);
    }
};

REGISTER_SERVICE(Pxa27xOsTimer);

}  /* namespace */
