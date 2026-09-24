#include "../../peripherals/peripheral_base.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_context.h"
#include "imx51_id.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../irq_controller.h"
#include "imx51_gpu2d_command_engine.h"
#include "imx51_gpu2d_rasterizer.h"

#include <cstdint>

namespace {

/* g12 register page 0x1000: functional 0x800 (MCIMX51RM Table 37-1) + PrimeCell PERIPHID 0xFE4/0xFE8. */
constexpr uint32_t kBase = 0xD0000000u;
constexpr uint32_t kSize = 0x00001000u;

/* Command-window funnel ports (vgregs_z160.h:52/57). Internal 2/VG registers are
   write-only and reached ONLY through a two-write sequence to one of these ports
   (gsl_cmdwindow.c:104-133): word1 latches (target,addr), word2 is the data for
   internal register addr. */
constexpr uint32_t kOffCommandStream    = 0x000u;  /* ADDR_VGC_COMMANDSTREAM */
constexpr uint32_t kOffMmuCommandStream = 0x3FCu;  /* ADDR_VGC_MMUCOMMANDSTREAM */

/* MH-register read indirection (shipped kgsl_g12_regread sub_C1016D50): to read an
   MH register the guest writes its index to ADDR_MMU_READ_ADDR then reads the value
   back from ADDR_MMU_READ_DATA. */
constexpr uint32_t kOffMmuReadAddr = 0x510u;  /* ADDR_MMU_READ_ADDR */
constexpr uint32_t kOffMmuReadData = 0x518u;  /* ADDR_MMU_READ_DATA */

constexpr uint32_t kAddrMhArbiterConfig = 0xA40u;  /* MH_ARBITER_CONFIG, vgregs_z160.h:130 */
constexpr uint32_t kAddrMhMmuConfig     = 0x40u;   /* MH_MMU_CONFIG, vgregs_z160.h:139 */
constexpr uint32_t kAddrMhInterruptMask = 0xA42u;  /* MH_INTERRUPT_MASK, vgregs_z160.h:137 */
constexpr uint32_t kAddrMhMpuBase       = 0x46u;   /* MH_MMU_MPU_BASE, vgregs_z160.h:141 */
constexpr uint32_t kAddrMhMpuEnd        = 0x47u;   /* MH_MMU_MPU_END, vgregs_z160.h:142 */

/* ADDR_VGC_IRQENABLE (0x438, vgregs_z160.h:54): MH/G2D/FIFO/FBC interrupt-enable
   bitmask (vgregs_z160.h:1685-1694). Interface register, R/W accessible per
   MCIMX51RM §37.8.1 (interface regs 0x400-0x7FC read/write). */
constexpr uint32_t kOffIrqEnable    = 0x438u;
constexpr uint32_t kOffIrqStatus    = 0x418u;  /* ADDR_VGC_IRQSTATUS (vgregs_z160.h:55) */
constexpr uint32_t kOffIrqActiveCnt = 0x4E0u;  /* ADDR_VGC_IRQ_ACTIVE_CNT (vgregs_z160.h:56) */
constexpr uint32_t kVgcIrqG2d       = 0x2u;    /* VGC_IRQ*_G2D bit1 (vgregs_z160.h:1701/1689/1713) */
constexpr int      kTzicG2d         = 84;      /* gpu2d_int_b, MCIMX51RM Table 3-2 (imgs_intmap_p72.png, S188) */

/* g12 chip-id PATCH_RELEASE(reg 1)/PERIPHID1(0x3F9)/PERIPHID2(0x3FA), getchipid sub_C101EABC -> 0 */
constexpr uint32_t kOffChipIdPatchRelease = 0x004u;
constexpr uint32_t kOffChipIdPeriphId1    = 0xFE4u;
constexpr uint32_t kOffChipIdPeriphId2    = 0xFE8u;

class Imx51Gpu2d : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetSocId() == SocId::Imx51;
    }
    void OnReady() override {
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    uint32_t MmioBase() const override { return kBase; }
    uint32_t MmioSize() const override { return kSize; }

    uint32_t ReadWord(uint32_t a) override {
        switch (a - kBase) {
            case kOffIrqEnable:   return irq_enable_;
            case kOffIrqStatus:   return irqstatus_;
            case kOffIrqActiveCnt: {  /* G2D mark count [15:8]; read-clears (waittimestamp reads it once, sub_C1016E10) */
                const uint32_t v = (irq_active_g2d_ & 0xFFu) << 8;
                irq_active_g2d_ = 0;
                return v;
            }
            case kOffMmuReadData: return ReadMhReg(mh_read_addr_);
            case kOffChipIdPatchRelease:
            case kOffChipIdPeriphId1:
            case kOffChipIdPeriphId2: return 0u;
        }
        HaltUnsupportedAccess("ReadWord", a, 0);
    }
    void WriteWord(uint32_t a, uint32_t v) override {
        switch (a - kBase) {
            case kOffCommandStream:    Funnel(cmd_, v, /*is_mmu=*/false); return;
            case kOffMmuCommandStream: Funnel(mmu_cmd_, v, /*is_mmu=*/true); return;
            case kOffMmuReadAddr:      mh_read_addr_ = v; return;
            case kOffIrqEnable:        irq_enable_ = v; return;
            case kOffIrqStatus:  /* write-1-to-clear ack (kgsl_intr_decode sub_C1017B14) */
                irqstatus_ &= ~v;
                if ((irqstatus_ & kVgcIrqG2d) == 0u) emu_.Get<IrqController>().DeAssertIrq(kTzicG2d);
                return;
        }
        HaltUnsupportedAccess("WriteWord", a, v);
    }

    void SaveState(StateWriter& w) override {
        SaveLatch(w, cmd_);
        SaveLatch(w, mmu_cmd_);
        w.Write("mh_arbiter_config", mh_arbiter_config_);
        w.Write("mh_mmu_config", mh_mmu_config_);
        w.Write("mh_interrupt_mask", mh_interrupt_mask_);
        w.Write("mh_mpu_base", mh_mpu_base_);
        w.Write("mh_mpu_end", mh_mpu_end_);
        w.Write("mh_read_addr", mh_read_addr_);
        w.Write("irq_enable", irq_enable_);
        w.Write("irqstatus", irqstatus_);
        w.Write("irq_active_g2d", irq_active_g2d_);
        /* Services, not in the peripheral walk - serialized through this funnel. */
        emu_.Get<Imx51Gpu2dCommandEngine>().SaveState(w);
        emu_.Get<Imx51Gpu2dRasterizer>().SaveState(w);
    }
    void RestoreState(StateReader& r) override {
        RestoreLatch(r, cmd_);
        RestoreLatch(r, mmu_cmd_);
        r.Read("mh_arbiter_config", mh_arbiter_config_);
        r.Read("mh_mmu_config", mh_mmu_config_);
        r.Read("mh_interrupt_mask", mh_interrupt_mask_);
        r.Read("mh_mpu_base", mh_mpu_base_);
        r.Read("mh_mpu_end", mh_mpu_end_);
        r.Read("mh_read_addr", mh_read_addr_);
        r.Read("irq_enable", irq_enable_);
        r.Read("irqstatus", irqstatus_);
        r.Read("irq_active_g2d", irq_active_g2d_);
        emu_.Get<Imx51Gpu2dCommandEngine>().RestoreState(r);
        emu_.Get<Imx51Gpu2dRasterizer>().RestoreState(r);
    }
    void PostRestore() override {  /* re-drive the restored G2D IRQ line (hibernation.md peripheral contract) */
        if ((irqstatus_ & kVgcIrqG2d) && (irq_enable_ & kVgcIrqG2d))
            emu_.Get<IrqController>().AssertIrq(kTzicG2d);
    }

private:
    /* One command-window port's two-write latch (gsl_cmdwindow.c:119-133,
       GSL_CMDWINDOW_{TARGET,ADDR}_{SHIFT,MASK}): target=w&0xFF, addr=(w>>8)&0xFFFF. */
    struct Latch {
        bool     have_addr = false;
        uint8_t  pad[3]    = {};
        uint32_t target    = 0;
        uint32_t addr      = 0;

        template <typename F>
        static constexpr void Visit(Latch& l, F& field) {
            field("have_addr", l.have_addr);
            field.Skip(l.pad);
            field("target", l.target);
            field("addr", l.addr);
        }
    };

    void Funnel(Latch& l, uint32_t v, bool is_mmu) {
        if (!l.have_addr) {
            l.target    = v & 0xFFu;
            l.addr      = (v >> 8) & 0xFFFFu;
            l.have_addr = true;
            return;
        }
        l.have_addr = false;
        /* MMU stream = MH register space, command stream = 2D/VG register space
           (kgsl_g12_regwrite gsl_g12.c:571-591); the two collide in raw addr. */
        if (is_mmu) WriteMhReg(l.addr, v);
        else if (emu_.Get<Imx51Gpu2dCommandEngine>().WriteReg(l.addr, v))
            CompleteSubmit();
    }

    void WriteMhReg(uint32_t addr, uint32_t data) {
        switch (addr) {
            case kAddrMhArbiterConfig: mh_arbiter_config_ = data; return;
            case kAddrMhMmuConfig:     mh_mmu_config_ = data; return;
            case kAddrMhInterruptMask: mh_interrupt_mask_ = data; return;
            case kAddrMhMpuBase:       mh_mpu_base_ = data; return;
            case kAddrMhMpuEnd:        mh_mpu_end_ = data; return;
        }
        HaltUnsupportedAccess("WriteMhReg", addr, data);
    }
    uint32_t ReadMhReg(uint32_t addr) {
        switch (addr) {
            case kAddrMhArbiterConfig: return mh_arbiter_config_;
            case kAddrMhMmuConfig:     return mh_mmu_config_;
            case kAddrMhInterruptMask: return mh_interrupt_mask_;
            case kAddrMhMpuBase:       return mh_mpu_base_;
            case kAddrMhMpuEnd:        return mh_mpu_end_;
        }
        HaltUnsupportedAccess("ReadMhReg", addr, 0);
    }

    /* One submit retired. The guest advances current_timestamp by 1 per submit
       (issueibcmds sub_C1016F3C) and waittimestamp adds the G2D IRQ_ACTIVE_CNT byte to its
       timestamp (sub_C1016E10), so the completion count is 1 per submit, not the mark count. */
    void CompleteSubmit() {
        if (irq_active_g2d_ < 0xFFu) ++irq_active_g2d_;
        irqstatus_ |= kVgcIrqG2d;
        if (irq_enable_ & kVgcIrqG2d) emu_.Get<IrqController>().AssertIrq(kTzicG2d);
    }

    static void SaveLatch(StateWriter& w, Latch& l) {
        static_assert(StateVisitCoversAllBytes<Latch>(
                          [](Latch& x, StateFieldBytes& f) { Latch::Visit(x, f); }),
                      "Latch::Visit must name or skip every field of Latch");
        StateWriteField field(w);
        Latch::Visit(l, field);
    }
    static void RestoreLatch(StateReader& r, Latch& l) {
        StateReadField field(r);
        Latch::Visit(l, field);
    }

    uint32_t mh_arbiter_config_ = 0;
    uint32_t mh_mmu_config_     = 0;
    uint32_t mh_interrupt_mask_ = 0;
    uint32_t mh_mpu_base_       = 0;
    uint32_t mh_mpu_end_        = 0;
    uint32_t mh_read_addr_      = 0;
    uint32_t irq_enable_        = 0;
    uint32_t irqstatus_         = 0;
    uint32_t irq_active_g2d_    = 0;
    Latch    cmd_;
    Latch    mmu_cmd_;
};

}  /* namespace */

REGISTER_SERVICE(Imx51Gpu2d);
