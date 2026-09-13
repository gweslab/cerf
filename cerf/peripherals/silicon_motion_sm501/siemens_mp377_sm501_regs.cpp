#define NOMINMAX

#include "siemens_mp377_sm501_internal.h"
#include "siemens_mp377_sm501_regs.h"
#include "siemens_mp377_sm501_blitter.h"
#include "siemens_mp377_sm501_register_map.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../socs/irq_controller.h"
#include "../../state/state_stream.h"

#include <algorithm>
#include <cstdint>

namespace siemens_mp377 {
namespace {

/* siemens_mp377_v1040 nk.exe sub_80445460 (BSPIntrInit);
   VGXaudio.dll sub_298913C. */
constexpr int kMp377Sm501IrqSource = 10;
constexpr uint32_t kMp377Sm501IrqContributor = 1u << 1;

} // namespace

bool SiemensMp377Sm501Regs::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoard() == Board::SiemensMP377;
}
void SiemensMp377Sm501Regs::OnReady() {
    ResetDevice(false);
    emu_.Get<PeripheralDispatcher>().Register(this);
    emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
        if (!emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) ResetDevice(true);
    });
}
void SiemensMp377Sm501Regs::ResetDevice(bool synchronize_audio) {
    std::unique_lock<std::recursive_mutex> ac97_lock;
    if (synchronize_audio) ac97_lock = emu_.Get<SiemensMp377Sm501Ac97>().LockForState();
    {
        std::lock_guard<std::mutex> irq_lock(sm501_irq_mutex_);
        regs_.assign(kSm501RegsBytes / 4u, 0u);
        /* SM501 MMCC Databook v1.02, table 2-1 and DRAM Control. */
        regs_[kSm501SystemControlReg / 4u] = 0x00100000u;
        regs_[kSm501MiscControlReg / 4u] = 0x00001000u;
        regs_[kSm501DramControlReg / 4u] = 0x07F147C0u;
        regs_[kSm501ArbitrationControlReg / 4u] = 0x05146732u;
        regs_[0x000068u / 4u] = 0x00090900u;
        regs_[0x080200u / 4u] = 0x00010000u;
        emu_.Get<SiemensMp377Sm501PowerGpio>().Initialize(*this);
        panel_fb_raw_ = 0u;
        panel_pitch_bytes_ = 0u;
    }
    emu_.Get<IrqController>().SetSharedIrqLevel(kMp377Sm501IrqSource, kMp377Sm501IrqContributor, false);
}
uint32_t SiemensMp377Sm501Regs::MmioBase() const {
    return kSm501RegsBarPa;
}
uint32_t SiemensMp377Sm501Regs::MmioSize() const {
    return kSm501RegsBytes;
}
uint32_t SiemensMp377Sm501Regs::PanelFbOffset() const {
    return NormalizePanelFbOffset(panel_fb_raw_);
}

/* SM501 Databook v1.02 section 5, Panel Horizontal Total, HDE[11:0]. */
uint32_t SiemensMp377Sm501Regs::PanelWidthPixels() const {
    const uint32_t hde = ReadSm501Register(0x080024u) & 0xFFFu;
    return hde ? hde + 1u : 0u;
}

/* SM501 Databook v1.02 section 5, Panel Vertical Total (MMIO_base + 0x08002C):
   VDE bits[10:0] is the "panel vertical display end specified as number of
   lines - 1". */
uint32_t SiemensMp377Sm501Regs::PanelHeightLines() const {
    const uint32_t vde = ReadSm501Register(0x08002Cu) & 0x7FFu;
    return vde ? vde + 1u : 0u;
}
uint32_t SiemensMp377Sm501Regs::PanelPitchBytes() const {
    return panel_pitch_bytes_;
}

uint32_t SiemensMp377Sm501Regs::CrtFbOffset() const {
    return NormalizePanelFbOffset(ReadSm501Register(0x080204u));
}

uint32_t SiemensMp377Sm501Regs::CrtPitchBytes() const {
    return DecodePanelPitchBytes(ReadSm501Register(0x080208u));
}

uint32_t SiemensMp377Sm501Regs::CrtWidthPixels() const {
    const uint32_t hde = ReadSm501Register(0x08020Cu) & 0xFFFu;
    return hde ? hde + 1u : 0u;
}

uint32_t SiemensMp377Sm501Regs::CrtHeightLines() const {
    /* SM501 Databook v1.02 section 5, CRT Vertical Total: VDE bits[10:0]. */
    const uint32_t vde = ReadSm501Register(0x080214u) & 0x7FFu;
    return vde ? vde + 1u : 0u;
}

uint32_t SiemensMp377Sm501Regs::ReadSm501Register(uint32_t offset) const {
    return regs_[offset / 4u];
}

uint8_t SiemensMp377Sm501Regs::ReadByte(uint32_t a) {
    return static_cast<uint8_t>(ReadWord(a & ~3u) >> ((a & 3u) * 8u));
}

uint16_t SiemensMp377Sm501Regs::ReadHalf(uint32_t a) {
    return static_cast<uint16_t>(ReadWord(a & ~3u) >> ((a & 2u) * 8u));
}

uint32_t SiemensMp377Sm501Regs::ReadWord(uint32_t a) {
    uint32_t off = 0;
    if (!Sm501RegsPaToOffset(a, off)) HaltUnsupportedAccess("SM501 regs read outside BAR1", a, 0);
    std::unique_lock<std::recursive_mutex> ac97_lock;
    if (Sm501IsAc97SharedRegister(off)) ac97_lock = emu_.Get<SiemensMp377Sm501Ac97>().LockForState();
    if (SiemensMp377Sm501Dma::IsRegister(off)) {
        const uint32_t value = emu_.Get<SiemensMp377Sm501Dma>().Read(off);
        return value;
    }

    if (SiemensMp377Sm501Ac97::IsRegister(off)) {
        const uint32_t value = emu_.Get<SiemensMp377Sm501Ac97>().Read(off, true);
        return value;
    }

    if (SiemensMp377Sm501AudioMcu::IsControlRegister(off)) {
        auto& mcu = emu_.Get<SiemensMp377Sm501AudioMcu>();
        const uint32_t value = mcu.ReadControl(a, off);
        return value;
    }

    if (SiemensMp377Sm501AudioMcu::IsSram(off)) {
        return emu_.Get<SiemensMp377Sm501AudioMcu>().ReadSramWord(a, off);
    }

    uint32_t value = 0u;
    switch (off) {
    case kSm501DramControlReg: value = regs_[off / 4u]; break;
    case kSm501CommandListStatusReg: value = kSm501CommandListIdle; break;
    case kSm501IrqStatusReg:
        value = emu_.Get<SiemensMp377SmiBridge>().Sm501MasterStatus() | Sm501LatchedInterruptStatus();
        break;
    case kSm501IrqMaskReg: value = Sm501InterruptMask(); break;
    case kSm501CurrentGateReg: value = emu_.Get<SiemensMp377Sm501PowerGpio>().CurrentGate(); break;
    case kSm501CurrentClockReg: value = emu_.Get<SiemensMp377Sm501PowerGpio>().CurrentClock(); break;
    case kSm501PowerMode0GateReg:
    case kSm501PowerMode0ClockReg:
    case kSm501PowerMode1GateReg:
    case kSm501PowerMode1ClockReg:
    case kSm501SleepModeGateReg:
    case kSm501PowerModeControlReg: value = regs_[off / 4u]; break;
    case kSm501GpioDataLowReg: value = emu_.Get<SiemensMp377Sm501PowerGpio>().ReadGpioDataLow(); break;
    case kSm501GpioDirectionLowReg: value = emu_.Get<SiemensMp377Sm501PowerGpio>().ReadGpioDirectionLow(); break;
    case kSm501DeviceIdReg: value = kSm501DeviceId; break;
    case 0x020008u:
    case 0x020108u: {
        value = emu_.Get<SiemensMp377TouchPanel>().ReadSmiSampleWord();
        RefreshSspInterruptCascade();
        break;
    }
    case 0x02000Cu:
    case 0x02010Cu: {
        /* SM501 Databook v1.02, SSP Status T[1:0] and R[1:0]. */
        constexpr uint32_t kTransmitEmpty = 0x3u;
        constexpr uint32_t kReceiveNotEmpty = 0x1u << 2;
        value = kTransmitEmpty;
        if (emu_.Get<SiemensMp377TouchPanel>().HasPendingSmiResponse()) value |= kReceiveNotEmpty;
        break;
    }
    case 0x020014u:
    case 0x020114u: value = SspInterruptStatus(off & ~0x1Fu); break;
    default:
        if (!Sm501IsPlainRegister(off))
            emu_.Get<Fatal>().Die("[MP377 SM501] read of unmodelled BAR1 register pa=0x%08X off=0x%06X", a, off);
        value = regs_[off / 4u];
        break;
    }
    return value;
}

void SiemensMp377Sm501Regs::WriteByte(uint32_t a, uint8_t v) {
    uint32_t off = 0;
    if (!Sm501RegsPaToOffset(a, off)) HaltUnsupportedAccess("SM501 regs byte write outside BAR1", a, v);
    const uint32_t shift = (a & 3u) * 8u;
    uint32_t w = regs_[off / 4u];
    w = (w & ~(0xFFu << shift)) | (static_cast<uint32_t>(v) << shift);
    WriteResolvedWord(a & ~3u, off & ~3u, w);
}

void SiemensMp377Sm501Regs::WriteHalf(uint32_t a, uint16_t v) {
    uint32_t off = 0;
    if (!Sm501RegsPaToOffset(a, off)) HaltUnsupportedAccess("SM501 regs halfword write outside BAR1", a, v);
    const uint32_t shift = (a & 2u) * 8u;
    uint32_t w = regs_[off / 4u];
    w = (w & ~(0xFFFFu << shift)) | (static_cast<uint32_t>(v) << shift);
    WriteResolvedWord(a & ~3u, off & ~3u, w);
}

void SiemensMp377Sm501Regs::WriteWord(uint32_t a, uint32_t v) {
    uint32_t off = 0;
    if (!Sm501RegsPaToOffset(a, off)) HaltUnsupportedAccess("SM501 regs word write outside BAR1", a, v);
    WriteResolvedWord(a, off, v);
}

void SiemensMp377Sm501Regs::WriteResolvedWord(uint32_t a, uint32_t off, uint32_t v) {
    std::unique_lock<std::recursive_mutex> ac97_lock;
    if (Sm501IsAc97SharedRegister(off)) ac97_lock = emu_.Get<SiemensMp377Sm501Ac97>().LockForState();
    if (SiemensMp377Sm501AudioMcu::IsSram(off)) {
        auto& mcu = emu_.Get<SiemensMp377Sm501AudioMcu>();
        const uint32_t old_value = regs_[off / 4u];
        regs_[off / 4u] = v;
        mcu.WriteSramWord(a, off, old_value, v);
        return;
    }
    if (!SiemensMp377Sm501Dma::IsRegister(off) && !SiemensMp377Sm501Ac97::IsRegister(off) &&
        !SiemensMp377Sm501AudioMcu::IsControlRegister(off) && !Sm501IsPlainRegister(off))
        emu_.Get<Fatal>().Die("[MP377 SM501] write of unmodelled BAR1 register 0x%06X = 0x%08X", off, v);
    if (off == kSm501IrqMaskReg) {
        SetSm501InterruptMask(v);
        return;
    }
    const uint32_t old_value = regs_[off / 4u];
    regs_[off / 4u] = v;

    if (off == 0x020014u || off == 0x020114u) {
        /* SM501 Databook v1.02, SSP Interrupt Status: writing any value to
           overflow bit 2 clears it; receive/transmit bits are read-only. */
        constexpr uint32_t kReceiveOverflow = 1u << 2;
        regs_[off / 4u] = old_value & ~kReceiveOverflow;
        RefreshSspInterruptCascade();
        return;
    }

    switch (off) {
    case 0x100000u:
        /* SM501 Databook v1.02 section 4, 2D Source: bit 31 enables
           wrapping and bit 30 is reserved. */
        if ((v & 0x80000000u) != 0u)
            emu_.Get<Fatal>().Die("[MP377 SM501] 2D source wrapping is not implemented");
        regs_[off / 4u] = v & 0x3FFFFFFFu;
        return;
    case 0x100004u:
        /* SM501 Databook v1.02 section 4, 2D Destination: bit 31
           enables wrapping and bits 30:29 are reserved. */
        if ((v & 0x80000000u) != 0u)
            emu_.Get<Fatal>().Die("[MP377 SM501] 2D destination wrapping is not implemented");
        regs_[off / 4u] = v & 0x1FFFFFFFu;
        return;
    case kSm501SystemControlReg:
        regs_[off / 4u] = (old_value & 0x10DB0000u) | (v & 0xEF00B8F7u);
        return;
    case kSm501MiscControlReg:
        regs_[off / 4u] = (old_value & 0x000000EFu) | (v & 0xFF7FFF10u);
        return;
    case kSm501Gpio63_32ControlReg:
        regs_[off / 4u] = v & 0xFF80FFFFu;
        return;
    case kSm501DramControlReg:
        regs_[off / 4u] = (old_value & 0x80000000u) | (v & 0x7FFFFFC3u);
        return;
    case kSm501ArbitrationControlReg:
        regs_[off / 4u] = v & 0x37777777u;
        return;
    case kSm501EndianControlReg:
        if ((v & 1u) != 0u) emu_.Get<Fatal>().Die("[MP377 SM501] big-endian MMIO mode is not implemented");
        regs_[off / 4u] = 0u;
        return;
    case 0x080000u:
        /* SM501 display controller, Panel Display Control. */
        regs_[off / 4u] = v & 0x0FFF73FFu;
        return;
    case 0x080200u:
        /* QEMU v10.1 hw/display/sm501.c sm501_disp_ctrl_write(). */
        regs_[off / 4u] = v & 0x0003FFFFu;
        return;
    case 0x080204u:
    case 0x080230u:
        regs_[off / 4u] = v & 0x8FFFFFF0u;
        return;
    case 0x080208u:
        regs_[off / 4u] = v & 0x3FF03FF0u;
        return;
    case 0x08020Cu:
        regs_[off / 4u] = v & 0x0FFF0FFFu;
        return;
    case 0x080214u:
        /* SM501 Databook v1.02 section 5, CRT Vertical Total:
           VT bits[26:16], VDE bits[10:0]. */
        regs_[off / 4u] = v & 0x07FF07FFu;
        return;
    case 0x080210u:
        regs_[off / 4u] = v & 0x00FF0FFFu;
        return;
    case 0x080218u:
        /* SM501 Databook v1.02 section 5, CRT Vertical Sync:
           VSH bits[21:16], VS bits[10:0]. */
        regs_[off / 4u] = v & 0x003F07FFu;
        return;
    case 0x080234u:
        regs_[off / 4u] = v & 0x0FFF0FFFu;
        return;
    case 0x08023Cu:
        regs_[off / 4u] = v & 0x0000FFFFu;
        return;
    default: break;
    }

    if (off == kSm501GpioIrqStatusReg) {
        /* Databook section 7: writes to 0x010014 reset the selected latched
           GPIO interrupt-status bits. */
        regs_[off / 4u] = old_value & ~v;
        return;
    }

    if (off >= 0x010020u && off <= 0x010028u) {
        /* Databook chapter 15: bit 1 is reserved and bit 3 is a
           write-one-to-clear interrupt-pending flag. */
        constexpr uint32_t kPending = 1u << 3;
        constexpr uint32_t kReserved = 1u << 1;
        regs_[off / 4u] = (v & ~(kPending | kReserved)) | ((old_value & kPending) & ~(v & kPending));
        return;
    }

    if (SiemensMp377Sm501Dma::IsRegister(off)) {
        emu_.Get<SiemensMp377Sm501Dma>().Write(off, v);
        return;
    }

    if (off == kSm501PowerModeControlReg) {
        emu_.Get<SiemensMp377Sm501PowerGpio>().WritePowerModeControl(v);
        emu_.Get<SiemensMp377Sm501PowerGpio>().UpdateAc97Link();
    } else if (off == kSm501PowerMode0GateReg || off == kSm501PowerMode0ClockReg || off == kSm501PowerMode1GateReg ||
               off == kSm501PowerMode1ClockReg || off == kSm501SleepModeGateReg || off == kSm501Gpio31_0ControlReg ||
               off == kSm501GpioDataLowReg || off == kSm501GpioDirectionLowReg) {
        emu_.Get<SiemensMp377Sm501PowerGpio>().UpdateAc97Link();
    }

    if (SiemensMp377Sm501Ac97::IsRegister(off)) {
        emu_.Get<SiemensMp377Sm501Ac97>().Write(off, old_value, v);
        return;
    }

    if (SiemensMp377Sm501AudioMcu::IsControlRegister(off)) {
        auto& mcu = emu_.Get<SiemensMp377Sm501AudioMcu>();
        mcu.WriteControl(off, old_value, v);
        return;
    }

    if (off == 0x020004u || off == 0x020104u) RefreshSspInterruptCascade();

    if (off == 0x08000Cu) {
        panel_fb_raw_ = v;
    } else if (off == 0x080010u) {
        panel_pitch_bytes_ = DecodePanelPitchBytes(v);
    }

    if (off == 0x020008u || off == 0x020108u) {
        if (emu_.Get<SiemensMp377TouchPanel>().QueueSmiCommand(static_cast<uint16_t>(v & 0xFFFFu)))
            regs_[((off & ~0x1Fu) + 0x14u) / 4u] |= 1u << 2;
        RefreshSspInterruptCascade();
    }
    if (SiemensMp377Sm501Blitter::IsCommandRegister(off) && (v & 0x80000000u)) {
        emu_.Get<SiemensMp377Sm501Blitter>().ExecuteCommand(v);
    }
    if (SiemensMp377Sm501Blitter::IsDataPort(off)) emu_.Get<SiemensMp377Sm501Blitter>().WriteDataPort(v);
}

uint32_t SiemensMp377Sm501Regs::SspInterruptStatus(uint32_t base) const {
    /* SM501 Databook v1.02, SSP Interrupt Status and SSP Interrupts. */
    constexpr uint32_t kReceive = 1u << 0;
    constexpr uint32_t kTransmit = 1u << 1;
    constexpr uint32_t kOverflow = 1u << 2;
    uint32_t status = kTransmit | (regs_[(base + 0x14u) / 4u] & kOverflow);
    if (emu_.Get<SiemensMp377TouchPanel>().PendingSmiResponseCount() >= 4u) status |= kReceive;
    return status;
}

void SiemensMp377Sm501Regs::RefreshSspInterruptCascade() {
    /* SM501 Databook v1.02 section 16: SSPINTR is the OR of the three status
       sources after their matching Control 1 mask bits are applied. */
    constexpr uint32_t kInterruptEnableBits = 0x7u;
    bool pending = false;
    for (const uint32_t base : {0x020000u, 0x020100u}) {
        const uint32_t control = regs_[(base + 0x04u) / 4u];
        pending = pending || ((control & SspInterruptStatus(base) & kInterruptEnableBits) != 0u);
    }
    auto& bridge = emu_.Get<SiemensMp377SmiBridge>();
    if (pending)
        bridge.AssertPending();
    else
        bridge.ClearPending();
}

uint32_t SiemensMp377Sm501Regs::NormalizePanelFbOffset(uint32_t v) {
    uint32_t off = 0;
    if (Sm501FbPaToOffset(v, off)) return off;

    off = v & 0x03FFFFFFu;
    return off < kSm501FbBytes ? off : kSm501FbBytes;
}

uint32_t SiemensMp377Sm501Regs::DecodePanelPitchBytes(uint32_t v) {
    /* SM501 Databook v1.02, Panel FB Offset register, pages 135-136. */
    const uint32_t bytes = ((v >> 4) & 0x3FFu) * 16u;
    if (bytes < 2u || bytes > kSm501FbBytes / 2u) return 0u;
    return bytes;
}

uint32_t SiemensMp377Sm501Regs::Sm501LatchedInterruptStatus() const {
    std::lock_guard<std::mutex> lock(sm501_irq_mutex_);
    return regs_[kSm501IrqStatusReg / 4u] & kSm501LatchedIrqBits;
}
uint32_t SiemensMp377Sm501Regs::Sm501InterruptMask() const {
    std::lock_guard<std::mutex> lock(sm501_irq_mutex_);
    return regs_[kSm501IrqMaskReg / 4u] & kSm501WritableIrqMaskBits;
}
void SiemensMp377Sm501Regs::SetSm501InterruptMask(uint32_t value) {
    /* SM501 MMCC Databook v1.02, Interrupt Mask. */
    constexpr uint32_t kValidInterruptMaskBits = 0xFFDF3F4Fu;
    const uint32_t unsupported = value & kValidInterruptMaskBits & ~kSm501WritableIrqMaskBits;
    if (unsupported != 0u)
        emu_.Get<Fatal>().Die("[MP377 SM501] unimplemented interrupt mask bits 0x%08X", unsupported);
    {
        std::lock_guard<std::mutex> lock(sm501_irq_mutex_);
        regs_[kSm501IrqMaskReg / 4u] = value & kSm501WritableIrqMaskBits;
    }
    RefreshSm501InterruptLine();
}
void SiemensMp377Sm501Regs::RefreshSm501InterruptLine() {
    std::lock_guard<std::mutex> lock(sm501_irq_mutex_);
    const uint32_t active = regs_[kSm501IrqStatusReg / 4u] & regs_[kSm501IrqMaskReg / 4u] &
                            kSm501LatchedIrqBits;
    emu_.Get<IrqController>().SetSharedIrqLevel(kMp377Sm501IrqSource,
                                                kMp377Sm501IrqContributor,
                                                active != 0u);
}
void SiemensMp377Sm501Regs::RaiseSm501InterruptBits(uint32_t bits) {
    bits &= kSm501LatchedIrqBits;
    if (bits == 0u) return;
    {
        std::lock_guard<std::mutex> lock(sm501_irq_mutex_);
        regs_[kSm501IrqStatusReg / 4u] |= bits;
    }
    RefreshSm501InterruptLine();
}

void SiemensMp377Sm501Regs::ClearSm501InterruptBits(uint32_t bits) {
    bits &= kSm501LatchedIrqBits;
    if (bits == 0u) return;
    {
        std::lock_guard<std::mutex> lock(sm501_irq_mutex_);
        regs_[kSm501IrqStatusReg / 4u] &= ~bits;
    }
    RefreshSm501InterruptLine();
}

REGISTER_SERVICE(SiemensMp377Sm501Regs);

} // namespace siemens_mp377
