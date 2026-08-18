#include "imx51_usboh3.h"
#include "usb_device_host.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../boards/board_context.h"
#include "../../cpu/emulated_memory.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../irq_controller.h"

#include <array>
#include <cstdint>
#include <vector>

namespace {

constexpr uint32_t kBase = 0x73F80000u;

constexpr uint32_t kOffUsbcmd   = 0x00000140u;  /* USBCMD within each core */
constexpr uint32_t kUsbcmdReset = 1u << 1;      /* USBCMD.RST */
constexpr uint32_t kOffCaplen   = 0x00000100u;  /* CAPLENGTH(b0)+HCIVERSION(b16) */
/* CAPLENGTH 0x40 (operational regs at cap+0x40) | HCIVERSION 0x0100 (EHCI 1.00). */
constexpr uint32_t kCapReset = 0x01000040u;
/* EHCI 1.0 Spec Table 2-5 (p13) + Table 2-6 (p14, N_PORTS bits 3:0). */
constexpr uint32_t kOffHcsparams = kOffCaplen + 0x04u;
constexpr uint32_t kHcsparamsOnePort = 1u;

constexpr uint32_t kOffUsbsts = 0x00000144u;  /* USBSTS (=USBCMD+4) */
constexpr uint32_t kCmdRs  = 1u << 0;   /* USBCMD.RS  Run/Stop */
constexpr uint32_t kCmdPse = 1u << 4;   /* USBCMD.PSE */
constexpr uint32_t kCmdAse = 1u << 5;   /* USBCMD.ASE */
constexpr uint32_t kStsHch = 1u << 12;  /* USBSTS.HCH (RO; set when RS=0) */
constexpr uint32_t kStsPss = 1u << 14;  /* USBSTS.PS  (RO==PSE) */
constexpr uint32_t kStsAss = 1u << 15;  /* USBSTS.AS  (RO==ASE) */
constexpr uint32_t kUsbstsRoMask = kStsHch | (1u << 13) | kStsPss | kStsAss;

constexpr uint32_t kOffUlpiview = 0x00000170u;
constexpr uint32_t kUlpiWu  = 1u << 31;
constexpr uint32_t kUlpiRun = 1u << 30;
constexpr uint32_t kUlpiRw  = 1u << 29;

/* Device-controller registers within the OTG core (MCIMX51RM Ch 60 Table 60-2). */
constexpr uint32_t kOffUsbmode      = 0x000001A8u;
constexpr uint32_t kUsbmodeCmMask   = 0x3u;
constexpr uint32_t kUsbmodeDevice   = 0x2u;   /* CM=10: device controller */
constexpr uint32_t kOffPortsc       = 0x00000184u;
constexpr uint32_t kPortscCcs       = 1u << 0;
constexpr uint32_t kPortscPe        = 1u << 2;
constexpr uint32_t kPortscHsp       = 1u << 9;
constexpr uint32_t kPortscPspdShift = 26;
constexpr uint32_t kPortscPspdHs    = 0x2u << kPortscPspdShift;
constexpr uint32_t kPortscDevAttached =
    kPortscCcs | kPortscPe | kPortscHsp | kPortscPspdHs;

/* EHCI 1.0 Spec Table 2-16 (p27), PP field: with HCSPARAMS.PPC=0 (no port
   power switches, kHcsparamsOnePort below) PP is RO and hard-wired to 1 -
   "port power is always available". Host-mode PORTSC1 must reflect this on
   every read, or guest port-reset gating that requires PP=1 never opens. */
constexpr uint32_t kPortscPp = 1u << 12;

constexpr uint32_t kOffUsbintr       = 0x00000148u;
constexpr uint32_t kOffEndptlistaddr = 0x00000158u;  /* dQH array base (2 KB aligned) */
constexpr uint32_t kOffEndptsetupstat= 0x000001ACu;  /* per-EP setup-received (w1c) */
constexpr uint32_t kOffEndptprime    = 0x000001B0u;  /* per-ep-dir prime (self-clear) */
constexpr uint32_t kOffEndptflush    = 0x000001B4u;
constexpr uint32_t kOffEndptcomplete = 0x000001BCu;  /* per-ep-dir complete (w1c) */
/* USBSTS device interrupt bits (MCIMX51RM Ch 60, p2896-2897). */
constexpr uint32_t kStsUi  = 1u << 0;   /* USB transaction complete */
constexpr uint32_t kStsUei = 1u << 1;   /* error */
constexpr uint32_t kStsPci = 1u << 2;   /* port change detect */
constexpr uint32_t kStsUri = 1u << 6;   /* USB reset received */
constexpr uint32_t kDevIntBits = kStsUi | kStsUei | kStsPci | kStsUri;
constexpr uint32_t kUsbOtgIrq = 18u;    /* TZIC source 18 (SBOOT sub_8005DC4C) */

/* ChipIdea device dQH/dTD layout, MCIMX51RM Fig 60-88/89/90: dQH array indexed
   (2*ep + dir_in) on a 64-byte stride; the constants below name the field offsets. */
constexpr uint32_t kDqhStride   = 0x40u;
constexpr uint32_t kDqhOvNext   = 0x08u;
constexpr uint32_t kDqhOvCur    = 0x04u;
constexpr uint32_t kDqhOvToken  = 0x0Cu;
constexpr uint32_t kSetupBufOff = 0x28u;
constexpr uint32_t kDtdNext     = 0x00u;
constexpr uint32_t kDtdToken    = 0x04u;
constexpr uint32_t kDtdBuf0     = 0x08u;
constexpr uint32_t kDtdTerminate = 1u;
constexpr uint32_t kTokenActive  = 0x80u;
constexpr uint32_t kPageSize     = 0x1000u;

constexpr uint8_t kUsb3317Id[4] = {0x24u, 0x04u, 0x06u, 0x00u};

}  /* namespace */

REGISTER_SERVICE(Imx51Usboh3);

bool Imx51Usboh3::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSoc() == SocFamily::iMX51;
}

void Imx51Usboh3::OnReady() {
    for (uint32_t core = 0; core < kNonCore; core += kCoreSpan) {
        regs_[(core + kOffCaplen) >> 2] = kCapReset;
        /* Out of reset the host controller is halted (Table 60-40/41). */
        regs_[(core + kOffUsbsts) >> 2] = kStsHch;
    }
    regs_[kOffHcsparams >> 2] = kHcsparamsOnePort;
    for (auto& phy : phy_)
        for (uint8_t i = 0; i < 4; ++i) phy[i] = kUsb3317Id[i];
    emu_.Get<PeripheralDispatcher>().Register(this);
}

uint32_t Imx51Usboh3::MmioBase() const { return kBase; }
uint32_t Imx51Usboh3::MmioSize() const { return kSize; }

uint8_t Imx51Usboh3::ReadByte(uint32_t addr) {
    const uint32_t off = addr - kBase;
    return static_cast<uint8_t>(regs_[off >> 2] >> ((off & 3u) * 8u));
}
uint16_t Imx51Usboh3::ReadHalf(uint32_t addr) {
    const uint32_t off = addr - kBase;
    return static_cast<uint16_t>(regs_[off >> 2] >> ((off & 2u) * 8u));
}
uint32_t Imx51Usboh3::ReadWord(uint32_t addr) {
    const uint32_t off = addr - kBase;
    /* Device mode (core0): CERF is the always-present host, so PORTSC1 reflects a
       connected, enabled, high-speed device port (sub_8005D97C polls it). */
    if (off == kOffPortsc && Core0IsDevice())
        return regs_[off >> 2] | kPortscDevAttached;
    const uint32_t coff = off % kCoreSpan;
    if (off < kCoreSpan && !Core0IsDevice() && (coff == kOffUsbsts || coff == kOffPortsc)) {
        ExecuteAsyncSchedule();
    }
    if (coff == kOffPortsc && !Core0IsDevice())
        return regs_[off >> 2] | kPortscPp;
    return regs_[off >> 2];
}

void Imx51Usboh3::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - kBase;
    if (off < kNonCore) {
        const uint32_t coff = off % kCoreSpan;
        const bool core0_dev = off < kCoreSpan && Core0IsDevice();
        if (coff == kOffUsbcmd) {
            const bool reset_requested = (value & kUsbcmdReset) != 0u;
            value &= ~kUsbcmdReset;   /* RST self-clears at reset completion */
            const uint32_t old = regs_[off >> 2];
            regs_[off >> 2] = value;
            if (core0_dev) {
                /* RS 0->1: CERF (host) attaches and drives a bus reset ->
                   USBSTS.URI|PCI, raising the OTG interrupt. */
                if ((value & kCmdRs) && !(old & kCmdRs))
                    regs_[kOffUsbsts >> 2] |= kStsUri | kStsPci;
                RefreshDeviceIrq();
            } else {
                if (off < kCoreSpan && reset_requested) host_port_reported_ = false;
                ReflectScheduleStatus(off, value);
                if (off < kCoreSpan && (value & kCmdRs) && (value & kCmdAse)) {
                    ExecuteAsyncSchedule();
                }
            }
            return;
        }
        if (coff == kOffUsbsts) {
            const uint32_t old = regs_[off >> 2];
            regs_[off >> 2] = (old & kUsbstsRoMask) | (old & ~kUsbstsRoMask & ~value);
            if (core0_dev) {
                RefreshDeviceIrq();
                /* URI cleared marks the start of SBOOT's reset handler
                   (sub_8005D554); it clears ENDPTSETUPSTAT next, so enumeration
                   must wait until the handler's ENDPTFLUSH write below - a SETUP
                   delivered here would have its ENDPTSETUPSTAT wiped. */
                if ((old & kStsUri) && (value & kStsUri))
                    reset_seen_ = true;
            } else if (off < kCoreSpan) {
                RefreshDeviceIrq();
            }
            return;
        }
        if (off < kCoreSpan && coff == kOffUsbintr) {
            regs_[off >> 2] = value;
            RefreshDeviceIrq();
            return;
        }
        if (core0_dev && (coff == kOffEndptsetupstat || coff == kOffEndptcomplete)) {
            regs_[off >> 2] &= ~value;   /* write-1-clear */
            return;
        }
        if (core0_dev && coff == kOffEndptprime) {
            ExecutePrime(value);
            regs_[off >> 2] = 0;         /* prime self-clears once serviced */
            return;
        }
        if (core0_dev && coff == kOffEndptflush) {
            regs_[off >> 2] = 0;
            /* The reset handler's ENDPTFLUSH is the first one after URI; by here
               it has already cleared ENDPTSETUPSTAT, so the host can deliver its
               first SETUP and it will survive to the next ISR. */
            if (reset_seen_) {
                reset_seen_ = false;
                if (host_) host_->OnDeviceReset();
            }
            return;
        }
        if (coff == kOffUlpiview) {
            regs_[off >> 2] = UlpiTransfer(off / kCoreSpan, value);
            return;
        }
        if (off < kCoreSpan && !core0_dev && coff == kOffEndptlistaddr) {
            regs_[off >> 2] = value;
            ExecuteAsyncSchedule();
            return;
        }
        if (off < kCoreSpan && !core0_dev && coff == kOffPortsc) {
            WriteOtgHostPortsc(value);
            return;
        }
    }
    regs_[off >> 2] = value;
}

void Imx51Usboh3::SaveState(StateWriter& w) {
    w.WriteBytes(regs_.data(), sizeof(regs_));
    w.WriteBytes(phy_.data(), sizeof(phy_));
    w.Write<uint8_t>(reset_seen_ ? 1 : 0);
    if (host_) host_->SaveState(w);   /* forward to the registered USB host driver */
}
void Imx51Usboh3::RestoreState(StateReader& r) {
    r.ReadBytes(regs_.data(), sizeof(regs_));
    r.ReadBytes(phy_.data(), sizeof(phy_));
    uint8_t b = 0; r.Read(b); reset_seen_ = b != 0;
    if (host_) host_->RestoreState(r);
}

bool Imx51Usboh3::Core0IsDevice() const {
    return (regs_[kOffUsbmode >> 2] & kUsbmodeCmMask) == kUsbmodeDevice;
}

void Imx51Usboh3::RefreshDeviceIrq() {
    const bool pending = (regs_[kOffUsbsts >> 2] & regs_[kOffUsbintr >> 2] &
                          kDevIntBits) != 0;
    auto& intc = emu_.Get<IrqController>();
    if (pending) intc.AssertIrq(static_cast<int>(kUsbOtgIrq));
    else         intc.DeAssertIrq(static_cast<int>(kUsbOtgIrq));
}

void Imx51Usboh3::ReflectScheduleStatus(uint32_t usbcmd_off, uint32_t usbcmd) {
    const uint32_t i = (usbcmd_off >> 2) + 1;  /* USBSTS = USBCMD + 4 */
    uint32_t s = regs_[i];
    s = (usbcmd & kCmdAse) ? (s | kStsAss) : (s & ~kStsAss);
    s = (usbcmd & kCmdPse) ? (s | kStsPss) : (s & ~kStsPss);
    s = (usbcmd & kCmdRs)  ? (s & ~kStsHch) : (s | kStsHch);
    regs_[i] = s;
}

uint32_t Imx51Usboh3::UlpiTransfer(uint32_t core, uint32_t value) {
    if (value & kUlpiWu)      return value & ~kUlpiWu;
    if (!(value & kUlpiRun))  return value;
    auto& phy = phy_[core % kCores];
    const uint8_t addr = static_cast<uint8_t>(value >> 16) & (kPhyRegCount - 1);
    if (value & kUlpiRw) {
        phy[addr] = static_cast<uint8_t>(value);
        return value & ~kUlpiRun;
    }
    return (value & ~kUlpiRun & ~0xFF00u) | (static_cast<uint32_t>(phy[addr]) << 8);
}

uint32_t Imx51Usboh3::DqhBase() const {
    return regs_[kOffEndptlistaddr >> 2] & ~0x7FFu;
}

void Imx51Usboh3::DeliverSetup(const uint8_t setup[8]) {
    auto& mem = emu_.Get<EmulatedMemory>();
    const uint32_t base = DqhBase();
    if (!base || !mem.TryTranslate(base)) {
        LOG(Caution, "Imx51Usboh3: DeliverSetup with invalid ENDPTLISTADDR=0x%08X\n", base);
        return;
    }
    /* EP0-OUT dQH = index 0; the SETUP buffer is at dQH+0x28. */
    mem.CopyIn(base + kSetupBufOff, setup, 8);
    regs_[kOffEndptsetupstat >> 2] |= 1u;   /* EP0 setup received */
    regs_[kOffUsbsts >> 2] |= kStsUi;
    RefreshDeviceIrq();
}

void Imx51Usboh3::ExecutePrime(uint32_t prime_bits) {
    for (uint32_t ep = 0; ep < 16; ++ep) {
        if (prime_bits & (1u << ep))          ExecuteEndpoint(ep, false);  /* OUT */
        if (prime_bits & (1u << (16u + ep)))  ExecuteEndpoint(ep, true);   /* IN  */
    }
}

void Imx51Usboh3::ExecuteEndpoint(uint32_t ep, bool dir_in) {
    auto& mem = emu_.Get<EmulatedMemory>();
    const uint32_t base = DqhBase();
    if (!base || !mem.TryTranslate(base)) {
        LOG(Caution, "Imx51Usboh3: ENDPTPRIME ep%u %s but ENDPTLISTADDR=0x%08X invalid\n",
            ep, dir_in ? "IN" : "OUT", base);
        return;
    }
    const uint32_t dqh  = base + (ep * 2u + (dir_in ? 1u : 0u)) * kDqhStride;
    const uint32_t next = mem.ReadWord(dqh + kDqhOvNext);
    if (next & kDtdTerminate) return;            /* nothing primed */

    uint32_t dtd = next & ~0x1Fu;
    bool any = false;
    for (int guard = 0; guard < 64 && dtd; ++guard) {
        if (!mem.TryTranslate(dtd)) break;
        const uint32_t token = mem.ReadWord(dtd + kDtdToken);
        const uint32_t total = (token >> 16) & 0x7FFFu;

        uint32_t pages[5];
        for (int p = 0; p < 5; ++p) pages[p] = mem.ReadWord(dtd + kDtdBuf0 + p * 4u);

        uint32_t residual = total;
        if (dir_in) {
            /* device->host: gather the dTD's buffers, hand them to the host. */
            std::vector<uint8_t> data(total);
            TransferDtdBuffers(pages, data.data(), total, /*to_host=*/true);
            if (host_) host_->OnDeviceIn(ep, data.data(), static_cast<uint32_t>(data.size()));
            residual = 0;
        } else {
            /* host->device: ask the host for up to `total` bytes, scatter them. */
            std::vector<uint8_t> data(total);
            const uint32_t got = host_ ? host_->OnDeviceOut(ep, data.data(), total) : 0u;
            TransferDtdBuffers(pages, data.data(), got, /*to_host=*/false);
            residual = total - got;
        }

        /* Retire: clear Active + error/status, set the residual byte count. The
           dTD token (which SBOOT's dTD wrapper aliases) is what its sub_8005E540
           reads to detect completion (token & 0x80 == 0). */
        const uint32_t new_token = residual << 16;
        mem.WriteWord(dtd + kDtdToken, new_token);
        const uint32_t dtd_next = mem.ReadWord(dtd + kDtdNext);
        mem.WriteWord(dqh + kDqhOvCur, dtd);
        mem.WriteWord(dqh + kDqhOvNext, dtd_next);
        mem.WriteWord(dqh + kDqhOvToken, new_token);
        any = true;
        if (dtd_next & kDtdTerminate) break;
        dtd = dtd_next & ~0x1Fu;
    }

    if (any) {
        regs_[kOffEndptcomplete >> 2] |= dir_in ? (1u << (16u + ep)) : (1u << ep);
        regs_[kOffUsbsts >> 2] |= kStsUi;
        RefreshDeviceIrq();
    }
}

void Imx51Usboh3::TransferDtdBuffers(const uint32_t pages[5], uint8_t* host,
                                     uint32_t n, bool to_host) {
    /* EHCI/ChipIdea dTD buffer pages (RM Fig 60-90): page 0 carries the Current
       Offset in bits[11:0]; pages 1-4 reserve bits[11:0], so the byte stream
       continues at each page frame's boundary - mask the offset bits off pages
       1-4 (a non-zero low value there is reserved, not a data offset). */
    auto& mem = emu_.Get<EmulatedMemory>();
    uint32_t left = n, cursor = 0;
    for (int p = 0; p < 5 && left; ++p) {
        const uint32_t pa    = (p == 0) ? pages[0] : (pages[p] & ~0xFFFu);
        const uint32_t inpg  = (p == 0) ? (kPageSize - (pages[0] & 0xFFFu)) : kPageSize;
        const uint32_t chunk = inpg < left ? inpg : left;
        if (to_host) mem.CopyOut(pa, host + cursor, chunk);
        else         mem.CopyIn(pa, host + cursor, chunk);
        cursor += chunk;
        left   -= chunk;
    }
}
