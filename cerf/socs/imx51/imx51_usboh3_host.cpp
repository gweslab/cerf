#include "imx51_usboh3.h"

#include "../../core/cerf_emulator.h"
#include "../../cpu/emulated_memory.h"
#include "../../peripherals/usb/usb_device.h"
#include "../irq_controller.h"

namespace {

constexpr uint32_t kOffUsbcmdRel  = 0x00000140u;
constexpr uint32_t kOffUsbstsRel  = 0x00000144u;
constexpr uint32_t kOffFrindexRel = 0x0000014Cu;
constexpr uint32_t kOffPeriodicListBaseRel = 0x00000154u;
constexpr uint32_t kOffAsyncListRel = 0x00000158u;
constexpr uint32_t kOffPortscRel  = 0x00000184u;
/* EHCI 1.0 Spec Table 2-12 (p23): FRINDEX is a 14-bit field, bits[13:0]. */
constexpr uint32_t kFrindexMask = 0x00003FFFu;
/* EHCI 1.0 Spec 2.3.4 (p23): with the default (non-programmable-length)
   1024-element frame list, N=12, so the current entry is FRINDEX[12:3]. */
constexpr uint32_t kFrameListIndexMask = 0x000003FFu;
constexpr uint32_t kCmdPseLocal = 1u << 4;
constexpr uint32_t kStsUiLocal  = 1u << 0;
constexpr uint32_t kStsUeiLocal = 1u << 1;
/* EHCI 1.0 Spec Table 2-10 (p22): USBSTS bit 2, Port Change Detect. */
constexpr uint32_t kStsPciLocal = 1u << 2;

/* EHCI 1.0 Spec Table 2-16 (p26-29): PORTSC bit layout. */
constexpr uint32_t kPortscCcs     = 1u << 0;
constexpr uint32_t kPortscCsc     = 1u << 1;
constexpr uint32_t kPortscPed     = 1u << 2;
constexpr uint32_t kPortscPedc    = 1u << 3;
constexpr uint32_t kPortscFpr     = 1u << 6;
constexpr uint32_t kPortscSuspend = 1u << 7;
constexpr uint32_t kPortscPr      = 1u << 8;
/* MCIMX51RM Table 60-52 (PORTSCx Field Descriptions): PHCD, bit 23. */
constexpr uint32_t kPortscPhcd    = 1u << 23;

/* EHCI 1.0 Spec Figure 3-7 (p46): Queue Head Structure Layout. */
constexpr uint32_t kQhEpCharOff       = 0x04u;
constexpr uint32_t kQhCurQtdOff       = 0x0Cu;
constexpr uint32_t kQhOverlayNextOff  = 0x10u;
constexpr uint32_t kQhOverlayTokenOff = 0x18u;
constexpr uint32_t kQhHorizLinkOff    = 0x00u;
constexpr uint32_t kQhTypMask  = 0x6u;
constexpr uint32_t kQhTypQh    = 0x2u;

/* EHCI 1.0 Spec Table 3-14/3-16 (p40-43): qTD structure and Token fields. */
constexpr uint32_t kQtdNextOff = 0x00u;
constexpr uint32_t kQtdTokenOff = 0x08u;
constexpr uint32_t kQtdBuf0Off  = 0x0Cu;
constexpr uint32_t kQtdTerminate = 1u;
constexpr uint32_t kQtdActive   = 0x80u;
constexpr uint32_t kQtdHalted   = 1u << 6;
constexpr uint32_t kQtdDataBufferError = 1u << 5;
constexpr uint32_t kQtdIoc      = 1u << 15;
constexpr uint32_t kQtdPidShift = 8u;
constexpr uint32_t kQtdPidMask  = 0x3u;
constexpr uint32_t kQtdPidOut   = 0u;
constexpr uint32_t kQtdPidIn    = 1u;
constexpr uint32_t kQtdPidSetup = 2u;
constexpr uint32_t kQtdTotalBytesShift = 16u;
constexpr uint32_t kQtdTotalBytesMask  = 0x7FFFu;
constexpr uint32_t kPageSizeLocal = 0x1000u;
constexpr int       kQtdChainGuard = 32;
constexpr int       kQhRingGuard   = 16;

/* EHCI 1.0 Spec Table 3-19 (p47): Endpoint Characteristics, QH DWord 1. */
uint32_t QhDeviceAddress(uint32_t ep_char) { return ep_char & 0x7Fu; }
uint32_t QhEndpointNumber(uint32_t ep_char) { return (ep_char >> 8) & 0xFu; }

}

void Imx51Usboh3::OnPortConnectChanged(int port_index) {
    if (port_index != 0) return;
    /* EHCI 1.0 Table 2-16: CCS reflects the powered port, independently of RS. */
    const uint32_t idx = kOffPortscRel >> 2;
    if (otg_host_root_port_.IsConnected()) {
        regs_[idx] |= kPortscCcs | kPortscCsc;
    } else {
        regs_[idx] &= ~(kPortscCcs | kPortscPed | kPortscSuspend | kPortscPhcd);
        regs_[idx] |= kPortscCsc;
    }
    regs_[kOffUsbstsRel >> 2] |= kStsPciLocal;
    RefreshDeviceIrq();
    UpdateScheduleTimer();
}

void Imx51Usboh3::WriteOtgHostPortsc(uint32_t value) {
    const uint32_t idx = kOffPortscRel >> 2;
    const uint32_t old = regs_[idx];
    uint32_t next = old;

    if ((value & kPortscPr) && !(old & kPortscPr)) {
        /* MCIMX51RM 60.4.5.5.2 Discovery/Port Reset (p60-219): PORTSCx
           auto-completes reset via its own 10ms counter and reports it via
           a Port Enable Change interrupt; software never writes PR back. */
        next &= ~kPortscPr;
        if (old & kPortscCcs) {
            next |= kPortscPed | kPortscPedc;
            regs_[kOffUsbstsRel >> 2] |= kStsPciLocal;
            if (UsbDevice* dev = otg_host_root_port_.Device()) dev->ResetToDefault();
        }
    }

    if (value & kPortscCsc)  next &= ~kPortscCsc;
    if (value & kPortscPedc) next &= ~kPortscPedc;

    if (value & kPortscSuspend) next |= kPortscSuspend;
    /* MCIMX51RM Table 60-52, FPR: host resume auto-completes; a write of zero
       has no effect, unlike EHCI. */
    if (value & kPortscFpr) {
        next &= ~(kPortscFpr | kPortscSuspend);
    }

    if (value & kPortscPhcd) next |= kPortscPhcd;
    else                     next &= ~kPortscPhcd;

    regs_[idx] = next;
    RefreshDeviceIrq();
}

void Imx51Usboh3::ExecuteAsyncSchedule() {
    const uint32_t cmd = regs_[kOffUsbcmdRel >> 2];
    constexpr uint32_t kCmdRsLocal  = 1u << 0;
    constexpr uint32_t kCmdAseLocal = 1u << 5;
    if (!(cmd & kCmdRsLocal)) return;

    if (!(cmd & kCmdAseLocal)) return;
    const uint32_t start = regs_[kOffAsyncListRel >> 2] & ~0x1Fu;
    if (start == 0u) return;

    auto& mem = emu_.Get<EmulatedMemory>();
    uint32_t qh = start;
    for (int i = 0; i < kQhRingGuard; ++i) {
        if (!mem.TryTranslate(qh)) break;
        ExecuteQueueHead(qh);
        const uint32_t link = mem.ReadWord(qh + kQhHorizLinkOff);
        if (link & kQtdTerminate) break;
        if ((link & kQhTypMask) != kQhTypQh) break;
        const uint32_t next_qh = link & ~0x1Fu;
        if (next_qh == start) break;
        qh = next_qh;
    }
}

void Imx51Usboh3::ExecutePeriodicSchedule() {
    const uint32_t cmd = regs_[kOffUsbcmdRel >> 2];
    if (!(cmd & 1u) || !(cmd & kCmdPseLocal)) return;

    const uint32_t base = regs_[kOffPeriodicListBaseRel >> 2] & ~0xFFFu;
    if (base == 0u) return;

    const uint32_t frindex = (regs_[kOffFrindexRel >> 2] + 8u) & kFrindexMask;
    regs_[kOffFrindexRel >> 2] = frindex;
    const uint32_t index = (frindex >> 3) & kFrameListIndexMask;

    auto& mem = emu_.Get<EmulatedMemory>();
    uint32_t link = mem.ReadWord(base + index * 4u);
    for (int i = 0; i < kQhRingGuard && !(link & kQtdTerminate); ++i) {
        if ((link & kQhTypMask) != kQhTypQh) break;
        const uint32_t qh = link & ~0x1Fu;
        if (!mem.TryTranslate(qh)) break;
        ExecuteQueueHead(qh);
        link = mem.ReadWord(qh + kQhHorizLinkOff);
    }
}

void Imx51Usboh3::ExecuteQueueHead(uint32_t qh_addr) {
    auto& mem = emu_.Get<EmulatedMemory>();
    /* EHCI 1.0 Figure 4-14: a halted queue advances horizontally. */
    if (mem.ReadWord(qh_addr + kQhOverlayTokenOff) & kQtdHalted) return;
    const uint32_t ep_char = mem.ReadWord(qh_addr + kQhEpCharOff);
    const uint32_t dev_addr = QhDeviceAddress(ep_char);
    const uint32_t endpt    = QhEndpointNumber(ep_char);

    UsbDevice* root = otg_host_root_port_.Device();
    UsbDevice* dev  = root ? root->FindByAddress(static_cast<uint8_t>(dev_addr)) : nullptr;
    if (!dev) return;

    uint32_t next_ptr = mem.ReadWord(qh_addr + kQhOverlayNextOff);
    uint32_t interrupts = 0;
    for (int i = 0; i < kQtdChainGuard && !(next_ptr & kQtdTerminate); ++i) {
        const uint32_t qtd_addr = next_ptr & ~0x1Fu;
        if (!mem.TryTranslate(qtd_addr)) break;
        const uint32_t token = mem.ReadWord(qtd_addr + kQtdTokenOff);
        if (!(token & kQtdActive)) break;

        const bool retired = ExecuteQtd(qtd_addr, dev, endpt);
        if (!retired) break;
        const uint32_t new_token = mem.ReadWord(qtd_addr + kQtdTokenOff);
        const bool halted = (new_token & kQtdHalted) != 0;
        const bool short_packet = !halted &&
            ((token >> kQtdPidShift) & kQtdPidMask) == kQtdPidIn &&
            ((new_token >> kQtdTotalBytesShift) & kQtdTotalBytesMask) != 0;
        /* EHCI 1.0 Table 2-10 and Table 3-15. */
        if (halted) interrupts |= kStsUeiLocal;
        if ((token & kQtdIoc) || short_packet) interrupts |= kStsUiLocal;
        const uint32_t this_next = mem.ReadWord(qtd_addr + (short_packet ? 4u : kQtdNextOff));
        mem.WriteWord(qh_addr + kQhCurQtdOff, qtd_addr);
        mem.WriteWord(qh_addr + kQhOverlayNextOff, this_next);
        mem.WriteWord(qh_addr + kQhOverlayTokenOff, new_token);
        if (halted) break;
        next_ptr = this_next;
    }

    if (interrupts) {
        regs_[kOffUsbstsRel >> 2] |= interrupts;
        RefreshDeviceIrq();
    }
}

bool Imx51Usboh3::ExecuteQtd(uint32_t qtd_addr, UsbDevice* dev, uint32_t endpt) {
    auto& mem = emu_.Get<EmulatedMemory>();
    const uint32_t token = mem.ReadWord(qtd_addr + kQtdTokenOff);
    const uint32_t pid   = (token >> kQtdPidShift) & kQtdPidMask;
    const uint32_t total = (token >> kQtdTotalBytesShift) & kQtdTotalBytesMask;
    /* EHCI 1.0 Table 3-16: preserve token controls; STALL halts without consuming data. */
    auto retire = [&](uint32_t residual, bool halted, uint32_t error = 0u) {
        const auto next = (token & ~(kQtdActive | (kQtdTotalBytesMask << kQtdTotalBytesShift))) |
            (residual << kQtdTotalBytesShift) | (halted ? kQtdHalted : 0u) | error;
        mem.WriteWord(qtd_addr + kQtdTokenOff, next);
        return true;
    };
    if (pid != kQtdPidSetup && dev->IsEndpointStalled(static_cast<uint8_t>(endpt)))
        return retire(total, true);

    uint32_t pages[5];
    for (int p = 0; p < 5; ++p) pages[p] = mem.ReadWord(qtd_addr + kQtdBuf0Off + p * 4u);

    /* EHCI 1.0 Table 3-17 and 4.10.6: page-zero low bits offset C_Page. */
    const uint32_t current_page = (token >> 12) & 7u;
    const uint32_t offset = pages[0] & (kPageSizeLocal - 1u);
    if (current_page >= 5 || total > (5u - current_page) * kPageSizeLocal - offset) {
        LOG(Caution, "USB: invalid qTD buffer span qtd=%08X page=%u offset=%u bytes=%u\n",
            qtd_addr, current_page, offset, total);
        return retire(total, true, kQtdDataBufferError);
    }
    auto transfer = [&](uint8_t* data, uint32_t n, bool to_guest) {
        uint32_t left = n, cursor = 0u;
        for (uint32_t p = current_page; p < 5 && left; ++p) {
            const uint32_t start = p == current_page ? offset : 0u;
            const uint32_t pa = (pages[p] & ~(kPageSizeLocal - 1u)) + start;
            const uint32_t inpg = kPageSizeLocal - start;
            const uint32_t chunk = inpg < left ? inpg : left;
            if (to_guest) mem.CopyIn(pa, data + cursor, chunk);
            else mem.CopyOut(pa, data + cursor, chunk);
            cursor += chunk;
            left   -= chunk;
        }
    };

    uint32_t residual = 0u;

    if (endpt == 0u && pid == kQtdPidSetup) {
        if (total != 8u) return retire(total, true);
        uint8_t raw[8] = {};
        transfer(raw, 8u, false);
        UsbDevice::SetupPacket setup{};
        setup.bmRequestType = raw[0];
        setup.bRequest      = raw[1];
        setup.wValue        = static_cast<uint16_t>(raw[2] | (raw[3] << 8));
        setup.wIndex        = static_cast<uint16_t>(raw[4] | (raw[5] << 8));
        setup.wLength        = static_cast<uint16_t>(raw[6] | (raw[7] << 8));
        if (!dev->BeginControlTransfer(setup)) return retire(total, true);
        residual = 0u;
    } else if (endpt == 0u && pid == kQtdPidIn) {
        std::vector<uint8_t> data(total);
        const uint32_t n = dev->ReadControlReply(data.data(), total);
        if (n > 0u) transfer(data.data(), n, true);
        residual = total - n;
    } else if (endpt == 0u && pid == kQtdPidOut) {
        if (total != 0u) {
            LOG(Caution, "USB: unsupported control OUT data length=%u\n", total);
            return retire(total, true);
        }
        dev->FinishControlTransfer();
        residual = 0u;
    } else if (pid == kQtdPidOut) {
        std::vector<uint8_t> data(total);
        transfer(data.data(), total, false);
        dev->OnBulkOut(static_cast<uint8_t>(endpt), data.data(), total);
        if (dev->IsEndpointStalled(static_cast<uint8_t>(endpt))) return retire(total, true);
        residual = 0u;
    } else if (pid == kQtdPidIn) {
        std::vector<uint8_t> data(total);
        const uint32_t got = dev->OnBulkIn(static_cast<uint8_t>(endpt), data.data(), total);
        if (got == UsbDevice::kNak) return false;
        if (got > 0u) transfer(data.data(), got, true);
        residual = total - got;
    } else {
        return retire(total, true);
    }

    return retire(residual, false);
}
