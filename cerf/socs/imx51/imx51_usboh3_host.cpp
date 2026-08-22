#include "imx51_usboh3.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../cpu/emulated_memory.h"
#include "../../jit/guest_engine.h"
#include "../../peripherals/usb/usb_device.h"
#include "../irq_controller.h"

namespace {

constexpr uint32_t kOffUsbcmdRel  = 0x00000140u;
constexpr uint32_t kOffUsbstsRel  = 0x00000144u;
constexpr uint32_t kOffAsyncListRel = 0x00000158u;
constexpr uint32_t kOffPortscRel  = 0x00000184u;
constexpr uint32_t kStsUiLocal  = 1u << 0;
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
    if (!host_port_reported_) return;
    const uint32_t idx = kOffPortscRel >> 2;
    if (otg_host_root_port_.IsConnected()) {
        regs_[idx] |= kPortscCcs | kPortscCsc;
    } else {
        regs_[idx] &= ~(kPortscCcs | kPortscPed);
        regs_[idx] |= kPortscCsc;
    }
    regs_[kOffUsbstsRel >> 2] |= kStsPciLocal;
    RefreshDeviceIrq();
}

void Imx51Usboh3::WriteOtgHostPortsc(uint32_t value) {
    LOG(Caution, "[PORTSC_CALLER] guest_pc=%08X value=%08X\n",
        emu_.Get<GuestEngine>().Pc(), value);

    const uint32_t idx = kOffPortscRel >> 2;
    const uint32_t old = regs_[idx];
    uint32_t next = old;

    if ((value & kPortscPr) && !(old & kPortscPr)) {
        next |= kPortscPr;
        next &= ~kPortscPed;
    } else if (!(value & kPortscPr) && (old & kPortscPr)) {
        next &= ~kPortscPr;
        if (old & kPortscCcs) next |= kPortscPed;
    }

    if (value & kPortscCsc)  next &= ~kPortscCsc;
    if (value & kPortscPedc) next &= ~kPortscPedc;

    if (value & kPortscSuspend) next |= kPortscSuspend;
    if ((value & kPortscFpr) && !(old & kPortscFpr)) {
        next |= kPortscFpr;
    } else if (!(value & kPortscFpr) && (old & kPortscFpr)) {
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
    if (!(cmd & kCmdRsLocal) || !(cmd & kCmdAseLocal)) return;

    if (!host_port_reported_) {
        host_port_reported_ = true;
        if (otg_host_root_port_.IsConnected()) {
            regs_[kOffPortscRel >> 2] |= kPortscCcs | kPortscCsc;
            regs_[kOffUsbstsRel >> 2] |= kStsPciLocal;
            RefreshDeviceIrq();
        }
    }

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

void Imx51Usboh3::ExecuteQueueHead(uint32_t qh_addr) {
    auto& mem = emu_.Get<EmulatedMemory>();
    const uint32_t ep_char = mem.ReadWord(qh_addr + kQhEpCharOff);
    const uint32_t dev_addr = QhDeviceAddress(ep_char);
    const uint32_t endpt    = QhEndpointNumber(ep_char);

    UsbDevice* root = otg_host_root_port_.Device();
    UsbDevice* dev  = root ? root->FindByAddress(static_cast<uint8_t>(dev_addr)) : nullptr;
    if (!dev) return;

    if (endpt == 0u) {
        ctrl_reply_.clear();
        ctrl_reply_off_ = 0u;
    }

    uint32_t next_ptr = mem.ReadWord(qh_addr + kQhOverlayNextOff);
    bool any = false;
    for (int i = 0; i < kQtdChainGuard && !(next_ptr & kQtdTerminate); ++i) {
        const uint32_t qtd_addr = next_ptr & ~0x1Fu;
        if (!mem.TryTranslate(qtd_addr)) break;
        const uint32_t token = mem.ReadWord(qtd_addr + kQtdTokenOff);
        if (!(token & kQtdActive)) break;

        const bool retired = ExecuteQtd(qtd_addr, dev, endpt);
        any = any || retired;

        const uint32_t new_token = mem.ReadWord(qtd_addr + kQtdTokenOff);
        const uint32_t this_next = mem.ReadWord(qtd_addr + kQtdNextOff);
        mem.WriteWord(qh_addr + kQhCurQtdOff, qtd_addr);
        mem.WriteWord(qh_addr + kQhOverlayNextOff, this_next);
        mem.WriteWord(qh_addr + kQhOverlayTokenOff, new_token);
        next_ptr = this_next;
    }

    if (any) {
        regs_[kOffUsbstsRel >> 2] |= kStsUiLocal;
        RefreshDeviceIrq();
    }
}

bool Imx51Usboh3::ExecuteQtd(uint32_t qtd_addr, UsbDevice* dev, uint32_t endpt) {
    auto& mem = emu_.Get<EmulatedMemory>();
    const uint32_t token = mem.ReadWord(qtd_addr + kQtdTokenOff);
    const uint32_t pid   = (token >> kQtdPidShift) & kQtdPidMask;
    const uint32_t total = (token >> kQtdTotalBytesShift) & kQtdTotalBytesMask;

    uint32_t pages[5];
    for (int p = 0; p < 5; ++p) pages[p] = mem.ReadWord(qtd_addr + kQtdBuf0Off + p * 4u);

    auto scatter = [&](const uint8_t* src, uint32_t n) {
        uint32_t left = n, cursor = 0u;
        for (int p = 0; p < 5 && left; ++p) {
            const uint32_t pa   = (p == 0) ? pages[0] : (pages[p] & ~0xFFFu);
            const uint32_t inpg = (p == 0) ? (kPageSizeLocal - (pages[0] & 0xFFFu)) : kPageSizeLocal;
            const uint32_t chunk = inpg < left ? inpg : left;
            mem.CopyIn(pa, src + cursor, chunk);
            cursor += chunk;
            left   -= chunk;
        }
    };
    auto gather = [&](uint8_t* dst, uint32_t n) {
        uint32_t left = n, cursor = 0u;
        for (int p = 0; p < 5 && left; ++p) {
            const uint32_t pa   = (p == 0) ? pages[0] : (pages[p] & ~0xFFFu);
            const uint32_t inpg = (p == 0) ? (kPageSizeLocal - (pages[0] & 0xFFFu)) : kPageSizeLocal;
            const uint32_t chunk = inpg < left ? inpg : left;
            mem.CopyOut(pa, dst + cursor, chunk);
            cursor += chunk;
            left   -= chunk;
        }
    };

    uint32_t residual = 0u;

    if (endpt == 0u && pid == kQtdPidSetup) {
        uint8_t raw[8] = {};
        gather(raw, 8u);
        UsbDevice::SetupPacket setup{};
        setup.bmRequestType = raw[0];
        setup.bRequest      = raw[1];
        setup.wValue        = static_cast<uint16_t>(raw[2] | (raw[3] << 8));
        setup.wIndex        = static_cast<uint16_t>(raw[4] | (raw[5] << 8));
        setup.wLength        = static_cast<uint16_t>(raw[6] | (raw[7] << 8));
        dev->HandleSetup(setup, ctrl_reply_);
        ctrl_reply_off_ = 0u;
        residual = 0u;
    } else if (endpt == 0u && pid == kQtdPidIn) {
        const uint32_t remain = static_cast<uint32_t>(ctrl_reply_.size() - ctrl_reply_off_);
        const uint32_t n = remain < total ? remain : total;
        if (n > 0u) scatter(ctrl_reply_.data() + ctrl_reply_off_, n);
        ctrl_reply_off_ += n;
        residual = total - n;
    } else if (endpt == 0u && pid == kQtdPidOut) {
        residual = 0u;
    } else if (pid == kQtdPidOut) {
        std::vector<uint8_t> data(total);
        gather(data.data(), total);
        dev->OnBulkOut(static_cast<uint8_t>(endpt), data.data(), total);
        residual = 0u;
    } else if (pid == kQtdPidIn) {
        std::vector<uint8_t> data(total);
        const uint32_t got = dev->OnBulkIn(static_cast<uint8_t>(endpt), data.data(), total);
        if (got > 0u) scatter(data.data(), got);
        residual = total - got;
    }

    mem.WriteWord(qtd_addr + kQtdTokenOff, residual << kQtdTotalBytesShift);
    return true;
}
