#pragma once

#include "../../peripherals/peripheral_base.h"
#include "../../peripherals/usb/usb_host_port.h"
#include "../../jit/guest_cycle_clock.h"
#include "../freescale_usb_frame_index.h"

#include <array>
#include <cstdint>
#include <mutex>
#include <vector>

class Imx51UsbDeviceTransfers;
class Imx51UsbTransceiverClocks;
class UsbDeviceHost;
enum class FreescaleLowPowerMode : uint8_t;

/* i.MX51 USBOH3 (MCIMX51RM Ch 60, base 0x73F80000): OAL PHY config block plus
   the four ChipIdea/EHCI cores. Core 0 (OTG) runs in device mode for the SBOOT
   flasher; CERF is the always-present host and drives the device controller's
   dQH/dTD engine through a registered UsbDeviceHost. */
class Imx51Usboh3 : public Peripheral, public UsbHostPortHost {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override;
    void OnReady() override;

    uint32_t MmioBase() const override;
    uint32_t MmioSize() const override;

    uint8_t  ReadByte(uint32_t addr) override;
    uint16_t ReadHalf(uint32_t addr) override;
    uint32_t ReadWord(uint32_t addr) override;
    void     WriteWord(uint32_t addr, uint32_t value) override;

    void SaveState(StateWriter& w) override;
    void RestoreState(StateReader& r) override;
    void PostRestore() override;

    void RegisterDeviceHost(UsbDeviceHost* host);

    /* Host->device EP0 control SETUP: write the 8-byte packet into the EP0-OUT
       dQH set-up buffer and raise the setup interrupt. */
    void DeliverSetup(const uint8_t setup[8]);

    UsbHostPort& OtgHostRootPort() { return otg_host_root_port_; }
    std::unique_lock<std::mutex> LockHostPort() { return std::unique_lock(async_schedule_mtx_); }

    void OnPortConnectChanged(int port_index) override;

private:
    static constexpr uint32_t kSize        = 0x00004000u;   /* AIPS 16 KB slot */
    static constexpr uint32_t kCoreSpan    = 0x00000200u;   /* per-core EHCI block */
    static constexpr uint32_t kNonCore     = 0x00000800u;   /* control block start */
    static constexpr uint32_t kCores       = kNonCore / kCoreSpan;
    static constexpr uint8_t  kPhyRegCount = 0x40u;

    void     ResetController();
    void     RefreshTransceiverClocks(FreescaleLowPowerMode mode);
    bool     Core0IsDevice() const;
    uint32_t ReadLocked(uint32_t off);
    void     WriteCoreFrameReg(uint32_t off, uint32_t value);
    void     RefreshDeviceIrq();
    void     ArmFrameIrq();
    void     OnFrameIrqEvent();
    void     ReflectScheduleStatus(uint32_t usbcmd_off, uint32_t usbcmd);
    uint32_t UlpiTransfer(uint32_t core, uint32_t value);

    uint32_t DqhBase() const;
    void     ExecutePrime(uint32_t prime_bits);

    void WriteOtgHostPortsc(uint32_t value);
    void ExecuteAsyncSchedule();
    void ExecutePeriodicSchedule();
    void ExecuteQueueHead(uint32_t qh_addr);
    bool ExecuteQtd(uint32_t qtd_addr, UsbDevice* dev, uint32_t endpt);
    void UpdateScheduleTimer();
    void OnScheduleTimer();
    void OnCpuRateChanged();
    void ArmNextFrame();

    Imx51UsbDeviceTransfers*   transfers_ = nullptr;
    Imx51UsbTransceiverClocks* transceiver_clocks_ = nullptr;
    bool                       reset_seen_ = false;

    UsbHostPort otg_host_root_port_{*this, 0};

    std::array<uint32_t, kSize / 4> regs_{};
    std::array<std::array<uint8_t, kPhyRegCount>, kCores> phy_{};

    std::mutex              async_schedule_mtx_;
    GuestCycleClock*        clock_ = nullptr;
    GuestCycleClock::Event* frame_event_ = nullptr;
    GuestCycleClock::Event* irq_event_   = nullptr;
    FreescaleUsbFrameIndex  frame_index_{emu_};
    bool                    frames_running_ = false;
};
