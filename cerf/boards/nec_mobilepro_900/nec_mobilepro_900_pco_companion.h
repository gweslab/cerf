#pragma once

#include "../../core/service.h"
#include "../../peripherals/serial/serial_endpoint.h"

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <mutex>

/* NEC P530 "PCO" companion MCU (keyboard + touch). It has NO MMIO of its own: the
   in-ROM pco.dll talks to it over the PXA255 BTUART, so it sits behind that line as its
   endpoint. Report byte protocol RE'd from pco.dll sub_1BC28B4. */
class NecMobilePro900PcoCompanion : public Service, public SerialEndpoint {
public:
    using Service::Service;
    bool ShouldRegister() override;
    void OnReady() override;

    void OnGuestTx(const uint8_t* data, size_t n) override;

    /* Main-battery raw value the PCO returns for an IOCTL-0xE main read. The CE
       battery driver (battery.dll sub_1BC2368) writes 0x70 to BTUART THR and waits
       for a [0x70][hi][lo] reply over RX; battery.dll maps the 16-bit value through
       a voltage table. The board battery service computes this from the widget %. */
    void SetMainBatteryRaw(uint16_t raw) { main_battery_raw_.store(raw, std::memory_order_release); }
    uint16_t MainBatteryRaw() const { return main_battery_raw_.load(std::memory_order_acquire); }

    /* Cache the current key matrix so keybddr's on-demand 0x13 scan request
       (pco.dll sub_1BC2368(0x13)) can be answered from it. The PICO keyboard is
       request/reply (Linux pic-pxa2xx.c process_packets: the PIC replies to a 0x13
       request and NEVER streams the matrix), so the matrix is only cached here. */
    void SetKeyMatrix(const uint8_t matrix[13]);
    uint8_t KeyMatrixByte(size_t i);
    /* PIC_KEY_DOWN (0x12): one async byte sent on a host key-down edge. pco's parser
       (sub_1BC28B4) signals the key-down event dword_1BC40D8 -> keybddr's sub_1BD3578
       wakes its idle scan thread into the 5 ms poll. Matches Linux notify_key_down. */
    void NotifyKeyDown();

    /* Touch report: opcode 0x04 then 16-bit X, Y big-endian (pco sub_1BC28B4
       states 4-7); pco signals event.pco.touch and touch.dll calibrates. */
    void SendTouch(uint16_t x, uint16_t y);
    /* Pen-up: opcode 0x05 (pco clears its touch state, signals event.pco.touch). */
    void SendPenUp();

private:
    void PushByte(uint8_t b);
    void SendBatteryReply(uint16_t raw);
    /* Answers the request commands the guest writes to THR and then blocks on (pco.dll
       sub_1BC2368, 200ms). 0x70/0x71 battery, 0x13 keyboard scan; an unanswered request
       holds the PCO_IOControl critsec -> input freeze. */
    void OnBtuartTx(uint8_t b);

    std::mutex report_mtx_;   /* serializes a full report's bytes into the RX FIFO */
    std::atomic<uint16_t> main_battery_raw_{0};
    /* last matrix cached by SetKeyMatrix (guarded by report_mtx_); idle = all-set
       (active-low). Answers an on-demand 0x13 scan when the pacer isn't streaming. */
    uint8_t cur_matrix_[13] = {0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu,
                               0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu, 0xFFu};
};
