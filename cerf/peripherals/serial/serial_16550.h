#pragma once

#include "serial_line.h"

#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <vector>

class HostWidget;
class SerialEndpoint;

class StateWriter;
class StateReader;

class Serial16550 : public SerialLine {
public:
    /* Level-triggered IRQ out of the UART's INTR pin. true -> raise, false -> clear. */
    using IrqLineFn = std::function<void(bool asserted)>;

    struct Config {
        /* Writable IER bits. PC16550D §8.6.6: bits 7:4 "are always logic 0", and the
           VR4102 SIU agrees (SIUIE, UM 24.2.4 p464: D[7..4] reserved). The PXA255 does
           not - its IER carries DMAE/UUE/NRZE/RTOIE, "used differently from the standard
           16550 register definition" (PXA255 Dev Manual Table 10-7, p10-9). */
        uint8_t ier_mask = 0x0F;

        /* Board wiring: MCR bits that must be set for INTR to reach the controller. On a
           PC/AT-style card OUT2 drives the tri-state buffer onto the bus IRQ line; the
           part has no such gate (PC16550D §8.6.7 bit 3: OUT2 is "an auxiliary
           user-designated output"). 0 = the pin is wired straight through. */
        uint8_t irq_gate_mcr = 0;

        /* IER bits that must be set for the unit to interrupt at all. PXA255 UUE (IER.6,
           Table 10-7: "0 - The unit is disabled"). 0 = no unit gate. */
        uint8_t irq_gate_ier = 0;

        /* RCVR-FIFO trigger level per FCR bits 7:6. PC16550D §8.6.4 gives 1/4/8/14, and
           the VR4102 SIU matches it (SIUFC, UM 24.2.7 p469: 14/08/04 bytes; its "00
           Byte" entry is 1 - a zero-byte trigger would interrupt on an empty FIFO). The
           PXA255's 64-byte FIFOs use 1/8/16/32 (Table 10-11, FCR[ITL], p10-12). */
        uint8_t rx_trigger[4] = {1, 4, 8, 14};

        /* IER bit enabling the character-timeout interrupt: the RDA bit itself on the
           PC16550D (§8.6.6 bit 0 "and timeout interrupts in the FIFO mode") and on the
           VR4102 SIU (SIUIE IE[0], UM 24.2.4), but a separate RTOIE on the PXA255
           (IER.4, Table 10-7). */
        uint8_t cti_ier_bit = 0x01;
    };

    Serial16550(SerialEndpoint* endpoint, IrqLineFn irq_line, Config cfg);

    uint8_t ReadReg8 (uint32_t offset);
    void SaveState(StateWriter& w) const;
    void RestoreState(StateReader& r);
    void    WriteReg8(uint32_t offset, uint8_t value);

    /* Personality -> RX. Any thread. Asserts the RX interrupt per IER/trigger. */
    void PushRx(const uint8_t* data, size_t n) override;

    /* True once the guest has read every queued RX byte. */
    bool RxEmpty() const override;

    /* Fired off-lock when a guest read empties the RX queue, so a flow-
       controlled feeder can push the next frame. */
    void SetRxDrainCallback(RxDrainFn cb) override;

    /* Personality -> modem inputs (CTS/DSR/RI/DCD line levels). Any thread; a
       changed level sets the matching MSR delta bit and (per IER.MS) an IRQ. */
    void SetModemInputs(bool cts, bool dsr, bool ri, bool dcd) override;

    uint32_t BaudRate() const;   /* derived from the divisor latch + 115200 base */

    LineConfig GetLineConfig() const override;

    /* Fired off-lock when the guest changes baud (DLL/DLM under DLAB) or the LCR
       framing, so a host-port forwarder can re-apply SetCommState live. */
    void SetLineConfigCallback(LineConfigFn cb) override;

    void SetEndpoint(SerialEndpoint* endpoint) override;

    /* Status-bar widget the port's traffic lights up: the owning UART's SerialCradle,
       or a card's PcmciaSlot. Set once by the owner before any traffic flows. */
    void SetActivityWidget(HostWidget* w) { activity_ = w; }

    void Reset();
    void ResetRegisters();
    void ResendEndpointInputs();

    /* Re-drive the INTR line from restored register state. Call only once every
       peripheral is restored: an edge-latching INTC whose own registers are not back yet
       latches or loses the transition. */
    void RepublishIrq();

protected:
    /* One guest TX byte leaving THR. The default hands it to the attached personality;
       an on-SoC UART overrides this to reach its debug sink when none is attached.
       Called off-lock. Returns false when no personality took the byte. */
    virtual void DeliverTx(uint8_t byte);
    bool         DeliverTxToEndpoint(uint8_t byte);

private:
    size_t     RxTriggerLocked() const;
    uint8_t    PendingSourceLocked() const;
    bool       ComputeIrqLevelLocked() const;
    uint8_t    ReadIirLocked();           /* reading IIR clears the THRE source */
    void       SettleAndFireIrq();        /* recompute level, call irq_line_ off-lock */
    LineConfig GetLineConfigLocked() const;

    IrqLineFn       irq_line_;
    Config          cfg_;
    HostWidget*     activity_ = nullptr;

    /* A cradle swaps the personality from the UI thread while the JIT thread is inside
       DeliverTx / OnControlLines, so the pointer and the callbacks it installs are held
       under their own lock. Recursive: an endpoint may re-enter the line (PushRx) from
       inside a callback made under it. Order: endpoint_mu_ before mu_. */
    mutable std::recursive_mutex endpoint_mu_;
    SerialEndpoint*              endpoint_;
    RxDrainFn                    rx_drain_;
    LineConfigFn                 line_cfg_cb_;

    mutable std::mutex mu_;

    uint8_t ier_ = 0;
    uint8_t fcr_ = 0;
    uint8_t lcr_ = 0;
    uint8_t mcr_ = 0;
    uint8_t lsr_ = 0;        /* error/break bits; THRE/TEMT/DR derived on read */
    uint8_t msr_ = 0;
    uint8_t scr_ = 0;
    uint8_t dll_ = 0, dlm_ = 0;

    bool thre_armed_ = false;   /* THRE interrupt pending until next IIR read     */

    /* The visible FIFO is the head of an unbounded queue (bytes still "on the wire"),
       so a fast personality never overruns the receiver. */
    std::vector<uint8_t> rx_;
    size_t rx_pos_ = 0;
    size_t RxAvailLocked() const { return rx_.size() - rx_pos_; }

    bool last_irq_level_ = false;
};
