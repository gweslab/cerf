#include "pxa27x_keypad.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../irq_controller.h"

#include <mutex>

namespace {
/* Intel PXA27x Developer's Manual 280000-001 Table 18-3. */
constexpr uint32_t kKpcAs        = 1u << 30;
constexpr uint32_t kKpcAsact     = 1u << 29;
constexpr uint32_t kKpcMi        = 1u << 22;
constexpr uint32_t kKpcImkp      = 1u << 21;
constexpr uint32_t kKpcMsShift   = 13u;
constexpr uint32_t kKpcMsMask    = 0xFFu << kKpcMsShift;
constexpr uint32_t kKpcMe        = 1u << 12;
constexpr uint32_t kKpcMie       = 1u << 11;
constexpr uint32_t kKpcDi        = 1u << 5;

/* Intel PXA27x Developer's Manual 280000-001 Table 18-6. */
constexpr uint32_t kKpmkMkp      = 1u << 31;

/* Intel PXA27x Developer's Manual 280000-001 Table 18-7. */
constexpr uint32_t kKpasMukpShift = 26u;
constexpr uint32_t kKpasRpShift   = 4u;
constexpr uint32_t kKpasInvalid   = 0x000000FFu;

/* Intel PXA27x Developer's Manual 280000-001 Table 18-5. */
constexpr uint32_t kKprecOf1     = 1u << 31;
constexpr uint32_t kKprecUf1     = 1u << 30;
constexpr uint32_t kKprecOf0     = 1u << 15;
constexpr uint32_t kKprecUf0     = 1u << 14;

/* Intel PXA27x Developer's Manual 280000-001 Table 25-2: IP[4] keypad
   controller interrupt. */
constexpr int kIntcKeypadBit = 4;
}

bool Pxa27xKeypad::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSoc() == SocFamily::PXA27x;
}

void Pxa27xKeypad::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
}

bool Pxa27xKeypad::IsKnown(uint32_t off) {
    return off == kKpc   || off == kKpdk     || off == kKprec    || off == kKpmk ||
           off == kKpas  || off == kKpasmkp0 || off == kKpasmkp1 ||
           off == kKpasmkp2 || off == kKpasmkp3 || off == kKpkdi;
}

uint32_t Pxa27xKeypad::SenseRowsLocked() const {
    uint32_t rows = 0;
    const uint32_t ms = (kpc_ & kKpcMsMask) >> kKpcMsShift;
    for (uint32_t col = 0; col < 8u; ++col) {
        if (ms & (1u << col)) rows |= matrix_col_rows_[col];
    }
    return rows & 0xFFu;
}

void Pxa27xKeypad::RunAutomaticScanLocked() {
    uint32_t pressed = 0;
    for (uint32_t col = 0; col < 8u; ++col) {
        uint8_t r = matrix_col_rows_[col];
        while (r) { r &= (uint8_t)(r - 1u); ++pressed; }
    }

    for (uint32_t i = 0; i < 4u; ++i) {
        const uint32_t even = matrix_col_rows_[i * 2u];
        const uint32_t odd  = matrix_col_rows_[i * 2u + 1u];
        kpasmkp_[i] = (odd << 16) | even;
    }

    if (pressed == 0) {
        kpas_ = kKpasInvalid;
        return;
    }
    if (pressed > 1u) {
        const uint32_t mukp = (pressed > 0x1Fu) ? 0x1Fu : pressed;
        kpas_ = (mukp << kKpasMukpShift) | kKpasInvalid;
        return;
    }
    for (uint32_t col = 0; col < 8u; ++col) {
        if (!matrix_col_rows_[col]) continue;
        uint32_t row = 0;
        while (!(matrix_col_rows_[col] & (1u << row))) ++row;
        kpas_ = (1u << kKpasMukpShift) | (row << kKpasRpShift) | col;
        return;
    }
}

bool Pxa27xKeypad::MatrixIrqPendingLocked() const {
    return mi_ && (kpc_ & kKpcMie) != 0;
}

void Pxa27xKeypad::PublishIrq(bool pending) {
    auto& intc = emu_.Get<IrqController>();
    if (pending) intc.AssertIrq(kIntcKeypadBit);
    else         intc.DeAssertIrq(kIntcKeypadBit);
}

void Pxa27xKeypad::SetMatrixKey(uint32_t row, uint32_t col, bool pressed) {
    if (row >= 8u || col >= 8u) return;
    bool irq;
    {
        std::lock_guard<std::mutex> lk(state_mtx_);
        const uint8_t bit = (uint8_t)(1u << row);
        const uint8_t before = matrix_col_rows_[col];
        matrix_col_rows_[col] = pressed ? (uint8_t)(before | bit)
                                       : (uint8_t)(before & ~bit);
        if (matrix_col_rows_[col] == before) return;

        if (!(kpc_ & kKpcMe)) return;

        uint32_t any = 0;
        for (uint32_t c = 0; c < 8u; ++c) any |= matrix_col_rows_[c];

        /* Intel PXA27x Developer's Manual 280000-001 Section 18.5.1: if IMKP is
           set, multiple keypresses are ignored; only when all keys are released
           is a new scan initiated or an interrupt generated. */
        if (kpc_ & kKpcImkp) {
            if (any == 0) { imkp_latched_ = false; }
            else if (imkp_latched_) { return; }
            else { imkp_latched_ = true; }
        }

        if (any) mkp_ = true;

        /* Intel PXA27x Developer's Manual 280000-001 Table 18-3 bit 29 ASACT:
           if KPC[AS] is clear, the keypad is scanned whenever there is any
           keypad activity. Section 18.5.1: when the scan completes, MI is set. */
        if ((kpc_ & kKpcAsact) && !(kpc_ & kKpcAs)) RunAutomaticScanLocked();
        mi_ = true;
        irq = MatrixIrqPendingLocked();
    }
    PublishIrq(irq);
}

uint32_t Pxa27xKeypad::ReadRegLocked(uint32_t off) {
    switch (off) {
    case kKpc: {
        /* Intel PXA27x Developer's Manual 280000-001 Table 18-3 bit 22 MI and
           bit 5 DI: reset when read, writes ignored. */
        uint32_t v = kpc_ & ~(kKpcMi | kKpcDi);
        if (mi_) v |= kKpcMi;
        if (di_) v |= kKpcDi;
        mi_ = false;
        di_ = false;
        return v;
    }
    case kKpdk:
        /* Intel PXA27x Developer's Manual 280000-001 Section 18.4.2.2: direct-key
           inputs that are not connected are guaranteed a logic 0 at all times. */
        return 0;
    case kKprec: {
        /* Intel PXA27x Developer's Manual 280000-001 Table 18-5: the overflow
           and underflow bits are reset when KPREC is read. */
        const uint32_t v = kprec_;
        kprec_ &= ~(kKprecOf1 | kKprecUf1 | kKprecOf0 | kKprecUf0);
        return v;
    }
    case kKpmk: {
        /* Intel PXA27x Developer's Manual 280000-001 Table 18-6 bit 31 MKP:
           reset on register read; bits 7:0 MR7..MR0 matrix row inputs. */
        uint32_t v = SenseRowsLocked();
        if (mkp_) v |= kKpmkMkp;
        mkp_ = false;
        return v;
    }
    case kKpas:     return kpas_;
    case kKpasmkp0: return kpasmkp_[0];
    case kKpasmkp1: return kpasmkp_[1];
    case kKpasmkp2: return kpasmkp_[2];
    case kKpasmkp3: return kpasmkp_[3];
    case kKpkdi:    return kpkdi_;
    default:        return 0;
    }
}

void Pxa27xKeypad::WriteRegLocked(uint32_t off, uint32_t value) {
    switch (off) {
    case kKpc:
        /* Intel PXA27x Developer's Manual 280000-001 Table 18-3 bit 22 MI and
           bit 5 DI: writes to them are ignored. */
        kpc_ = value & ~(kKpcMi | kKpcDi);
        /* Intel PXA27x Developer's Manual 280000-001 Table 18-3 bit 30 AS:
           writes cause the keypad to be scanned once, and then the AS bit is
           reset to zero. */
        if (value & kKpcAs) {
            RunAutomaticScanLocked();
            kpc_ &= ~kKpcAs;
            mi_ = true;
        }
        return;
    case kKprec: kprec_ = value; return;
    case kKpkdi: kpkdi_ = value & 0x0000FFFFu; return;
    default:     return;
    }
}

uint32_t Pxa27xKeypad::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (!IsKnown(off)) HaltUnsupportedAccess("ReadWord", addr, 0);
    std::lock_guard<std::mutex> lk(state_mtx_);
    return ReadRegLocked(off);
}

void Pxa27xKeypad::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (!IsKnown(off)) HaltUnsupportedAccess("WriteWord", addr, value);
    bool irq;
    {
        std::lock_guard<std::mutex> lk(state_mtx_);
        WriteRegLocked(off, value);
        irq = MatrixIrqPendingLocked();
    }
    PublishIrq(irq);
}

void Pxa27xKeypad::SaveState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(state_mtx_);
    w.Write(kpc_);
    w.Write(kprec_);
    w.Write(kpkdi_);
    w.Write(kpas_);
    for (uint32_t i = 0; i < 4u; ++i) w.Write(kpasmkp_[i]);
    w.Write(mkp_);
    w.Write(mi_);
    w.Write(di_);
    w.Write(imkp_latched_);
    for (uint32_t i = 0; i < 8u; ++i) w.Write(matrix_col_rows_[i]);
}

void Pxa27xKeypad::RestoreState(StateReader& r) {
    std::lock_guard<std::mutex> lk(state_mtx_);
    r.Read(kpc_);
    r.Read(kprec_);
    r.Read(kpkdi_);
    r.Read(kpas_);
    for (uint32_t i = 0; i < 4u; ++i) r.Read(kpasmkp_[i]);
    r.Read(mkp_);
    r.Read(mi_);
    r.Read(di_);
    r.Read(imkp_latched_);
    for (uint32_t i = 0; i < 8u; ++i) r.Read(matrix_col_rows_[i]);
}

void Pxa27xKeypad::PostRestore() {
    bool irq;
    {
        std::lock_guard<std::mutex> lk(state_mtx_);
        irq = MatrixIrqPendingLocked();
    }
    PublishIrq(irq);
}

REGISTER_SERVICE(Pxa27xKeypad);
