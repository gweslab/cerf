#include "imx31_kpp.h"

#include "../../core/cerf_emulator.h"
#include "../../boards/board_detector.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "imx31_avic.h"

#include <chrono>
#include <cstdint>
#include <mutex>

namespace {

constexpr uint32_t kBase = 0x43FA8000u;
constexpr uint32_t kKpcr = 0x00u;
constexpr uint32_t kKpsr = 0x02u;
constexpr uint32_t kKddr = 0x04u;
constexpr uint32_t kKpdr = 0x06u;

/* KPSR fields — MCIMX31RM Table 27-6. */
constexpr uint16_t kKpkd = 0x0001u;  /* key depress, W1C */
constexpr uint16_t kKpkr = 0x0002u;  /* key release, W1C */
constexpr uint16_t kKdsc = 0x0004u;  /* depress sync clear, self-clearing (reads 0) */
constexpr uint16_t kKrss = 0x0008u;  /* release sync set, self-clearing (reads 0) */
constexpr uint16_t kKdie = 0x0100u;  /* depress interrupt enable */
constexpr uint16_t kKrie = 0x0200u;  /* release interrupt enable */

/* MCIMX31RM Ch 9 interrupt-source assignment table: source 24 = KPP. */
constexpr uint32_t kAvicSourceKpp = 24u;

/* Held-key re-detect interval. Must be below the pyxis_keybd debounce
   (sub_30F1CDC compares GetTickCount deltas against 0x28 = 40 ms). */
constexpr auto kSyncDetectInterval = std::chrono::milliseconds(16);

}  /* namespace */

Imx31Kpp::~Imx31Kpp() {
    { std::lock_guard<std::mutex> lk(mtx_); stop_ = true; }
    sync_cv_.notify_all();
    if (sync_thread_.joinable()) sync_thread_.join();
}

bool Imx31Kpp::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardDetector>();
    return bd && bd->GetSoc() == SocFamily::iMX31;
}

void Imx31Kpp::OnReady() {
    emu_.Get<PeripheralDispatcher>().Register(this);
    sync_thread_ = std::thread([this] { SyncDetectLoop(); });
}

/* Row sense (KPDR bits 0-4): a row reads low only where a pressed key shorts it
   to a column currently strobed low (column data bit 8+c == 0). */
uint16_t Imx31Kpp::RowSenseLocked() const {
    uint16_t rows = 0x1Fu;
    for (uint8_t c = 0; c < 4; ++c)
        if (((kpdr_col_ >> (8u + c)) & 1u) == 0u)
            rows &= static_cast<uint16_t>(~pressed_[c]);
    return rows & 0x1Fu;
}

uint16_t Imx31Kpp::ReadReg16Locked(uint32_t off) {
    switch (off) {
        case kKpcr: return kpcr_;
        case kKpsr: return kpsr_ & (kKpkd | kKpkr | kKdie | kKrie);
        case kKddr: return kddr_;
        case kKpdr: return static_cast<uint16_t>(kpdr_col_ | RowSenseLocked());
    }
    HaltUnsupportedAccess("ReadReg16", kBase + off, 0);
}

bool Imx31Kpp::WriteReg16Locked(uint32_t off, uint16_t value) {
    switch (off) {
        case kKpcr: kpcr_ = value; return false;
        case kKpsr:
            kpsr_ = static_cast<uint16_t>(kpsr_ & ~(value & (kKpkd | kKpkr)));
            kpsr_ = static_cast<uint16_t>((kpsr_ & ~(kKdie | kKrie)) |
                                          (value & (kKdie | kKrie)));
            return true;  /* enable/W1C change -> re-eval IRQ */
        case kKddr: kddr_ = value; return false;
        /* Columns are software-driven outputs; rows are sense inputs (ignored). */
        case kKpdr: kpdr_col_ = value & 0xFF00u; return false;
    }
    HaltUnsupportedAccess("WriteReg16", kBase + off, value);
}

bool Imx31Kpp::IrqDesiredLocked() const {
    return ((kpsr_ & kKpkd) && (kpsr_ & kKdie)) ||
           ((kpsr_ & kKpkr) && (kpsr_ & kKrie));
}

bool Imx31Kpp::AnyPressedLocked() const {
    return (pressed_[0] | pressed_[1] | pressed_[2] | pressed_[3]) != 0u;
}

/* Re-assert KPKD while a key is held so the driver re-scans: its KEYDOWN inject
   needs a scan finding the key still down >=40 ms after the first, which one
   IRQ-per-press edge can't supply. (KEYUP injects on the release edge, scan-once.) */
void Imx31Kpp::SyncDetectLoop() {
    std::unique_lock<std::mutex> lk(mtx_);
    while (!stop_) {
        sync_cv_.wait(lk, [this] { return stop_ || AnyPressedLocked(); });
        while (!stop_ && AnyPressedLocked()) {
            if (kpsr_ & kKdie) {
                kpsr_ |= kKpkd;
                const bool desired = IrqDesiredLocked();
                lk.unlock();
                ApplyIrq(desired);
                lk.lock();
            }
            sync_cv_.wait_for(lk, kSyncDetectInterval);
        }
    }
}

void Imx31Kpp::ApplyIrq(bool desired) {
    if (irq_on_.exchange(desired) == desired) return;
    auto& avic = emu_.Get<Imx31Avic>();
    if (desired) avic.AssertSource(kAvicSourceKpp);
    else         avic.DeassertSource(kAvicSourceKpp);
}

void Imx31Kpp::SetMatrixKey(uint8_t col, uint8_t row, bool pressed) {
    if (col >= 4u || row >= 5u) return;
    bool desired;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        const uint8_t bit = static_cast<uint8_t>(1u << row);
        if (((pressed_[col] & bit) != 0) == pressed) return;
        if (pressed) { pressed_[col] |= bit;  kpsr_ |= kKpkd; }
        else         { pressed_[col] &= static_cast<uint8_t>(~bit); kpsr_ |= kKpkr; }
        desired = IrqDesiredLocked();
    }
    ApplyIrq(desired);
    if (pressed) sync_cv_.notify_all();  /* start re-detect for the held key */
}

uint8_t Imx31Kpp::ReadByte(uint32_t addr) {
    const uint32_t off = (addr - kBase) & ~1u;
    uint16_t v;
    { std::lock_guard<std::mutex> lk(mtx_); v = ReadReg16Locked(off); }
    return ((addr & 1u) ? (v >> 8) : v) & 0xFFu;
}

void Imx31Kpp::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off = (addr - kBase) & ~1u;
    bool eval, desired = false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        uint16_t v = ReadReg16Locked(off);
        v = (addr & 1u) ? static_cast<uint16_t>((v & 0x00FFu) | (uint16_t(value) << 8))
                        : static_cast<uint16_t>((v & 0xFF00u) | value);
        eval = WriteReg16Locked(off, v);
        if (eval) desired = IrqDesiredLocked();
    }
    if (eval) ApplyIrq(desired);
}

uint16_t Imx31Kpp::ReadHalf(uint32_t addr) {
    std::lock_guard<std::mutex> lk(mtx_);
    return ReadReg16Locked(addr - kBase);
}

void Imx31Kpp::WriteHalf(uint32_t addr, uint16_t value) {
    bool eval, desired = false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        eval = WriteReg16Locked(addr - kBase, value);
        if (eval) desired = IrqDesiredLocked();
    }
    if (eval) ApplyIrq(desired);
}

uint32_t Imx31Kpp::ReadWord(uint32_t addr) {
    const uint32_t off = addr - kBase;
    std::lock_guard<std::mutex> lk(mtx_);
    return ReadReg16Locked(off) | (uint32_t(ReadReg16Locked(off + 2)) << 16);
}

void Imx31Kpp::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - kBase;
    bool eval, desired = false;
    {
        std::lock_guard<std::mutex> lk(mtx_);
        const bool e0 = WriteReg16Locked(off, value & 0xFFFFu);
        const bool e1 = WriteReg16Locked(off + 2, value >> 16);
        eval = e0 || e1;
        if (eval) desired = IrqDesiredLocked();
    }
    if (eval) ApplyIrq(desired);
}

REGISTER_SERVICE(Imx31Kpp);
