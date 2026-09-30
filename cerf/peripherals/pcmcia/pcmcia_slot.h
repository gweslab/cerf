#pragma once

#include "pcmcia_card.h"

#include <atomic>
#include <cstdint>
#include <memory>
#include <mutex>
#include <string>

class CerfEmulator;
class PcmciaSlot;

class PcmciaSlotHost {
public:
    virtual ~PcmciaSlotHost() = default;
    virtual void OnCardDetectChanged(PcmciaSlot& slot) = 0;
    virtual void OnCardIrqAsserted  (PcmciaSlot& slot) = 0;
    virtual void OnCardIrqDeasserted(PcmciaSlot& slot) = 0;
    virtual void OnCardAccess(PcmciaSlot&) {}
};

/* One physical PCMCIA socket. Lock hierarchy: bus_mutex_ > backend rx-callback
   mutex > card mutex > controller mutex. */
class PcmciaSlot : public HostWidget {
public:
    PcmciaSlot(CerfEmulator& emu, PcmciaSlotHost& host, std::wstring label);

    /* Guest bus surface. Empty or unpowered socket reads float high
       (PCMCIA bus convention: no card drives the data lines). */

    /* CD/Vcc pin state. Lock-free by construction: a socket host reads these
       from inside its own lock, and bus_mutex_ ranks above it. */
    bool HasCard()   const { return (pins_.load(std::memory_order_acquire) & kPinPresent) != 0u; }
    bool IsPowered() const {
        constexpr uint8_t live = kPinPresent | kPinPowered;
        return (pins_.load(std::memory_order_acquire) & live) == live;
    }
    void SetPowered(bool on);
    void ResetCard();          /* socket RESET pin pulse */
    void GateCardAccess() { access_gate_ = true; }

    uint8_t  ReadAttribute8 (uint32_t offset);
    void     WriteAttribute8(uint32_t offset, uint8_t value);
    uint8_t  ReadCommon8  (uint32_t offset);
    uint16_t ReadCommon16 (uint32_t offset);
    void     WriteCommon8 (uint32_t offset, uint8_t  value);
    void     WriteCommon16(uint32_t offset, uint16_t value);
    uint8_t  ReadIo8  (uint32_t offset);
    uint16_t ReadIo16 (uint32_t offset);
    void     WriteIo8 (uint32_t offset, uint8_t  value);
    void     WriteIo16(uint32_t offset, uint16_t value);

    /* Card-side IRQ line, callable from any card thread; no bus lock. */
    void RaiseIrq();
    void ClearIrq();

    /* Insert/eject. Used by the UI menu and by board boot-default
       services. Inserting into an occupied slot is rejected loudly. */
    void InsertCard(std::unique_ptr<PcmciaCard> card);
    void EjectCard();

    /* Eject on behalf of a card whose host resource died, keyed on the residency id
       it was given at insert: the request is dispatched from a UI job, by which time
       the card may already be gone and another may hold the slot. */
    void EjectCardIfResident(uint64_t card_id);

    /* Forward the CerfEmulator quiesce phase to the resident card so it can
       detach from peers before any service is destroyed. Owning controllers
       call this from their Service::OnShutdown. */
    void OnShutdown();

    void SaveSlotState(StateWriter& w);
    void RestoreSlotState(StateReader& r);
    void PostRestoreSlot();

    /* HostWidget. */
    std::wstring WidgetName() const override { return label_; }
    WidgetGroup  Group() const override { return WidgetGroup::Pcmcia; }
    std::wstring Tooltip() const override;
    std::vector<WidgetMenuItem> BuildMenu() override;
    void DrawIcon(HDC dc, const RECT& box) const override;
    bool PollDirty() override;

private:
    static constexpr uint8_t kPinPresent = 0x01u;
    static constexpr uint8_t kPinPowered = 0x02u;
    void PublishPinsLocked();
    bool CardSelectedLocked();

    void InsertLocked(std::unique_ptr<PcmciaCard> card);
    void EjectLocked();

    /* Menu actions; gen guards against stale popup callbacks firing
       after the slot's contents changed. */
    void MenuEject(uint64_t gen);
    void CombinedSwap(uint64_t gen, std::unique_ptr<PcmciaCard> card);
    void MenuInsert(uint64_t gen, const std::string& card_id);
    /* Insert a pre-built card (gen-guarded) - used by card kinds whose
       insert menu resolves a host resource (e.g. CompactFlash image). */
    void MenuInsertCard(uint64_t gen, std::unique_ptr<PcmciaCard> card);
    std::vector<WidgetMenuItem> BuildInsertSubmenuLocked(uint64_t gen);
    WidgetMenuItem GuardCardItemLocked(WidgetMenuItem item, uint64_t gen);

    CerfEmulator&   emu_;
    PcmciaSlotHost& host_;
    std::wstring    label_;

    mutable std::mutex          bus_mutex_;
    std::unique_ptr<PcmciaCard> card_;
    bool                        powered_ = false;
    bool                        access_gate_ = false;
    uint64_t                    generation_ = 0;
    std::atomic<uint8_t>        pins_{0};

    std::wstring ui_last_res_;   /* last-drawn icon resource; UI thread only (PollDirty) */
};
