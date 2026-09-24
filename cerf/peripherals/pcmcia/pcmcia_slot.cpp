#include "pcmcia_slot.h"

#include "pcmcia_card_catalog.h"

#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../host/host_icon_cache.h"
#include "../../state/state_stream.h"

#include <chrono>
#include <thread>
#include <utility>

namespace {

constexpr uint8_t  kFloat8  = PcmciaCard::kBusFloat8;
constexpr uint16_t kFloat16 = PcmciaCard::kBusFloat16;

}  /* namespace */

PcmciaSlot::PcmciaSlot(CerfEmulator& emu, PcmciaSlotHost& host,
                       std::wstring label)
    : emu_(emu), host_(host), label_(std::move(label)) {}

void PcmciaSlot::PublishPinsLocked() {
    const uint8_t v = (card_ ? kPinPresent : 0u) | (powered_ ? kPinPowered : 0u);
    pins_.store(v, std::memory_order_release);
}

void PcmciaSlot::SetPowered(bool on) {
    std::lock_guard<std::mutex> lk(bus_mutex_);
    if (powered_ == on) return;
    powered_ = on;
    PublishPinsLocked();
    if (!card_) return;
    if (on) card_->PowerOn();
    else    card_->PowerOff();
}

void PcmciaSlot::ResetCard() {
    std::lock_guard<std::mutex> lk(bus_mutex_);
    if (!card_ || !powered_) return;
    card_->SocketReset();
}

uint8_t PcmciaSlot::ReadAttribute8(uint32_t offset) {
    std::lock_guard<std::mutex> lk(bus_mutex_);
    if (!card_ || !powered_) return kFloat8;
    return card_->ReadAttribute8(offset);
}

void PcmciaSlot::WriteAttribute8(uint32_t offset, uint8_t value) {
    std::lock_guard<std::mutex> lk(bus_mutex_);
    if (!card_ || !powered_) return;
    card_->WriteAttribute8(offset, value);
}

uint8_t PcmciaSlot::ReadCommon8(uint32_t offset) {
    std::lock_guard<std::mutex> lk(bus_mutex_);
    if (!card_ || !powered_) return kFloat8;
    return card_->ReadCommon8(offset);
}

uint16_t PcmciaSlot::ReadCommon16(uint32_t offset) {
    std::lock_guard<std::mutex> lk(bus_mutex_);
    if (!card_ || !powered_) return kFloat16;
    return card_->ReadCommon16(offset);
}

void PcmciaSlot::WriteCommon8(uint32_t offset, uint8_t value) {
    std::lock_guard<std::mutex> lk(bus_mutex_);
    if (!card_ || !powered_) return;
    card_->WriteCommon8(offset, value);
}

void PcmciaSlot::WriteCommon16(uint32_t offset, uint16_t value) {
    std::lock_guard<std::mutex> lk(bus_mutex_);
    if (!card_ || !powered_) return;
    card_->WriteCommon16(offset, value);
}

uint8_t PcmciaSlot::ReadIo8(uint32_t offset) {
    std::lock_guard<std::mutex> lk(bus_mutex_);
    if (!card_ || !powered_) return kFloat8;
    return card_->ReadIo8(offset);
}

uint16_t PcmciaSlot::ReadIo16(uint32_t offset) {
    std::lock_guard<std::mutex> lk(bus_mutex_);
    if (!card_ || !powered_) return kFloat16;
    return card_->ReadIo16(offset);
}

void PcmciaSlot::WriteIo8(uint32_t offset, uint8_t value) {
    std::lock_guard<std::mutex> lk(bus_mutex_);
    if (!card_ || !powered_) return;
    card_->WriteIo8(offset, value);
}

void PcmciaSlot::WriteIo16(uint32_t offset, uint16_t value) {
    std::lock_guard<std::mutex> lk(bus_mutex_);
    if (!card_ || !powered_) return;
    card_->WriteIo16(offset, value);
}

void PcmciaSlot::RaiseIrq() { host_.OnCardIrqAsserted(*this); }
void PcmciaSlot::ClearIrq() { host_.OnCardIrqDeasserted(*this); }

void PcmciaSlot::InsertLocked(std::unique_ptr<PcmciaCard> card) {
    card_ = std::move(card);
    ++generation_;
    PublishPinsLocked();
    card_->AttachSlot(this, generation_);
    card_->OnInserted();
    if (powered_) card_->PowerOn();
    LOG(Pcmcia, "[Slot %ls] inserted: %ls\n", label_.c_str(),
        card_->DisplayName().c_str());
}

void PcmciaSlot::EjectLocked() {
    LOG(Pcmcia, "[Slot %ls] ejected: %ls\n", label_.c_str(),
        card_->DisplayName().c_str());
    if (powered_) card_->PowerOff();
    card_.reset();
    ++generation_;
    PublishPinsLocked();
}

void PcmciaSlot::InsertCard(std::unique_ptr<PcmciaCard> card) {
    {
        std::lock_guard<std::mutex> lk(bus_mutex_);
        if (card_) {
            LOG(Caution, "[Slot %ls] InsertCard into occupied slot "
                    "(%ls) - rejected\n",
                label_.c_str(), card_->DisplayName().c_str());
            return;
        }
        InsertLocked(std::move(card));
    }
    host_.OnCardDetectChanged(*this);
}

void PcmciaSlot::OnShutdown() {
    std::lock_guard<std::mutex> lk(bus_mutex_);
    if (card_) card_->OnShutdown();
}

void PcmciaSlot::SaveSlotState(StateWriter& w) {
    std::lock_guard<std::mutex> lk(bus_mutex_);
    w.Write<uint8_t>("powered", powered_ ? 1u : 0u);
    const bool has = (card_ != nullptr);
    w.Write<uint8_t>("has", has ? 1u : 0u);
    if (!has) return;
    const std::string id = card_->SaveId();
    w.Write<uint32_t>("id_count", static_cast<uint32_t>(id.size()));
    if (!id.empty()) w.WriteBytes("id", id.data(), id.size());
    const std::wstring binding = card_->SaveBinding();
    w.Write<uint32_t>("binding_count", static_cast<uint32_t>(binding.size()));
    if (!binding.empty())
        w.WriteBytes("binding", binding.data(), binding.size() * sizeof(wchar_t));
    w.BeginFrame(0);
    card_->SaveState(w);
    w.EndFrame();
}

/* Called by the controller with its own lock released: the card may drive its socket IRQ
   from here, which re-enters the controller. */
void PcmciaSlot::PostRestoreSlot() {
    std::lock_guard<std::mutex> lk(bus_mutex_);
    if (card_) card_->PostRestore();
}

void PcmciaSlot::RestoreSlotState(StateReader& r) {
    std::lock_guard<std::mutex> lk(bus_mutex_);
    uint8_t powered = 0, has = 0;
    r.Read("powered", powered);
    r.Read("has", has);
    if (!has) {
        /* Saved socket was empty; eject any live card so the restored
           desktop matches exactly. */
        if (card_) EjectLocked();
        powered_ = (powered != 0);
        PublishPinsLocked();
        return;
    }
    uint32_t idlen = 0; r.Read("id_count", idlen);
    std::string id(static_cast<size_t>(idlen), '\0');
    if (idlen) r.ReadBytes("id", &id[0], idlen);
    uint32_t blen = 0; r.Read("binding_count", blen);
    std::wstring binding(static_cast<size_t>(blen), L'\0');
    if (blen) r.ReadBytes("binding", &binding[0], blen * sizeof(wchar_t));
    if (const uint32_t frame = r.EnterFrame(); frame != 0u)
        r.Reject("PC Card body in frame 0x%X, this build writes frame 0", frame);
    /* Resume the exact desktop: rebuild the saved card from its id + host
       binding when the socket is empty or holds a different card, then apply
       its register state. */
    if (!card_ || id != card_->SaveId()) {
        auto card = emu_.Get<PcmciaCardCatalog>().TryCreate(id, binding);
        if (!card) r.Reject("PC Card '%s' is unknown to this build", id.c_str());
        if (card_) EjectLocked();
        powered_ = (powered != 0);
        PublishPinsLocked();
        InsertLocked(std::move(card));
    } else if (powered_ != (powered != 0)) {
        powered_ = (powered != 0);
        PublishPinsLocked();
        if (powered_) card_->PowerOn();
        else          card_->PowerOff();
    }
    card_->RestoreState(r);
    r.LeaveFrame();
}

void PcmciaSlot::EjectCard() {
    {
        std::lock_guard<std::mutex> lk(bus_mutex_);
        if (!card_) return;
        EjectLocked();
    }
    host_.OnCardDetectChanged(*this);
}

void PcmciaSlot::EjectCardIfResident(uint64_t card_id) {
    {
        std::lock_guard<std::mutex> lk(bus_mutex_);
        if (!card_ || card_->CardId() != card_id) return;
        EjectLocked();
    }
    host_.OnCardDetectChanged(*this);
}

void PcmciaSlot::MenuEject(uint64_t gen) {
    {
        std::lock_guard<std::mutex> lk(bus_mutex_);
        if (generation_ != gen || !card_) return;
        EjectLocked();
    }
    host_.OnCardDetectChanged(*this);
}

void PcmciaSlot::CombinedSwap(uint64_t gen, std::unique_ptr<PcmciaCard> card) {
    bool ejected = false;
    {
        std::lock_guard<std::mutex> lk(bus_mutex_);
        if (generation_ != gen) return;
        if (card_) {
            EjectLocked();
            ejected = true;
        }
    }
    if (ejected) {
        host_.OnCardDetectChanged(*this);   /* removal edge */
        /* Hold the socket empty until the guest's detect handler runs and reads
           it absent */
        std::this_thread::sleep_for(std::chrono::milliseconds(1500));
    }
    {
        std::lock_guard<std::mutex> lk(bus_mutex_);
        if (card_) return;   /* raced with another inserter; keep theirs */
        InsertLocked(std::move(card));
    }
    host_.OnCardDetectChanged(*this);       /* insert edge */
}

void PcmciaSlot::MenuInsert(uint64_t gen, const std::string& card_id) {
    CombinedSwap(gen, emu_.Get<PcmciaCardCatalog>().Create(card_id));
}

void PcmciaSlot::MenuInsertCard(uint64_t gen, std::unique_ptr<PcmciaCard> card) {
    if (!card) return;
    CombinedSwap(gen, std::move(card));
}

std::vector<WidgetMenuItem> PcmciaSlot::BuildInsertSubmenuLocked(uint64_t gen) {
    std::vector<WidgetMenuItem> items;
    for (const auto& e : emu_.Get<PcmciaCardCatalog>().Entries()) {
        WidgetMenuItem it;
        it.label = e.display_name;
        if (e.insert_submenu) {
            /* Card kind contributes its own insert submenu; the inserter
               places a card it built (e.g. from a file dialog). */
            auto inserter = [this, gen](std::unique_ptr<PcmciaCard> card) {
                MenuInsertCard(gen, std::move(card));
            };
            it.submenu = e.insert_submenu(inserter);
        } else {
            const std::string id = e.id;
            it.on_click = [this, gen, id] { MenuInsert(gen, id); };
        }
        items.push_back(std::move(it));
    }
    return items;
}

WidgetMenuItem PcmciaSlot::GuardCardItemLocked(WidgetMenuItem item,
                                               uint64_t gen) {
    if (item.on_click) {
        auto inner = std::move(item.on_click);
        item.on_click = [this, gen, inner] {
            std::lock_guard<std::mutex> lk(bus_mutex_);
            if (generation_ != gen) return;
            inner();
        };
    }
    for (auto& sub : item.submenu) {
        sub = GuardCardItemLocked(std::move(sub), gen);
    }
    return item;
}

std::vector<WidgetMenuItem> PcmciaSlot::BuildMenu() {
    std::lock_guard<std::mutex> lk(bus_mutex_);
    const uint64_t gen = generation_;
    std::vector<WidgetMenuItem> items;

    if (!card_) {
        WidgetMenuItem insert;
        insert.label   = L"Insert card";
        insert.submenu = BuildInsertSubmenuLocked(gen);
        items.push_back(std::move(insert));
        return items;
    }

    WidgetMenuItem header;
    header.label   = card_->DisplayName();
    header.enabled = false;
    items.push_back(std::move(header));

    WidgetMenuItem eject;
    eject.label    = L"Eject";
    eject.on_click = [this, gen] { MenuEject(gen); };
    items.push_back(std::move(eject));

    WidgetMenuItem swap;
    swap.label   = L"Eject and insert";
    swap.submenu = BuildInsertSubmenuLocked(gen);
    items.push_back(std::move(swap));

    auto card_items = card_->BuildCardMenu();
    if (!card_items.empty()) {
        items.emplace_back();   /* separator */
        for (auto& ci : card_items) {
            items.push_back(GuardCardItemLocked(std::move(ci), gen));
        }
    }
    return items;
}

std::wstring PcmciaSlot::Tooltip() const {
    std::lock_guard<std::mutex> lk(bus_mutex_);
    if (!card_) return label_ + L" - empty";
    return label_ + L" - " + card_->TooltipDetail();
}

void PcmciaSlot::DrawIcon(HDC dc, const RECT& box) const {
    const wchar_t* res;
    {
        std::lock_guard<std::mutex> lk(bus_mutex_);
        res = card_ ? card_->IconResource() : L"ICON_PCMCIA_EMPTY";
    }
    emu_.Get<HostIconCache>().DrawCentered(dc, box, res);
}

bool PcmciaSlot::PollDirty() {
    std::wstring res;
    {
        std::lock_guard<std::mutex> lk(bus_mutex_);
        res = card_ ? card_->IconResource() : L"ICON_PCMCIA_EMPTY";
    }
    if (res == ui_last_res_) return false;
    ui_last_res_ = std::move(res);
    return true;
}
