#include "peripheral_dispatcher.h"

#include "peripheral_base.h"
#include "../core/byte_order.h"
#include "../core/cerf_emulator.h"
#include "../core/fatal.h"
#include "../core/log.h"
#include "../cpu/emulated_memory.h"

#include <algorithm>
#include <typeinfo>

REGISTER_SERVICE(PeripheralDispatcher);

std::vector<Peripheral*> PeripheralDispatcher::RegisteredPeripherals() const {
    std::vector<Peripheral*> out;
    const EntryTable* t = live_.load(std::memory_order_acquire);
    if (!t) return out;
    out.reserve(t->size());
    for (const auto& e : *t) out.push_back(e.p);
    return out;
}

void PeripheralDispatcher::Register(Peripheral* p) {
    if (!p) {
        LOG(Caution, "PeripheralDispatcher::Register called with null\n");
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    const uint32_t base = p->MmioBase();
    const uint32_t size = p->MmioSize();
    if (size == 0) {
        LOG(Caution, "PeripheralDispatcher::Register peripheral has "
                "zero-size MMIO range (base 0x%08X)\n", base);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    if (size - 1u > 0xFFFFFFFFu - base) {
        emu_.Get<Fatal>().Die("PeripheralDispatcher::Register %s at 0x%08X size 0x%08X runs "
                              "past 0xFFFFFFFF", typeid(*p).name(), base, size);
    }
    const uint32_t last = base + (size - 1u);

    std::lock_guard<std::mutex> lock(table_mutex_);
    for (const auto& e : entries_) {
        if (base <= e.last && e.base <= last) {
            LOG(Caution, "PeripheralDispatcher::Register overlap: "
                    "new [0x%08X..0x%08X] vs existing [0x%08X..0x%08X]\n",
                    base, last, e.base, e.last);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
    }

    const Entry entry{base, last, p->FastReader(), p->FastWriter(), p, p, nullptr};
    auto pos = std::lower_bound(entries_.begin(), entries_.end(), base,
        [](const Entry& e, uint32_t b) { return e.base < b; });
    entries_.insert(pos, entry);
    table_by_active_.clear();
    PublishLocked();

    LOG(Periph, "Register [0x%08X..0x%08X]\n", base, last);
}

PeripheralDispatcher::DataInversionId PeripheralDispatcher::InstallDataInversion(
    uint32_t base, uint32_t end) {
    if (base >= end) {
        emu_.Get<Fatal>().Die("PeripheralDispatcher::InstallDataInversion empty range "
                              "[0x%08X..0x%08X)", base, end);
    }
    if (emu_.Get<EmulatedMemory>().OverlapsRegion(base, end - base)) {
        emu_.Get<Fatal>().Die("PeripheralDispatcher::InstallDataInversion [0x%08X..0x%08X) "
                              "overlaps backed memory", base, end);
    }
    std::lock_guard<std::mutex> lock(table_mutex_);
    if (inversions_.size() >= kMaxDataInversions) {
        emu_.Get<Fatal>().Die("PeripheralDispatcher::InstallDataInversion [0x%08X..0x%08X) "
                              "past %u ranges", base, end, kMaxDataInversions);
    }
    if (OverlapsDataInversionLocked(base, end)) {
        emu_.Get<Fatal>().Die("PeripheralDispatcher::InstallDataInversion [0x%08X..0x%08X) "
                              "overlaps another inversion range", base, end);
    }
    inversions_.push_back({base, end});
    table_by_active_.clear();
    PublishLocked();

    LOG(Periph, "InstallDataInversion 0x%08X..0x%08X\n", base, end);
    return static_cast<DataInversionId>(inversions_.size() - 1u);
}

void PeripheralDispatcher::SetDataInversion(DataInversionId id, bool inverting) {
    std::lock_guard<std::mutex> lock(table_mutex_);
    if (id >= inversions_.size()) {
        emu_.Get<Fatal>().Die("PeripheralDispatcher::SetDataInversion unknown range %u", id);
    }
    const uint32_t bit    = 1u << id;
    const uint32_t active = inverting ? (active_inversions_ | bit) : (active_inversions_ & ~bit);
    if (active == active_inversions_) return;
    active_inversions_ = active;
    PublishLocked();

    const EntryTable* live = live_.load(std::memory_order_acquire);
    const auto wrapped = std::count_if(live->begin(), live->end(),
        [](const Entry& e) { return e.inverted != nullptr; });
    LOG(Periph, "SetDataInversion range %u %s: active 0x%X, %d of %zu entries wrapped\n",
        id, inverting ? "on" : "off", active, static_cast<int>(wrapped), live->size());
}

bool PeripheralDispatcher::OverlapsDataInversion(uint32_t base, uint32_t size) const {
    std::lock_guard<std::mutex> lock(table_mutex_);
    return OverlapsDataInversionLocked(base, uint64_t{base} + size);
}

bool PeripheralDispatcher::OverlapsDataInversionLocked(uint32_t base, uint64_t end) const {
    for (const InversionRange& r : inversions_) {
        if (base < r.end && r.base < end) return true;
    }
    return false;
}

const PeripheralDispatcher::InversionRange* PeripheralDispatcher::InversionRangeOf(
    const Entry& entry) const {
    for (const InversionRange& r : inversions_) {
        if (entry.base < r.end && r.base <= entry.last) {
            if (entry.base < r.base || entry.last >= r.end) {
                emu_.Get<Fatal>().Die("PeripheralDispatcher: %s at [0x%08X..0x%08X] crosses the "
                                      "edge of data inversion range [0x%08X..0x%08X)",
                                      typeid(*entry.p).name(), entry.base, entry.last, r.base,
                                      r.end);
            }
            return &r;
        }
    }
    return nullptr;
}

void PeripheralDispatcher::PublishLocked() {
    const EntryTable* published = nullptr;
    const auto cached = table_by_active_.find(active_inversions_);
    if (cached != table_by_active_.end()) {
        published = cached->second;
    } else {
        auto next = std::make_unique<EntryTable>(entries_);
        for (Entry& e : *next) {
            const InversionRange* r = InversionRangeOf(e);
            if (!r) continue;
            const uint32_t index = static_cast<uint32_t>(r - inversions_.data());
            if ((active_inversions_ & (1u << index)) == 0u) continue;
            inverted_targets_.push_back(std::make_unique<InvertedTarget>(
                InvertedTarget{e.read, e.write, e.ctx}));
            InvertedTarget* t = inverted_targets_.back().get();
            e.read     = &InvertedRead;
            e.write    = &InvertedWrite;
            e.ctx      = t;
            e.inverted = t;
        }
        published = next.get();
        tables_.push_back(std::move(next));
        table_by_active_.emplace(active_inversions_, published);
    }
    last_hit_.store(0, std::memory_order_relaxed);
    live_.store(published, std::memory_order_release);
}

uint32_t PeripheralDispatcher::InvertedRead(void* ctx, uint32_t off, uint32_t width_bytes) {
    const auto* t = static_cast<const InvertedTarget*>(ctx);
    return ~t->read(t->ctx, off, width_bytes) & cerf::ByteWidthMask(width_bytes);
}

void PeripheralDispatcher::InvertedWrite(void* ctx, uint32_t off, uint32_t value,
                                         uint32_t width_bytes) {
    const auto* t = static_cast<const InvertedTarget*>(ctx);
    t->write(t->ctx, off, ~value & cerf::ByteWidthMask(width_bytes), width_bytes);
}

bool PeripheralDispatcher::IsPeripheralAddress(uint32_t addr) const {
    return LookupEntry(addr) != nullptr;
}

void PeripheralDispatcher::ValidatePhysReachable(uint32_t phys_addr_mask) const {
    if (phys_addr_mask == 0xFFFFFFFFu) return;
    const EntryTable* t = live_.load(std::memory_order_acquire);
    if (!t) return;
    for (const auto& e : *t) {
        if (e.last > phys_addr_mask) {
            LOG(Caution, "PeripheralDispatcher: %s at [0x%08X..0x%08X] is above "
                    "the SoC physical space (mask 0x%08X); it aliases to "
                    "0x%08X and is unreachable/shadowed - relocate it into the "
                    "addressable range\n",
                    typeid(*e.p).name(), e.base, e.last, phys_addr_mask,
                    e.base & phys_addr_mask);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
    }
}

/* QEMU system/physmem.c:345 address_space_lookup_region(), mru_section. */
const PeripheralDispatcher::Entry* PeripheralDispatcher::LookupEntry(
    uint32_t addr) const {
    if (const Entry* hit = MemoHit(addr)) return hit;
    return LookupSlow(addr);
}

const PeripheralDispatcher::Entry* PeripheralDispatcher::LookupSlow(
    uint32_t addr) const {
    const EntryTable* t = live_.load(std::memory_order_acquire);
    if (!t) return nullptr;

    auto it = std::upper_bound(t->begin(), t->end(), addr,
        [](uint32_t a, const Entry& e) { return a < e.base; });
    if (it == t->begin()) return nullptr;
    --it;
    if (addr >= it->base && addr <= it->last) {
        last_hit_.store(static_cast<size_t>(it - t->begin()),
                        std::memory_order_relaxed);
        return &(*it);
    }
    return nullptr;
}

uint32_t PeripheralDispatcher::ReadSlow(uint32_t addr, MmioWidth width) {
    if (const Entry* e = LookupSlow(addr)) {
        return ClipToWidth(
            e->read(e->ctx, addr - e->base, static_cast<uint32_t>(width)),
            width);
    }
    switch (width) {
    case MmioWidth::kByte: return emu_.Get<EmulatedMemory>().ReadByte(addr);
    case MmioWidth::kHalf: return emu_.Get<EmulatedMemory>().ReadHalf(addr);
    case MmioWidth::kWord: return emu_.Get<EmulatedMemory>().ReadWord(addr);
    }
    HaltBadWidth(static_cast<uint32_t>(width));
}

void PeripheralDispatcher::HaltBadWidth(uint32_t width) {
    LOG(Caution, "PeripheralDispatcher: unmodeled MMIO width %u\n", width);
    CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
}

void PeripheralDispatcher::WriteSlow(uint32_t addr, uint32_t value,
                                     MmioWidth width) {
    if (const Entry* e = LookupSlow(addr)) {
        e->write(e->ctx, addr - e->base, ClipToWidth(value, width),
                 static_cast<uint32_t>(width));
        return;
    }
    switch (width) {
    case MmioWidth::kByte: emu_.Get<EmulatedMemory>().WriteByte(addr, static_cast<uint8_t>(value)); return;
    case MmioWidth::kHalf: emu_.Get<EmulatedMemory>().WriteHalf(addr, static_cast<uint16_t>(value)); return;
    case MmioWidth::kWord: emu_.Get<EmulatedMemory>().WriteWord(addr, value); return;
    }
    HaltBadWidth(static_cast<uint32_t>(width));
}

uint8_t PeripheralDispatcher::ReadByte(uint32_t addr) {
    return static_cast<uint8_t>(Read(addr, MmioWidth::kByte));
}

uint16_t PeripheralDispatcher::ReadHalf(uint32_t addr) {
    return static_cast<uint16_t>(Read(addr, MmioWidth::kHalf));
}

uint32_t PeripheralDispatcher::ReadWord(uint32_t addr) {
    return Read(addr, MmioWidth::kWord);
}

uint64_t PeripheralDispatcher::ReadDword(uint32_t addr) {
    if (const Entry* e = LookupEntry(addr)) {
        const uint64_t value = e->p->ReadDword(addr);
        return e->inverted ? ~value : value;
    }
    return emu_.Get<EmulatedMemory>().ReadDword(addr);
}

void PeripheralDispatcher::WriteByte(uint32_t addr, uint8_t value) {
    Write(addr, value, MmioWidth::kByte);
}

void PeripheralDispatcher::WriteHalf(uint32_t addr, uint16_t value) {
    Write(addr, value, MmioWidth::kHalf);
}

void PeripheralDispatcher::WriteWord(uint32_t addr, uint32_t value) {
    Write(addr, value, MmioWidth::kWord);
}

void PeripheralDispatcher::WriteDword(uint32_t addr, uint64_t value) {
    if (const Entry* e = LookupEntry(addr)) {
        if (e->inverted) value = ~value;
        e->p->WriteDword(addr, value);
        return;
    }
    emu_.Get<EmulatedMemory>().WriteDword(addr, value);
}

