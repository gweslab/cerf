#include "peripheral_dispatcher.h"

#include "peripheral_base.h"
#include "../core/cerf_emulator.h"
#include "../core/log.h"
#include "../core/rate_probe.h"
#include "../cpu/emulated_memory.h"
#include "../jit/arm_mmu.h"

#include <algorithm>
#include <intrin.h>

REGISTER_SERVICE(PeripheralDispatcher);

void PeripheralDispatcher::OnReady() {
    mmu_ = &emu_.Get<ArmMmu>();
}

void PeripheralDispatcher::Register(Peripheral* p) {
    if (!p) {
        LOG(Caution, "PeripheralDispatcher::Register called with null\n");
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    const uint32_t base = p->MmioBase();
    const uint32_t size = p->MmioSize();
    const uint32_t end  = base + size;
    if (size == 0) {
        LOG(Caution, "PeripheralDispatcher::Register peripheral has "
                "zero-size MMIO range (base 0x%08X)\n", base);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    for (const auto& e : entries_) {
        if (base < e.end && e.base < end) {
            LOG(Caution, "PeripheralDispatcher::Register overlap: "
                    "new [0x%08X..0x%08X) vs existing [0x%08X..0x%08X)\n",
                    base, end, e.base, e.end);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
    }

    Entry entry{base, end, p->FastReader(), p->FastWriter(), p, p};
    auto pos = std::lower_bound(entries_.begin(), entries_.end(), base,
        [](const Entry& e, uint32_t b) { return e.base < b; });
    entries_.insert(pos, entry);

    if (entries_.size() > 128u) {
        LOG(Caution, "PeripheralDispatcher::Register: more than 128 peripherals "
                "registered — the JIT IO helper's per-emit-site cache slot is a "
                "signed int8 holding the entries_ array index; index space "
                "exhausted.\n");
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }

    LOG(Periph, "Register 0x%08X..0x%08X\n", base, end);
}

bool PeripheralDispatcher::IsPeripheralAddress(uint32_t addr) const {
    return LookupEntry(addr) != nullptr;
}

PeripheralDispatcher::Entry* PeripheralDispatcher::LookupEntry(uint32_t addr) const {
    /* upper_bound finds the first entry whose base > addr. The
       candidate covering addr is the one immediately before it
       (largest base ≤ addr). */
    auto it = std::upper_bound(entries_.begin(), entries_.end(), addr,
        [](uint32_t a, const Entry& e) { return a < e.base; });
    if (it == entries_.begin()) return nullptr;
    --it;
    if (addr >= it->base && addr < it->end) {
        return const_cast<Entry*>(&(*it));
    }
    return nullptr;
}

uint8_t PeripheralDispatcher::ReadByte(uint32_t addr) {
    if (Entry* e = LookupEntry(addr)) {
        return static_cast<uint8_t>(e->read(e->ctx, addr - e->base, 1));
    }
    return emu_.Get<EmulatedMemory>().ReadByte(addr);
}

uint16_t PeripheralDispatcher::ReadHalf(uint32_t addr) {
    if (Entry* e = LookupEntry(addr)) {
        return static_cast<uint16_t>(e->read(e->ctx, addr - e->base, 2));
    }
    return emu_.Get<EmulatedMemory>().ReadHalf(addr);
}

uint32_t PeripheralDispatcher::ReadWord(uint32_t addr) {
    if (Entry* e = LookupEntry(addr)) {
        return e->read(e->ctx, addr - e->base, 4);
    }
    return emu_.Get<EmulatedMemory>().ReadWord(addr);
}

uint64_t PeripheralDispatcher::ReadDword(uint32_t addr) {
    if (Entry* e = LookupEntry(addr)) {
        return e->p->ReadDword(addr);
    }
    return emu_.Get<EmulatedMemory>().ReadDword(addr);
}

void PeripheralDispatcher::WriteByte(uint32_t addr, uint8_t value) {
    if (Entry* e = LookupEntry(addr)) {
        e->write(e->ctx, addr - e->base, value, 1);
        return;
    }
    emu_.Get<EmulatedMemory>().WriteByte(addr, value);
}

void PeripheralDispatcher::WriteHalf(uint32_t addr, uint16_t value) {
    if (Entry* e = LookupEntry(addr)) {
        e->write(e->ctx, addr - e->base, value, 2);
        return;
    }
    emu_.Get<EmulatedMemory>().WriteHalf(addr, value);
}

void PeripheralDispatcher::WriteWord(uint32_t addr, uint32_t value) {
    if (Entry* e = LookupEntry(addr)) {
        e->write(e->ctx, addr - e->base, value, 4);
        return;
    }
    emu_.Get<EmulatedMemory>().WriteWord(addr, value);
}

void PeripheralDispatcher::WriteDword(uint32_t addr, uint64_t value) {
    if (Entry* e = LookupEntry(addr)) {
        e->p->WriteDword(addr, value);
        return;
    }
    emu_.Get<EmulatedMemory>().WriteDword(addr, value);
}

uint8_t __fastcall PeripheralDispatcher::JitIoReadByte(int8_t* hint, PeripheralDispatcher* d) {
#if CERF_DEV_MODE
    const uint64_t t0 = __rdtsc();
#endif
    const uint32_t addr = d->mmu_->io_pending_address() +
                          d->mmu_->io_pending_address_adjust();

    const int8_t cached_index = *hint;
    Entry* entry = &d->entries_[cached_index];

    if (addr < entry->base || addr >= entry->end) {
        entry = d->LookupEntry(addr);
        if (!entry) {
            LOG(Caution, "PeripheralDispatcher::JitIoReadByte: no peripheral "
                    "registered at 0x%08X (pc=0x%08X)\n", addr, d->last_guest_pc_);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        *hint = static_cast<int8_t>(entry - d->entries_.data());
    }

    const uint8_t result =
        static_cast<uint8_t>(entry->read(entry->ctx, addr - entry->base, 1));
#if CERF_DEV_MODE
    auto& probe = d->emu_.Get<RateProbe>();
    probe.RecordMmioPc(d->last_guest_pc_, addr);
    probe.AddTsc(RateProbe::TimeCounter::JitIo, __rdtsc() - t0);
#endif
    return result;
}

uint16_t __fastcall PeripheralDispatcher::JitIoReadHalf(int8_t* hint, PeripheralDispatcher* d) {
#if CERF_DEV_MODE
    const uint64_t t0 = __rdtsc();
#endif
    const uint32_t addr = d->mmu_->io_pending_address() +
                          d->mmu_->io_pending_address_adjust();

    const int8_t cached_index = *hint;
    Entry* entry = &d->entries_[cached_index];

    if (addr < entry->base || addr >= entry->end) {
        entry = d->LookupEntry(addr);
        if (!entry) {
            LOG(Caution, "PeripheralDispatcher::JitIoReadHalf: no peripheral "
                    "registered at 0x%08X (pc=0x%08X)\n", addr, d->last_guest_pc_);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        *hint = static_cast<int8_t>(entry - d->entries_.data());
    }

    const uint16_t result =
        static_cast<uint16_t>(entry->read(entry->ctx, addr - entry->base, 2));
#if CERF_DEV_MODE
    auto& probe = d->emu_.Get<RateProbe>();
    probe.RecordMmioPc(d->last_guest_pc_, addr);
    probe.AddTsc(RateProbe::TimeCounter::JitIo, __rdtsc() - t0);
#endif
    return result;
}

uint32_t __fastcall PeripheralDispatcher::JitIoReadWord(int8_t* hint, PeripheralDispatcher* d) {
#if CERF_DEV_MODE
    const uint64_t t0 = __rdtsc();
#endif
    const uint32_t addr = d->mmu_->io_pending_address() +
                          d->mmu_->io_pending_address_adjust();

    const int8_t cached_index = *hint;
    Entry* entry = &d->entries_[cached_index];

    if (addr < entry->base || addr >= entry->end) {
        entry = d->LookupEntry(addr);
        if (!entry) {
            LOG(Caution, "PeripheralDispatcher::JitIoReadWord: no peripheral "
                    "registered at 0x%08X (pc=0x%08X)\n", addr, d->last_guest_pc_);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        *hint = static_cast<int8_t>(entry - d->entries_.data());
    }

    const uint32_t result = entry->read(entry->ctx, addr - entry->base, 4);
#if CERF_DEV_MODE
    auto& probe = d->emu_.Get<RateProbe>();
    probe.RecordMmioPc(d->last_guest_pc_, addr);
    probe.AddTsc(RateProbe::TimeCounter::JitIo, __rdtsc() - t0);
#endif
    return result;
}

void __fastcall PeripheralDispatcher::JitIoWriteByte(int8_t* hint, PeripheralDispatcher* d, uint8_t value) {
#if CERF_DEV_MODE
    const uint64_t t0 = __rdtsc();
#endif
    const uint32_t addr = d->mmu_->io_pending_address() +
                          d->mmu_->io_pending_address_adjust();

    const int8_t cached_index = *hint;
    Entry* entry = &d->entries_[cached_index];

    if (addr < entry->base || addr >= entry->end) {
        entry = d->LookupEntry(addr);
        if (!entry) {
            LOG(Caution, "PeripheralDispatcher::JitIoWriteByte: no peripheral "
                    "registered at 0x%08X (pc=0x%08X value=0x%08X)\n",
                    addr, d->last_guest_pc_, value);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        *hint = static_cast<int8_t>(entry - d->entries_.data());
    }

    entry->write(entry->ctx, addr - entry->base, value, 1);
#if CERF_DEV_MODE
    auto& probe = d->emu_.Get<RateProbe>();
    probe.RecordMmioPc(d->last_guest_pc_, addr);
    probe.AddTsc(RateProbe::TimeCounter::JitIo, __rdtsc() - t0);
#endif
}

void __fastcall PeripheralDispatcher::JitIoWriteHalf(int8_t* hint, PeripheralDispatcher* d, uint16_t value) {
#if CERF_DEV_MODE
    const uint64_t t0 = __rdtsc();
#endif
    const uint32_t addr = d->mmu_->io_pending_address() +
                          d->mmu_->io_pending_address_adjust();

    const int8_t cached_index = *hint;
    Entry* entry = &d->entries_[cached_index];

    if (addr < entry->base || addr >= entry->end) {
        entry = d->LookupEntry(addr);
        if (!entry) {
            LOG(Caution, "PeripheralDispatcher::JitIoWriteHalf: no peripheral "
                    "registered at 0x%08X (pc=0x%08X value=0x%08X)\n",
                    addr, d->last_guest_pc_, value);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        *hint = static_cast<int8_t>(entry - d->entries_.data());
    }

    entry->write(entry->ctx, addr - entry->base, value, 2);
#if CERF_DEV_MODE
    auto& probe = d->emu_.Get<RateProbe>();
    probe.RecordMmioPc(d->last_guest_pc_, addr);
    probe.AddTsc(RateProbe::TimeCounter::JitIo, __rdtsc() - t0);
#endif
}

void __fastcall PeripheralDispatcher::JitIoWriteWord(int8_t* hint, PeripheralDispatcher* d, uint32_t value) {
#if CERF_DEV_MODE
    const uint64_t t0 = __rdtsc();
#endif
    const uint32_t addr = d->mmu_->io_pending_address() +
                          d->mmu_->io_pending_address_adjust();

    const int8_t cached_index = *hint;
    Entry* entry = &d->entries_[cached_index];

    if (addr < entry->base || addr >= entry->end) {
        entry = d->LookupEntry(addr);
        if (!entry) {
            LOG(Caution, "PeripheralDispatcher::JitIoWriteWord: no peripheral "
                    "registered at 0x%08X (pc=0x%08X value=0x%08X)\n",
                    addr, d->last_guest_pc_, value);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        *hint = static_cast<int8_t>(entry - d->entries_.data());
    }

    entry->write(entry->ctx, addr - entry->base, value, 4);
#if CERF_DEV_MODE
    auto& probe = d->emu_.Get<RateProbe>();
    probe.RecordMmioPc(d->last_guest_pc_, addr);
    probe.AddTsc(RateProbe::TimeCounter::JitIo, __rdtsc() - t0);
#endif
}
