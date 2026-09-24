#pragma once

#include <cstdint>

inline constexpr char    kStateMagic[8]      = {'C','E','R','F','I','M','G','2'};
inline constexpr wchar_t kDefaultStateFile[] = L"state.img";
inline constexpr wchar_t kRollbackStateFile[] = L"rollback.img";

struct StateImageHeader {
    uint32_t rom_entry_va;
    uint32_t periph_layout_sig;
    uint64_t rom_total_bytes;
    uint8_t  guest_additions;
};

enum class StateSection : uint32_t {
    Cpu          = 1,
    Mmu          = 2,
    Ram          = 3,
    Periph       = 4,
    Presentation = 5,
    Flash        = 6,
    Widget       = 7,
    Reset        = 8,
};

inline constexpr StateSection kStateSectionOrder[] = {
    StateSection::Cpu,    StateSection::Mmu,          StateSection::Ram,
    StateSection::Flash,  StateSection::Periph,       StateSection::Presentation,
    StateSection::Widget, StateSection::Reset,
};
