#pragma once

#include <cstdint>

/* On-disk header at the start of every state image (.img). Written and
   validated by the Hibernation orchestrator via StateWriter/StateReader. */

inline constexpr char     kStateMagic[8]      = {'C','E','R','F','I','M','G','1'};
inline constexpr uint32_t kStateFormatVersion = 16;

inline constexpr wchar_t  kDefaultStateFile[] = L"state.img";

#pragma pack(push, 1)
struct StateImageHeader {
    char     magic[8];          /* kStateMagic */
    uint32_t format_version;    /* kStateFormatVersion */
    /* Lightweight ROM fingerprint + peripheral-layout signature. Restore
       refuses a mismatch before touching live state - a foreign ROM's RAM
       and registers describe a different machine, and a peripheral set
       saved by an incompatible build cannot be replayed in order. */
    uint32_t rom_entry_va;      /* primary partition entry VA */
    uint32_t periph_layout_sig; /* hash of ordered peripheral MmioBases + count */
    uint64_t rom_total_bytes;   /* sum of every loaded partition's raw size */
    /* Guest Additions inject a different display driver + cerf_virt host
       peripheral set, so a GA image and a stock image describe different
       machines; restore refuses a mode mismatch. */
    uint8_t  guest_additions;   /* 1 if saved under --guest-additions, else 0 */
};
#pragma pack(pop)

static_assert(sizeof(StateImageHeader) == 29, "StateImageHeader is an on-disk layout");

/* The image body is a sequence of length-framed sections so a partial
   restore (warm boot applies only Ram) can skip the others, and an
   unknown future section can be skipped by length. */
enum class StateSection : uint32_t {
    Cpu          = 1,
    Mmu          = 2,
    Ram          = 3,
    Periph       = 4,
    /* Host guest-surface dimensions, so a restore re-sizes the window to the
       saved display mode (both GA and stock modes publish them to HostCanvas).
       Full restore only - a warm boot's rebooting OS re-asserts its own mode. */
    Presentation = 5,
    /* Backed flash regions (guest NOR/NAND writes). Applied on warm boot too -
       flash survives a reboot on real hardware. */
    Flash        = 6,
    /* Host-widget state that drives guest-visible hardware (the battery
       widget's charge level / AC, which a board service feeds into GPIO/MCU
       lines the CE driver reads). Full restore only - a warm boot re-asserts
       it when the board service re-drives at startup. */
    Widget       = 7,
    Reset        = 8,
};

#pragma pack(push, 1)
struct StateSectionHeader {
    uint32_t id;       /* StateSection */
    uint64_t length;   /* body bytes following this header */
};
#pragma pack(pop)

static_assert(sizeof(StateSectionHeader) == 12, "StateSectionHeader is an on-disk layout");
