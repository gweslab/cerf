#include "siemens_mp377_ertec400_fdb.h"

#include "siemens_mp377_ertec400.h"
#include "siemens_mp377_ertec400_model.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"

bool SiemensMp377Ertec400Fdb::ShouldRegister() {
    auto* board = emu_.TryGet<BoardContext>();
    return board && board->GetBoard() == Board::SiemensMP377;
}

uint32_t SiemensMp377Ertec400Fdb::ExecutePrimary(uint32_t value) {
    using namespace siemens_mp377;
    Fatal& fatal = emu_.Get<Fatal>();
    if ((value & kErtecSerCommandActiveBit) == 0u) {
        fatal.Die("ERTEC400 SER primary command without active bit: 0x%08X", value);
    }

    const uint32_t function = (value >> 25u) & 0x1Fu;
    const uint32_t mode = (value >> 22u) & 0x07u;
    const uint32_t parameter = value & kErtecSerResultMask;
    switch (function) {
    case 0u:
        if (mode != 1u || parameter != 0u) {
            fatal.Die("ERTEC400 unsupported SER start command 0x%08X", value);
        }
        Clear();
        return 0u;
    case 2u:
        if (mode != 1u || parameter != 0x00007FFFu) {
            fatal.Die("ERTEC400 unsupported SER schedule command 0x%08X", value);
        }
        return 0u;
    case 9u:
        if (mode != 1u) {
            fatal.Die("ERTEC400 unsupported SER FDB reservation mode in 0x%08X",
                      value);
        }
        return Reserve(parameter);
    case 12u:
        if (mode != 1u) {
            fatal.Die("ERTEC400 unsupported SER FDB publication mode in 0x%08X",
                      value);
        }
        Publish(parameter);
        return 0u;
    default:
        fatal.Die("ERTEC400 unsupported SER primary command 0x%08X", value);
    }
}

void SiemensMp377Ertec400Fdb::Clear() {
    using namespace siemens_mp377;
    SiemensMp377Ertec400Model& model = emu_.Get<SiemensMp377Ertec400Model>();
    Fatal& fatal = emu_.Get<Fatal>();
    uint32_t base = 0u;
    uint32_t last_index = 0u;
    if (!model.GetWord(kErtecSerFdbBaseOffset, base) ||
        !model.GetWord(kErtecSerFdbLastIndexOffset, last_index)) {
        fatal.Die("ERTEC400 SER start before FDB configuration");
    }
    const uint64_t end = static_cast<uint64_t>(base) +
                         static_cast<uint64_t>(last_index) * 8u + 8u;
    if (base < kErtecCommunicationRamBase ||
        end > static_cast<uint64_t>(kErtecCommunicationRamBase) +
                  kErtecCommunicationRamSize) {
        fatal.Die("ERTEC400 invalid FDB range base=0x%X last=0x%X", base,
                  last_index);
    }
    for (uint32_t index = 0u; index <= last_index; ++index) {
        const uint32_t entry = base + index * 8u;
        model.SetWord(entry, 0u);
        model.SetWord(entry + 4u, 0u);
    }
}

uint32_t SiemensMp377Ertec400Fdb::Reserve(uint32_t parameter) {
    using namespace siemens_mp377;
    SiemensMp377Ertec400Model& model = emu_.Get<SiemensMp377Ertec400Model>();
    Fatal& fatal = emu_.Get<Fatal>();
    uint32_t base = 0u;
    uint32_t last_index = 0u;
    uint32_t search_limit = 0u;
    if (!model.GetWord(kErtecSerFdbBaseOffset, base) ||
        !model.GetWord(kErtecSerFdbLastIndexOffset, last_index) ||
        !model.GetWord(kErtecSerFdbSearchLimitOffset, search_limit)) {
        fatal.Die("ERTEC400 FDB reservation before table configuration");
    }
    if ((parameter & 7u) != 0u || parameter / 8u > last_index) {
        fatal.Die("ERTEC400 invalid FDB reservation parameter 0x%X", parameter);
    }

    uint32_t index = parameter / 8u;
    for (uint32_t probe = 0u; probe <= search_limit; ++probe) {
        const uint32_t entry = base + index * 8u;
        uint32_t control = 0u;
        if (!model.GetWord(entry, control)) {
            fatal.Die("ERTEC400 missing FDB entry at KRAM offset 0x%X", entry);
        }
        if ((control & kErtecSerFdbReservedBit) == 0u) {
            model.SetWord(entry, control | kErtecSerFdbReservedBit);
            return entry;
        }
        index = index == last_index ? 0u : index + 1u;
    }
    return kErtecSerNoFdbEntry;
}

void SiemensMp377Ertec400Fdb::Publish(uint32_t parameter) {
    using namespace siemens_mp377;
    SiemensMp377Ertec400Model& model = emu_.Get<SiemensMp377Ertec400Model>();
    Fatal& fatal = emu_.Get<Fatal>();
    uint32_t base = 0u;
    uint32_t last_index = 0u;
    if (!model.GetWord(kErtecSerFdbBaseOffset, base) ||
        !model.GetWord(kErtecSerFdbLastIndexOffset, last_index)) {
        fatal.Die("ERTEC400 FDB publication before table configuration");
    }
    if ((parameter & 7u) != 0u || parameter / 8u > last_index) {
        fatal.Die("ERTEC400 invalid FDB publication parameter 0x%X", parameter);
    }
    const uint32_t entry = base + parameter;
    uint32_t control = 0u;
    if (!model.GetWord(entry, control) ||
        (control & (kErtecSerFdbReservedBit | kErtecSerFdbValidBit)) !=
            (kErtecSerFdbReservedBit | kErtecSerFdbValidBit)) {
        fatal.Die("ERTEC400 publication of invalid FDB entry at KRAM offset 0x%X",
                  entry);
    }
}

REGISTER_SERVICE(SiemensMp377Ertec400Fdb);
