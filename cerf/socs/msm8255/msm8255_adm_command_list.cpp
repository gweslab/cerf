#include "msm8255_adm_command_list.h"

#include "../../boards/board_context.h"
#include "msm8255_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/fatal.h"
#include "../../cpu/physical_bus.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "msm8255_crci_bus.h"

namespace {

constexpr uint32_t kCmdPtrTypeShift = 29u;
constexpr uint32_t kCmdPtrTypeMask  = 3u;
constexpr uint32_t kCmdPtrTypeList  = 0u;

constexpr uint32_t kPtrAddrMask = 0x1FFFFFFFu;
constexpr uint32_t kPtrLast     = 1u << 31;
constexpr uint32_t kPtrType     = 3u << 29;

constexpr uint32_t kCmdLast       = 1u << 31;
constexpr uint32_t kCmdModeMask   = 7u;
constexpr uint32_t kCmdModeSingle = 0u;
constexpr uint32_t kCmdModeBox    = 3u;
constexpr uint32_t kCmdSrcCrci    = 0xFu << 3;
constexpr uint32_t kCmdDstCrci    = 0xFu << 7;
constexpr uint32_t kCmdActed =
    kCmdLast | kCmdModeMask | kCmdSrcCrci | kCmdDstCrci;

constexpr uint32_t kCmdSrcCrciShift = 3u;
constexpr uint32_t kCmdDstCrciShift = 7u;

constexpr uint32_t kMaxPointers = 256u;
constexpr uint32_t kMaxCommands = 1024u;

}  // namespace

REGISTER_SERVICE(Msm8255AdmCommandList);

bool Msm8255AdmCommandList::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetSocId() == SocId::Msm8255;
}

bool Msm8255AdmCommandList::IsModeledCmdPtr(uint32_t value) const {
    const uint32_t type = (value >> kCmdPtrTypeShift) & kCmdPtrTypeMask;
    return type == kCmdPtrTypeList && (value >> 31) == 0u;
}

void Msm8255AdmCommandList::RequireModeledCmdPtr(uint32_t value) {
    const uint32_t type = (value >> kCmdPtrTypeShift) & kCmdPtrTypeMask;
    if (!IsModeledCmdPtr(value)) {
        emu_.Get<Fatal>().Die(
            "msm8255 dmov: command pointer 0x%08X carries type %u with bit 31 "
            "set to %u, and only a type 0 pointer list with bit 31 clear is "
            "modeled", value, type, value >> 31);
    }
}

uint32_t Msm8255AdmCommandList::FirstCrci(uint32_t value) {
    const uint32_t entry = ReadPointerEntry((value & kPtrAddrMask) << 3);
    return CrciOf(BusRead((entry & kPtrAddrMask) << 3));
}

void Msm8255AdmCommandList::Run(uint32_t value, uint32_t crci) {
    uint32_t list = (value & kPtrAddrMask) << 3;
    for (uint32_t i = 0; i < kMaxPointers; ++i) {
        const uint32_t entry = ReadPointerEntry(list);
        RunCommandArray((entry & kPtrAddrMask) << 3, crci);
        if ((entry & kPtrLast) != 0u) return;
        list += 4u;
    }
    emu_.Get<Fatal>().Die(
        "msm8255 dmov: pointer list passed %u entries with no last-pointer "
        "marker", kMaxPointers);
}

uint32_t Msm8255AdmCommandList::BusRead(uint32_t pa) {
    if (emu_.Get<PeripheralDispatcher>().IsPeripheralAddress(pa)) {
        emu_.Get<Fatal>().Die(
            "msm8255 dmov: command list read at 0x%08X reaches a peripheral, "
            "and the client-interface burst width this engine drives is not "
            "modeled", pa);
    }
    uint32_t v = 0;
    if (!emu_.Get<PhysicalBus>().Read(pa, BusWidth::Word, &v)) {
        emu_.Get<Fatal>().Die(
            "msm8255 dmov: command list read at 0x%08X reaches neither memory "
            "nor a peripheral", pa);
    }
    return v;
}

uint32_t Msm8255AdmCommandList::ReadPointerEntry(uint32_t list) {
    const uint32_t entry = BusRead(list);
    if ((entry & kPtrType) != 0u) {
        emu_.Get<Fatal>().Die(
            "msm8255 dmov: pointer entry 0x%08X at 0x%08X carries a pointer "
            "type this engine does not model", entry, list);
    }
    return entry;
}

uint32_t Msm8255AdmCommandList::CrciOf(uint32_t cmd) {
    const uint32_t src = (cmd & kCmdSrcCrci) >> kCmdSrcCrciShift;
    const uint32_t dst = (cmd & kCmdDstCrci) >> kCmdDstCrciShift;
    if (src != 0u && dst != 0u) {
        emu_.Get<Fatal>().Die(
            "msm8255 dmov: command word 0x%08X pauses on a source crci %u and "
            "a destination crci %u at once, and pacing one transfer from two "
            "clients is not modeled", cmd, src, dst);
    }
    return src != 0u ? src : dst;
}

void Msm8255AdmCommandList::Move(uint32_t src, uint32_t dst, uint32_t len,
                                 uint32_t crci) {
    auto& bus   = emu_.Get<PhysicalBus>();
    auto& disp  = emu_.Get<PeripheralDispatcher>();
    auto& lines = emu_.Get<Msm8255CrciBus>();
    const BusWidth w = ((len | src | dst) & 3u) == 0u ? BusWidth::Word
                                                      : BusWidth::Byte;
    const uint32_t step = static_cast<uint32_t>(w);
    for (uint32_t done = 0; done < len; done += step) {
        const uint32_t s = src + done;
        const uint32_t d = dst + done;
        for (const uint32_t p : {s, d}) {
            if (!disp.IsPeripheralAddress(p)) continue;
            if (lines.FifoCovers(crci, p) && w == BusWidth::Word) continue;
            emu_.Get<Fatal>().Die(
                "msm8255 dmov: transfer 0x%08X -> 0x%08X reaches the peripheral "
                "at 0x%08X, which is not the data register the crci %u client "
                "pauses this channel on, and the client-interface burst this "
                "engine drives there is not modeled", s, d, p, crci);
        }
        uint32_t v = 0;
        if (!bus.Read(s, w, &v) || !bus.Write(d, w, v)) {
            emu_.Get<Fatal>().Die(
                "msm8255 dmov: transfer endpoint 0x%08X -> 0x%08X reaches "
                "neither memory nor a peripheral", s, d);
        }
    }
}

void Msm8255AdmCommandList::MoveBox(uint32_t src, uint32_t dst,
                                    uint32_t len_word, uint32_t rows_word,
                                    uint32_t off_word, uint32_t pa,
                                    uint32_t crci) {
    const uint32_t src_len  = len_word >> 16;
    const uint32_t dst_len  = len_word & 0xFFFFu;
    const uint32_t src_rows = rows_word >> 16;
    const uint32_t dst_rows = rows_word & 0xFFFFu;
    if (src_len != dst_len || src_rows != dst_rows) {
        emu_.Get<Fatal>().Die(
            "msm8255 dmov: box command at 0x%08X carries unequal source and "
            "destination geometry (len 0x%08X rows 0x%08X), and the re-blocking "
            "this engine performs is not modeled", pa, len_word, rows_word);
    }
    const uint32_t src_off = off_word >> 16;
    const uint32_t dst_off = off_word & 0xFFFFu;
    for (uint32_t row = 0; row < src_rows; ++row) {
        Move(src + src_off * row, dst + dst_off * row, src_len, crci);
    }
}

void Msm8255AdmCommandList::RunCommandArray(uint32_t pa, uint32_t crci) {
    for (uint32_t i = 0; i < kMaxCommands; ++i) {
        const uint32_t cmd  = BusRead(pa);
        const uint32_t mode = cmd & kCmdModeMask;
        if (mode != kCmdModeSingle && mode != kCmdModeBox) {
            emu_.Get<Fatal>().Die(
                "msm8255 dmov: command at 0x%08X selects transfer mode %u, "
                "whose descriptor layout is not modeled", pa, mode);
        }
        if ((cmd & ~kCmdActed) != 0u) {
            emu_.Get<Fatal>().Die(
                "msm8255 dmov: command word 0x%08X at 0x%08X carries fields "
                "outside the mode and last-command set this engine acts on",
                cmd, pa);
        }
        const uint32_t cmd_crci = CrciOf(cmd);
        if (cmd_crci != crci) {
            emu_.Get<Fatal>().Die(
                "msm8255 dmov: command at 0x%08X pauses on crci %u while this "
                "channel was paced on crci %u, and re-pacing inside one command "
                "list is not modeled", pa, cmd_crci, crci);
        }
        const uint32_t src = BusRead(pa + 4u);
        const uint32_t dst = BusRead(pa + 8u);
        if (mode == kCmdModeBox) {
            MoveBox(src, dst, BusRead(pa + 12u), BusRead(pa + 16u),
                    BusRead(pa + 20u), pa, crci);
            pa += 24u;
        } else {
            Move(src, dst, BusRead(pa + 12u), crci);
            pa += 16u;
        }
        if ((cmd & kCmdLast) != 0u) return;
    }
    emu_.Get<Fatal>().Die(
        "msm8255 dmov: command array passed %u entries with no last-command "
        "marker", kMaxCommands);
}
