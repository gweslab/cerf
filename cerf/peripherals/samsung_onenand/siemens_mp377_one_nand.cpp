#include "../../peripherals/peripheral_base.h"

#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../state/state_stream.h"
#include "../../socs/guest_cpu_reset.h"
#include "../../boards/board_context.h"
#include "../../boards/siemens_mp377/siemens_mp377_id.h"

#include <algorithm>
#include <array>
#include <cstring>
#include <vector>

/* MP377 mainboard markings: two KFG1G16U2D; Samsung KFG1G16U2B-DIB6
   specification rev. 1.2, sections 2.8.3/2.8.13; siemens_mp377_v1040
   TFFS3.dll sub_2BD27B0/sub_2BD2C14/sub_2BD3260. */

namespace {

constexpr size_t kPageMain = 4096;
constexpr size_t kPageSpare = 128;
constexpr size_t kPagesBlock = 64;
constexpr size_t kStorageBlocks = 1024;
constexpr size_t kBackingSize = kStorageBlocks * kPagesBlock * kPageMain;
constexpr size_t kSpareSize = kStorageBlocks * kPagesBlock * kPageSpare;

constexpr uint32_t kDataRam0 = 0x0800u;
constexpr uint32_t kDataRam1 = 0x1800u;
constexpr uint32_t kBufferRamEnd = 0x20000u;
constexpr uint32_t kSpareRamBase = 0x20000u;
constexpr uint32_t kSpareRamEnd = kSpareRamBase + static_cast<uint32_t>(kPageSpare);
constexpr uint32_t kBootStateMirrorBase = 0x3FF00u;
constexpr uint32_t kBootStateMirrorEnd = 0x40000u;
constexpr size_t kBootStateMirrorSize = kBootStateMirrorEnd - kBootStateMirrorBase;
constexpr uint16_t kManufacturerId = 0x00ECu;
constexpr uint16_t kDeviceId = 0x0035u;
constexpr uint16_t kDataBufferSizeWords = 0x0800u;
constexpr uint16_t kBootBufferSizeWords = 0x0200u;
constexpr uint16_t kBufferAmount = 0x0201u;
constexpr uint16_t kTechnology = 0x0000u;

class SiemensMp377OneNand : public Peripheral {
public:
    using Peripheral::Peripheral;

    bool ShouldRegister() override {
        auto* bd = emu_.TryGet<BoardContext>();
        return bd && bd->GetBoardId() == BoardId::SiemensMp377;
    }
    void OnReady() override {
        backing_.assign(kBackingSize, uint8_t{0xFFu});
        spare_.assign(kSpareSize, uint8_t{0xFFu});
        ResetInterface();
        emu_.Get<GuestCpuReset>().RegisterResetListener([this](ResetLineKind) {
            if (!emu_.Get<GuestCpuReset>().DeliveredResetWasResume()) ResetInterface();
        });
        emu_.Get<PeripheralDispatcher>().Register(this);
    }

    void ResetInterface() {
        data_ram_.fill(uint8_t{0xFFu});
        spare_ram_.fill(uint8_t{0xFFu});
        boot_state_mirror_.fill(uint8_t{0xFFu});
        block_unlocked_.fill(uint8_t{0});
        start_addr_1_ = start_addr_2_ = start_addr_3_ = start_addr_4_ = 0u;
        start_addr_5_ = start_addr_6_ = start_addr_7_ = start_addr_8_ = 0u;
        start_buffer_ = 0x0800u;
        sys_cfg_ = 0x40C0u;
        ctrl_status_ = 0u;
        interrupt_status_ = 0x8080u;
        unlock_start_ = unlock_end_ = 0u;
        last_cmd_ = 0u;
    }

    uint32_t MmioBase() const override { return 0xD0200000u; }
    uint32_t MmioSize() const override { return 0x00080000u; }

    uint8_t ReadByte(uint32_t addr) override {
        const uint32_t off = DecodeOffset(addr);
        if (off < kBufferRamEnd) return data_ram_[off];
        if (off >= kSpareRamBase && off < kSpareRamEnd) return spare_ram_[off - kSpareRamBase];
        if (off >= kBootStateMirrorBase && off < kBootStateMirrorEnd)
            return boot_state_mirror_[off - kBootStateMirrorBase];
        const uint16_t h = ReadHalf(addr & ~uint32_t{1});
        return static_cast<uint8_t>((addr & 1u) ? (h >> 8) : h);
    }
    uint16_t ReadHalf(uint32_t addr) override {
        const uint32_t off = DecodeOffset(addr);
        if (off < kBufferRamEnd)
            return cerf::le::U16(data_ram_.data(), off & ~uint32_t{1});
        if (off >= kSpareRamBase && off < kSpareRamEnd)
            return cerf::le::U16(spare_ram_.data(), (off - kSpareRamBase) & ~uint32_t{1});
        if (off >= kBootStateMirrorBase && off < kBootStateMirrorEnd)
            return cerf::le::U16(boot_state_mirror_.data(), (off - kBootStateMirrorBase) & ~uint32_t{1});
        /* siemens_mp377_v1040 TFFS3.dll sub_2BD2740; Samsung OneNAND
           ECC Status Register 0, chip word 0xFF00. */
        if (off == 0x3FC00u || off == 0x3FC02u) return 0;
        if (off >= 0x3C000u && off < 0x3D000u) return RegRead16(off);
        HaltUnsupportedAccess("OneNAND halfword read outside modelled RAM/registers", addr, off);
    }
    uint32_t ReadWord(uint32_t addr) override {
        const uint16_t lo = ReadHalf(addr);
        const uint16_t hi = ReadHalf(addr + 2);
        return static_cast<uint32_t>(lo) | (static_cast<uint32_t>(hi) << 16);
    }
    void WriteByte(uint32_t addr, uint8_t v) override {
        const uint32_t off = DecodeOffset(addr);
        if (off < kBufferRamEnd) {
            data_ram_[off] = v;
            return;
        }
        if (off >= kSpareRamBase && off < kSpareRamEnd) {
            spare_ram_[off - kSpareRamBase] = v;
            return;
        }
        if (off >= kBootStateMirrorBase && off < kBootStateMirrorEnd) {
            boot_state_mirror_[off - kBootStateMirrorBase] = v;
            return;
        }
        HaltUnsupportedAccess("OneNAND byte write outside RAM", addr, v);
    }
    void WriteHalf(uint32_t addr, uint16_t v) override {
        const uint32_t off = DecodeOffset(addr);
        if (off < kBufferRamEnd) {
            cerf::le::Put16(data_ram_.data() + (off & ~uint32_t{1}), v);
            return;
        }
        if (off >= kSpareRamBase && off < kSpareRamEnd) {
            cerf::le::Put16(spare_ram_.data() + ((off - kSpareRamBase) & ~uint32_t{1}), v);
            return;
        }
        if (off >= kBootStateMirrorBase && off < kBootStateMirrorEnd) {
            cerf::le::Put16(boot_state_mirror_.data() + ((off - kBootStateMirrorBase) & ~uint32_t{1}), v);
            return;
        }
        RegWrite16(off, v);
    }
    void WriteWord(uint32_t addr, uint32_t v) override {
        WriteHalf(addr, static_cast<uint16_t>(v & 0xFFFFu));
        WriteHalf(addr + 2, static_cast<uint16_t>((v >> 16) & 0xFFFFu));
    }

    void SaveState(StateWriter& w) override {
        w.WriteBytes("backing", backing_.data(), backing_.size());
        w.WriteBytes("spare", spare_.data(), spare_.size());
        w.WriteBytes("data_ram", data_ram_.data(), data_ram_.size());
        w.WriteBytes("spare_ram", spare_ram_.data(), spare_ram_.size());
        w.WriteBytes("boot_state_mirror", boot_state_mirror_.data(), boot_state_mirror_.size());
        w.Write("start_addr_1", start_addr_1_);
        w.Write("start_addr_2", start_addr_2_);
        w.Write("start_addr_3", start_addr_3_);
        w.Write("start_addr_4", start_addr_4_);
        w.Write("start_addr_5", start_addr_5_);
        w.Write("start_addr_6", start_addr_6_);
        w.Write("start_addr_7", start_addr_7_);
        w.Write("start_addr_8", start_addr_8_);
        w.Write("start_buffer", start_buffer_);
        w.Write("sys_cfg", sys_cfg_);
        w.Write("ctrl_status", ctrl_status_);
        w.Write("interrupt_status", interrupt_status_);
        w.Write("unlock_start", unlock_start_);
        w.Write("unlock_end", unlock_end_);
        w.WriteBytes("block_unlocked", block_unlocked_.data(), block_unlocked_.size());
        w.Write("last_cmd", last_cmd_);
    }

    void RestoreState(StateReader& r) override {
        r.ReadBytes("backing", backing_.data(), backing_.size());
        r.ReadBytes("spare", spare_.data(), spare_.size());
        r.ReadBytes("data_ram", data_ram_.data(), data_ram_.size());
        r.ReadBytes("spare_ram", spare_ram_.data(), spare_ram_.size());
        r.ReadBytes("boot_state_mirror", boot_state_mirror_.data(), boot_state_mirror_.size());
        r.Read("start_addr_1", start_addr_1_);
        r.Read("start_addr_2", start_addr_2_);
        r.Read("start_addr_3", start_addr_3_);
        r.Read("start_addr_4", start_addr_4_);
        r.Read("start_addr_5", start_addr_5_);
        r.Read("start_addr_6", start_addr_6_);
        r.Read("start_addr_7", start_addr_7_);
        r.Read("start_addr_8", start_addr_8_);
        r.Read("start_buffer", start_buffer_);
        r.Read("sys_cfg", sys_cfg_);
        r.Read("ctrl_status", ctrl_status_);
        r.Read("interrupt_status", interrupt_status_);
        r.Read("unlock_start", unlock_start_);
        r.Read("unlock_end", unlock_end_);
        r.ReadBytes("block_unlocked", block_unlocked_.data(), block_unlocked_.size());
        r.Read("last_cmd", last_cmd_);
    }

    static constexpr uint32_t kOneNandAliasStride = 0x00040000u;

    uint32_t DecodeOffset(uint32_t addr) const {
        const uint32_t off = addr - MmioBase();
        return off >= kOneNandAliasStride ? off - kOneNandAliasStride : off;
    }

private:
    /* Page index in the backing array: linear page number computed from
       Start Address 1 (block) + Start Address 8 (page-in-block). sub_2BD2C14
       writes SA8 as ((page << 2) | 1), replicated across both halfwords. */
    size_t PageIndex() const {
        const uint16_t block_no = start_addr_1_;
        const uint16_t page_no = static_cast<uint16_t>((start_addr_8_ >> 2) & 0x003Fu);
        return (size_t)block_no * kPagesBlock + (size_t)page_no;
    }
    size_t BlockIndex() const { return start_addr_1_; }
    uint32_t SelectedDataRamOffset() const { return ((start_buffer_ & 0x0FFFu) == 0x0C00u) ? kDataRam1 : kDataRam0; }

    void RunCommand(uint16_t cmd) {
        const uint8_t cmd8 = static_cast<uint8_t>(cmd & uint8_t{0xFFu});
        bool main_ok = true;
        bool spare_ok = true;
        ctrl_status_ = 0;
        switch (cmd8) {
        case 0x00:
        case 0x13: {
            const size_t pi = PageIndex();
            const size_t main_off = pi * kPageMain;
            const size_t spare_off = pi * kPageSpare;
            const uint32_t ram = SelectedDataRamOffset();
            std::fill(data_ram_.begin() + ram, data_ram_.begin() + ram + kPageMain, uint8_t{0xFFu});
            spare_ram_.fill(uint8_t{0xFFu});
            main_ok = main_off + kPageMain <= backing_.size();
            spare_ok = spare_off + kPageSpare <= spare_.size();
            if (main_ok) {
                std::memcpy(&data_ram_[ram], &backing_[main_off], kPageMain);
            }
            if (spare_ok) {
                std::memcpy(spare_ram_.data(), &spare_[spare_off], kPageSpare);
            }
            break;
        }
        case 0x1A: {
            const size_t pi = PageIndex();
            const size_t spare_off = pi * kPageSpare;
            spare_ok = spare_off + kPageSpare <= spare_.size() && BlockIndex() < block_unlocked_.size() &&
                       block_unlocked_[BlockIndex()];
            main_ok = true;
            if (spare_ok) {
                ProgramBytes(&spare_[spare_off], spare_ram_.data(), kPageSpare);
            }
            break;
        }
        case 0x80: {
            const size_t pi = PageIndex();
            const size_t main_off = pi * kPageMain;
            const uint32_t ram = SelectedDataRamOffset();
            main_ok = main_off + kPageMain <= backing_.size() && BlockIndex() < block_unlocked_.size() &&
                      block_unlocked_[BlockIndex()];
            spare_ok = true;
            if (main_ok) {
                ProgramBytes(&backing_[main_off], &data_ram_[ram], kPageMain);
            }
            break;
        }
        case 0x94: {
            const size_t bi = BlockIndex();
            const size_t mb = bi * kPagesBlock * kPageMain;
            const size_t sb = bi * kPagesBlock * kPageSpare;
            const size_t mlen = kPagesBlock * kPageMain;
            const size_t slen = kPagesBlock * kPageSpare;
            const bool unlocked = bi < block_unlocked_.size() && block_unlocked_[bi];
            main_ok = mb + mlen <= backing_.size() && unlocked;
            spare_ok = sb + slen <= spare_.size() && unlocked;
            if (main_ok) std::fill(backing_.begin() + mb, backing_.begin() + mb + mlen, uint8_t{0xFFu});
            if (spare_ok) std::fill(spare_.begin() + sb, spare_.begin() + sb + slen, uint8_t{0xFFu});
            break;
        }
        case 0x23: {
            main_ok = unlock_start_ <= unlock_end_ && unlock_end_ < block_unlocked_.size();
            spare_ok = main_ok;
            if (main_ok) {
                block_unlocked_.fill(uint8_t{0});
                std::fill(block_unlocked_.begin() + unlock_start_, block_unlocked_.begin() + unlock_end_ + 1u,
                          uint8_t{1});
            }
            break;
        }
        case 0xF0: break;
        default: HaltUnsupportedAccess("OneNAND unknown command", MmioBase() + 0x3C880u, cmd8);
        }
        last_cmd_ = cmd8;
        if (!main_ok || !spare_ok) ctrl_status_ = 0x0400u;
        interrupt_status_ = CompletionLow();
    }

    /* siemens_mp377_v1040 TFFS3.dll sub_2BD2C14/sub_2BD2B08,
       Controller Status Register chip word 0xF241. */
    uint16_t CompletionLow() const {
        switch (last_cmd_) {
        case 0x00:
        case 0x13: return 0x8080u;
        case 0x1A:
        case 0x80: return 0x8040u;
        case 0x94: return 0x8020u;
        case 0x23: return 0x8000u;
        case 0xF0: return 0x8010u;
        default: HaltUnsupportedAccess("OneNAND completion for unknown command", MmioBase() + 0x3C904u, last_cmd_);
        }
    }
    uint16_t WriteProtectionStatus() const {
        return unlock_start_ < block_unlocked_.size() && block_unlocked_[unlock_start_] ? 0x0004u : 0x0002u;
    }

    static void ProgramBytes(uint8_t* dst, const uint8_t* src, size_t count) {
        /* Samsung KFG1G16U2B-DIB6 specification §2.8.13: programming only
           changes array bits from 1 to 0. */
        for (size_t i = 0; i < count; ++i)
            dst[i] &= src[i];
    }

    uint16_t RegRead16(uint32_t off) {
        switch (off) {
        case 0x3C000u:
        case 0x3C002u: return kManufacturerId;
        case 0x3C004u:
        case 0x3C006u: return kDeviceId;
        case 0x3C008u:
        case 0x3C00Au:
            HaltUnsupportedAccess("OneNAND reserved Version ID register read", MmioBase() + off, off);
        case 0x3C00Cu:
        case 0x3C00Eu: return kDataBufferSizeWords;
        case 0x3C010u:
        case 0x3C012u: return kBootBufferSizeWords;
        case 0x3C014u:
        case 0x3C016u: return kBufferAmount;
        case 0x3C018u:
        case 0x3C01Au: return kTechnology;
        case 0x3C400u:
        case 0x3C402u: return start_addr_1_;
        case 0x3C404u:
        case 0x3C406u: return start_addr_2_;
        case 0x3C408u:
        case 0x3C40Au: return start_addr_3_;
        case 0x3C40Cu:
        case 0x3C40Eu: return start_addr_4_;
        case 0x3C410u:
        case 0x3C412u: return start_addr_5_;
        case 0x3C414u:
        case 0x3C416u: return start_addr_6_;
        case 0x3C418u:
        case 0x3C41Au: return start_addr_7_;
        case 0x3C41Cu:
        case 0x3C41Eu: return start_addr_8_;
        case 0x3C800u:
        case 0x3C802u: return start_buffer_;
        case 0x3C880u:
        case 0x3C882u: return last_cmd_;
        case 0x3C884u:
        case 0x3C886u: return sys_cfg_;
        case 0x3C900u:
        case 0x3C902u: return ctrl_status_;
        case 0x3C904u:
        case 0x3C906u: return interrupt_status_;
        case 0x3C930u:
        case 0x3C932u: return unlock_start_;
        case 0x3C934u:
        case 0x3C936u: return unlock_end_;
        case 0x3C938u:
        case 0x3C93Au: return WriteProtectionStatus();
        default: HaltUnsupportedAccess("OneNAND unknown register read", MmioBase() + off, 0);
        }
    }
    void RegWrite16(uint32_t off, uint16_t v) {
        switch (off) {
        case 0x3C400u: start_addr_1_ = v; break;
        case 0x3C404u: start_addr_2_ = v; break;
        case 0x3C408u: start_addr_3_ = v; break;
        case 0x3C40Cu: start_addr_4_ = v; break;
        case 0x3C410u: start_addr_5_ = v; break;
        case 0x3C414u: start_addr_6_ = v; break;
        case 0x3C418u: start_addr_7_ = v; break;
        case 0x3C41Cu: start_addr_8_ = v; break;
        case 0x3C800u: start_buffer_ = v; break;
        case 0x3C880u: RunCommand(v); break;
        case 0x3C884u: sys_cfg_ = v; break;
        case 0x3C904u: interrupt_status_ &= v; break;
        case 0x3C930u: unlock_start_ = v; break;
        case 0x3C934u: unlock_end_ = v; break;
        case 0x3C002u:
        case 0x3C006u:
        case 0x3C00Au:
        case 0x3C00Eu:
        case 0x3C012u:
        case 0x3C01Au:
        case 0x3C402u:
        case 0x3C406u:
        case 0x3C40Au:
        case 0x3C40Eu:
        case 0x3C412u:
        case 0x3C416u:
        case 0x3C41Au:
        case 0x3C41Eu:
        case 0x3C802u:
        case 0x3C882u:
        case 0x3C886u:
        case 0x3C906u:
        case 0x3C932u:
        case 0x3C936u: break;
        default: HaltUnsupportedAccess("OneNAND unknown register write", MmioBase() + off, v);
        }
    }

    std::vector<uint8_t> backing_;
    std::vector<uint8_t> spare_;
    std::array<uint8_t, kBufferRamEnd> data_ram_{};
    std::array<uint8_t, kPageSpare> spare_ram_{};
    std::array<uint8_t, kBootStateMirrorSize> boot_state_mirror_{};
    uint16_t start_addr_1_ = 0;
    uint16_t start_addr_2_ = 0;
    uint16_t start_addr_3_ = 0;
    uint16_t start_addr_4_ = 0;
    uint16_t start_addr_5_ = 0;
    uint16_t start_addr_6_ = 0;
    uint16_t start_addr_7_ = 0;
    uint16_t start_addr_8_ = 0;
    uint16_t start_buffer_ = 0x0800;
    std::array<uint8_t, kStorageBlocks> block_unlocked_{};
    uint16_t sys_cfg_ = 0x40C0u;
    uint16_t ctrl_status_ = 0;
    uint16_t interrupt_status_ = 0x8080u;
    uint16_t unlock_start_ = 0;
    uint16_t unlock_end_ = 0;
    uint8_t last_cmd_ = 0;
};

} /* namespace */

REGISTER_SERVICE(SiemensMp377OneNand);
