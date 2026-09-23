#include "imx51_nand_layout.h"

#include "../../boards/board_context.h"
#include "imx51_id.h"
#include "../../boot/sec_flash.h"
#include "../../core/byte_order.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"

#include <algorithm>
#include <array>
#include <cstdint>

REGISTER_SERVICE(Imx51NandLayout);

namespace {

/* flash-0x0 config block: magic word + per-module records from +0x60, stride 0x30
   ({delim, id@+4, size@+0xC}); the same structure SBOOT reads via its DPS lookup
   (Bootloader.bin 0x8FF0D63C). */
constexpr uint32_t kCfgMagic  = 0x400DB1B1u;
constexpr uint32_t kRecDelim  = 0xC001C000u;
constexpr uint32_t kRecBase   = 0x60u;
constexpr uint32_t kRecStride = 0x30u;
/* New-format DPS signature: SBOOT's new DPS_Read (0x8FF0DFBC) accepts 0x400BD8D8
   directly (0x8FF0E198); the old config magic 0x400DB1B1 is treated as "old"
   (0x8FF0E1D8) -> DPS_Write upgrade, which read-only `.sec` NAND cannot service. */
constexpr uint32_t kDpsMagicNew = 0x400BD8D8u;

/* DPS "Write Complete" pair (flasher staged_80040000.bin 0x8005A710/0x8005A718).
   SBOOT launches the OS only if [0x3C]!=0 (0x8FF0B858, else "image was partially
   programmed"); the `.sec` config is 0 there, so the synthesized DPS asserts it. */
constexpr size_t kDpsProgStatusA = 0x38u;
constexpr size_t kDpsProgStatusB = 0x3Cu;

/* Bootloader version at DPS[0x28]: SBOOT matches the low 24 bits against the IPL
   (0x8FF0BC30, else "_NOT_ matched." -> emergency); the IPL reports 0xAB000002
   (handler 0x8FF052E8) and the `.sec` config is 0. */
constexpr size_t   kDpsBootVerOff = 0x28u;
constexpr uint32_t kDpsBootVersion = 0xAB000002u;

/* Bad Block Table signature (DPS_ReadBadBlockTable 0x8FF0D7D0, search 0x8FF0D71C). */
constexpr uint32_t kBbtMagic  = 0xB041D283u;
constexpr uint64_t kPageBytes = 0x1000u;

/* Written-page marker in the NFC spare buffer: SBOOT's assembler (0x8FF09424) reads
   copied-index 156, which the 0x40 NFC chunk stride (copy at 0x8FF090F0) maps to NFC
   spare offset 6*0x40 = 0x180; meta[0]=0x00 marks the page written. */
constexpr size_t   kBbtMetaSpareOff = 0x180u;

using cerf::le::Put32;
using cerf::le::U32;

void Wr32(uint8_t* p, size_t off, size_t len, uint32_t v) {
    if (off + 4 > len) return;
    Put32(p + off, v);
}

}  /* namespace */

bool Imx51NandLayout::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    if (!bd || bd->GetSocId() != SocId::Imx51) return false;
    auto* sf = emu_.TryGet<SecFlash>();
    return sf && sf->IsPresent();
}

void Imx51NandLayout::OnReady() {
    device_blocks_ = kDeviceBytes / kBlock;
    auto& sf = emu_.Get<SecFlash>();

    std::array<uint8_t, kRecBase + kRecStride * 16> cfg{};
    sf.ReadFlash(0, cfg.data(), cfg.size());
    if (U32(cfg.data()) != kCfgMagic) {
        LOG(Caution, "Imx51NandLayout: flash-0x0 config magic mismatch (0x%08X)\n",
            U32(cfg.data()));
        return;
    }

    /* Walk the module records {delim, id@+4, size@+0xC}, assigning each a
       cumulative ceil(size/block) block span (manifest order). The `.sec` packs
       the modules by size: the config/IPL region is `.sec` 0x0..kBootRegion and
       every later module follows by size from kBootRegion. */
    uint64_t start_block = 0;
    uint64_t sec_off     = kBootRegion;
    for (uint32_t i = 0; i < 16; ++i) {
        const uint8_t* rec = cfg.data() + kRecBase + i * kRecStride;
        if (U32(rec) != kRecDelim) break;
        const uint32_t id   = U32(rec + 4);
        if (id == 0xFFu) break;
        const uint64_t size = U32(rec + 0xC);

        Part p{};
        p.id          = id;
        p.start_block = start_block;
        if (id == 0) {
            /* The config record covers the whole boot region (config + IPL stub),
               .sec 0x0..kBootRegion, so block 0 reads serve the stub bytes. */
            p.sec_off = 0;
            p.size    = kBootRegion;
        } else {
            p.sec_off = sec_off;
            p.size    = size;
            sec_off  += size;
        }
        p.nblocks    = (p.size + kBlock - 1) / kBlock;
        if (p.nblocks == 0) p.nblocks = 1;
        start_block += p.nblocks;
        parts_.push_back(p);

        LOG(SocNand, "Imx51NandLayout: id=0x%X block %llu (x%llu) -> .sec 0x%llX size 0x%llX\n",
            p.id, static_cast<unsigned long long>(p.start_block),
            static_cast<unsigned long long>(p.nblocks),
            static_cast<unsigned long long>(p.sec_off),
            static_cast<unsigned long long>(p.size));
    }

    /* Record the id-6 OS-region StartBlock (where the guest flasher provisions the
       OS store) and the id-7 NK `.sec` region (PhysToSec's NK remap). */
    for (const auto& p : parts_) {
        if (p.id == 6) os_sig_block_ = p.start_block;
        if (p.id == 7) { nk_sec_off_ = p.sec_off; nk_blocks_ = p.nblocks; }
    }
}

std::optional<uint64_t> Imx51NandLayout::PhysToSec(uint64_t phys_off) const {
    const uint64_t blk = phys_off / kBlock;
    /* The image-6 loader copies the NK image from the blocks after the two sig
       blocks (contiguous physical reads from os_sig_block_+2, Bootloader.bin
       0x8FF0C384); serve those from the id-7 NK `.sec` region. */
    if (nk_blocks_ != 0 && blk >= os_sig_block_ + 2 &&
        blk < os_sig_block_ + 2 + nk_blocks_) {
        return nk_sec_off_ + (blk - (os_sig_block_ + 2)) * kBlock + (phys_off % kBlock);
    }
    for (const auto& p : parts_) {
        if (blk < p.start_block || blk >= p.start_block + p.nblocks) continue;
        const uint64_t in_mod = phys_off - p.start_block * kBlock;
        if (in_mod >= p.size) return std::nullopt;   /* past module data -> blank */
        return p.sec_off + in_mod;
    }
    return std::nullopt;                              /* unmapped block -> blank */
}

bool Imx51NandLayout::BuildFactoryPage(uint64_t phys_off, uint8_t* main, size_t main_len,
                                       uint8_t* spare, size_t spare_len) const {
    if (IsBbtBlock(phys_off)) {
        BuildBbtPage(phys_off, main, main_len, spare, spare_len);
        return true;
    }
    if (IsDpsOffset(phys_off)) {
        BuildDpsPage(phys_off, main, main_len, spare, spare_len);
        return true;
    }
    if (phys_off / kBlock < os_sig_block_) {
        std::fill(main, main + main_len, static_cast<uint8_t>(0xFFu));
        std::fill(spare, spare + spare_len, static_cast<uint8_t>(0xFFu));
        if (auto sec = PhysToSec(phys_off))
            emu_.Get<SecFlash>().ReadFlash(*sec, main, main_len);
        return true;
    }
    return false;
}

bool Imx51NandLayout::IsDpsOffset(uint64_t phys_off) const {
    return device_blocks_ != 0 && (phys_off / kBlock) == device_blocks_ - 1;
}

void Imx51NandLayout::BuildDpsPage(uint64_t phys_off, uint8_t* main, size_t main_len,
                                   uint8_t* spare, size_t spare_len) const {
    std::fill(main, main + main_len, static_cast<uint8_t>(0xFFu));
    std::fill(spare, spare + spare_len, static_cast<uint8_t>(0xFFu));
    if ((phys_off % kBlock) / kPageBytes != 0) return;   /* page1+: erased terminator */
    /* The DPS manifest is the flash-0x0 config block; copy it, rewrite the magic to
       the new-format signature, and patch each module record's StartBlock (rec+8)
       to its cumulative block (the `.sec` records carry 0). */
    const size_t cfg = kRecBase + kRecStride * parts_.size();
    emu_.Get<SecFlash>().ReadFlash(0, main, std::min(main_len, cfg));
    Wr32(main, 0, main_len, kDpsMagicNew);
    Wr32(main, kDpsBootVerOff, main_len, kDpsBootVersion);
    for (size_t i = 0; i < parts_.size(); ++i)
        Wr32(main, kRecBase + i * kRecStride + 8, main_len,
             static_cast<uint32_t>(parts_[i].start_block));
    Wr32(main, kDpsProgStatusA, main_len, 1);
    Wr32(main, kDpsProgStatusB, main_len, 1);
    /* Written-page marker so the new DPS_Read validator (0x8FF0C9A0) accepts it. */
    if (kBbtMetaSpareOff < spare_len) spare[kBbtMetaSpareOff] = 0x00;
}

bool Imx51NandLayout::IsBbtBlock(uint64_t phys_off) const {
    /* The search (Bootloader.bin 0x8FF0D71C) starts at block count-5
       (`sub r6, r4, #5`) and scans down; serve the BBT at that first block. */
    return device_blocks_ != 0 && (phys_off / kBlock) == device_blocks_ - 5;
}

void Imx51NandLayout::BuildBbtPage(uint64_t phys_off, uint8_t* main, size_t main_len,
                                   uint8_t* spare, size_t spare_len) const {
    std::fill(main, main + main_len, static_cast<uint8_t>(0xFFu));
    std::fill(spare, spare + spare_len, static_cast<uint8_t>(0xFFu));
    /* Only page 0 carries the header; later pages stay erased (spare[0]=0xFF) so
       the validator (0x8FF0C9A0) terminates its page scan after page 0. */
    if ((phys_off % kBlock) / kPageBytes != 0) return;
    /* Main: signature + entry count 0. DPS_ReadBadBlockTable copies (count+4)*2 = 8
       bytes from main[0] (0x8FF0D8EC). */
    Put32(main, kBbtMagic);
    Put32(main + 4, 0);
    /* meta[0]=0x00 marks a written page (validator 0x8FF0C9A0); meta[1..2] stay
       0xFF so the stored checksum reads 0xFFFF and the reader skips it (0x8FF0D8C4). */
    if (kBbtMetaSpareOff < spare_len) spare[kBbtMetaSpareOff] = 0x00;
}
