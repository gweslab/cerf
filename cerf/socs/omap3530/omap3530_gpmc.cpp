#include "omap3530_gpmc.h"

#include "../../core/byte_order.h"
#include "../../storage/fat_volume_layout.h"

void Omap3530Gpmc::OnReady() {
    Omap3530PrcmStubBlock::OnReady();
    /* In-RAM blank NAND for CS0 - 256 MB of 0xFF. */
    nand_[0].storage.assign(kStorageSize, 0xFFu);
    WriteCeBootMbr();
}

void Omap3530Gpmc::WriteCeBootMbr() {
    auto& chip = nand_[0];

    constexpr uint8_t  kPartDos32       = 0x0B;
    constexpr uint32_t kPartStartSec    = 64;
    constexpr uint32_t kPartTotalSec    = 131008;

    uint8_t* data = chip.storage.data();
    data[0] = 0xE9u; data[1] = 0xFDu; data[2] = 0xFFu;
    fat_volume_layout::WriteBootSignature(data);

    std::memset(fat_volume_layout::MbrPartitionEntry(data, 0), 0,
                4 * fat_volume_layout::kMbrPartEntryBytes);

    fat_volume_layout::MbrPartition part;
    part.type = kPartDos32;
    part.start_lba = kPartStartSec;
    part.sectors = kPartTotalSec;
    fat_volume_layout::WriteMbrPartition(data, 0, part);

    uint8_t* spare = chip.storage.data() + kPageDataSize;
    /* If any ECC byte != 0, mspart's later MBR re-read fails
       NAND_CorrectEccData memcmp (CERF GPMC stub returns 0 from
       ECC1_RESULT) → FMD_ReadSector returns ERROR_READ_FAULT. */
    std::memset(spare + 2, 0, 12);
    /* spare[14..17] = logicalSectorAddr = 0 */
    spare[14] = 0; spare[15] = 0; spare[16] = 0; spare[17] = 0;
    /* If fDataStatus stays 0xFFFF, BuildupMappingInfo treats sector 0
       as FREE not MAPPED - no logical-0 mapping is registered. */
    spare[18] = 0xFBu; spare[19] = 0xFFu;
    /* If oemReserved stays 0xFF, FMD_GetBlockStatus doesn't report
       BLOCK_STATUS_READONLY - BuildupMappingInfo never enters the
       readonly-block branch that maps logical 0..63 of this block. */
    spare[21] = 0xFDu;
}

uint16_t Omap3530Gpmc::ReadHalf(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off >= 0x60u && off < 0x60u + 8u * 0x30u) {
        const uint32_t sub = (off - 0x60u) % 0x30u;
        const uint32_t cs  = (off - 0x60u) / 0x30u;
        if (sub == 0x24u) return ReadNandData16(cs);
    }
    return Omap3530PrcmStubBlock::ReadHalf(addr);
}

uint8_t Omap3530Gpmc::ReadByte(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off >= 0x60u && off < 0x60u + 8u * 0x30u) {
        const uint32_t sub = (off - 0x60u) % 0x30u;
        const uint32_t cs  = (off - 0x60u) / 0x30u;
        if (sub >= 0x24u && sub <= 0x27u) {
            return static_cast<uint8_t>(ReadNandData16(cs));
        }
    }
    return Omap3530PrcmStubBlock::ReadByte(addr);
}

void Omap3530Gpmc::WriteHalf(uint32_t addr, uint16_t value) {
    const uint32_t off = addr - MmioBase();
    Omap3530PrcmStubBlock::WriteHalf(addr, value);
    if (off >= 0x60u && off < 0x60u + 8u * 0x30u) {
        const uint32_t sub = (off - 0x60u) % 0x30u;
        const uint32_t cs  = (off - 0x60u) / 0x30u;
        if      (sub == 0x1Cu) WriteNandCommand(cs, value);
        else if (sub == 0x20u) WriteNandAddress(cs, value);
        else if (sub == 0x24u) WriteNandData16 (cs, value);
    }
}

void Omap3530Gpmc::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - MmioBase();
    if (off == 0x18u) {
        std::lock_guard<std::mutex> lk(irq_mu_);
        irq_status_ &= ~value;
        return;
    }
    if (off == 0x1Cu) {
        std::lock_guard<std::mutex> lk(irq_mu_);
        irq_enable_ = value;
    }
    Omap3530PrcmStubBlock::WriteWord(addr, value);
}

uint32_t Omap3530Gpmc::ReadWord(uint32_t addr) {
    const uint32_t off = addr - MmioBase();
    if (off == 0x18u) {
        std::lock_guard<std::mutex> lk(irq_mu_);
        return irq_status_;
    }
    if (off == 0x54u) {
        /* GPMC_STATUS bit 8 = WAIT0PIN. FMD's NAND_GetStatus polls
           this bit (NAND_STATUS_READY) - return ready always. */
        return 0x00000100u;
    }
    if (off == 0x1F0u) {
        /* BSP polls bits[30:24] of PREFETCH_STATUS, not the FIFOPOINTER
           field per OMAP3 TRM; <0x40 here spins the driver poll. */
        return 0x40000000u;
    }
    return Omap3530PrcmStubBlock::ReadWord(addr);
}

uint16_t Omap3530Gpmc::DrainPrefetchByte16(uint32_t cs) {
    return ReadNandData16(cs);
}

void Omap3530Gpmc::PushPrefetchByte16(uint32_t cs, uint16_t value) {
    WriteNandData16(cs, value);
}

void Omap3530Gpmc::PushPrefetchByte8(uint32_t cs, uint8_t value) {
    if (cs != 0) return;
    std::lock_guard<std::mutex> lk(nand_mu_);
    auto& chip = nand_[cs];
    if (chip.state == NandState::WriteData &&
        chip.data_offset + 1 <= chip.storage.size() &&
        chip.data_remaining >= 1) {
        chip.storage[chip.data_offset] &= value;
        chip.data_offset    += 1;
        chip.data_remaining -= 1;
    }
}

size_t Omap3530Gpmc::PageByteOffset(const NandChip& chip) {
    const uint8_t page_bytes[3] = {
        chip.addr_bytes[2], chip.addr_bytes[3],
        chip.addr_idx >= 5 ? chip.addr_bytes[4] : uint8_t(0)};
    const uint32_t column_words = cerf::le::U16(chip.addr_bytes);
    const uint32_t page         = cerf::le::U24(page_bytes);
    return static_cast<size_t>(page) * kPageTotalSize +
           static_cast<size_t>(column_words) * 2u;
}

void Omap3530Gpmc::WriteNandCommand(uint32_t cs, uint16_t cmd) {
    if (cs != 0) return;
    std::lock_guard<std::mutex> lk(nand_mu_);
    auto& chip = nand_[cs];
    const uint8_t cmd8 = static_cast<uint8_t>(cmd & 0xFFu);
    switch (cmd8) {
    case 0xFFu:                              /* RESET */
        chip.state         = NandState::Idle;
        chip.id_byte_index = 0;
        chip.addr_idx      = 0;
        break;
    case 0x70u:                              /* READ_STATUS */
        chip.state = NandState::StatusRead;
        break;
    case 0x90u:                              /* READ_ID */
        chip.state         = NandState::ReadId;
        chip.id_byte_index = 0;
        break;
    case 0x00u:                              /* READ page (1st) */
        if (chip.state == NandState::StatusRead &&
            chip.data_remaining > 0) {
            chip.state = NandState::ReadDataReady;
        } else {
            chip.state    = NandState::ReadAddr;
            chip.addr_idx = 0;
        }
        break;
    case 0x30u:                              /* READ page (2nd, confirm) */
        if (chip.state == NandState::ReadAddr && chip.addr_idx >= 4) {
            const size_t offset = PageByteOffset(chip);
            if (offset < chip.storage.size()) {
                chip.data_offset    = offset;
                chip.data_remaining =
                    kPageTotalSize - (offset % kPageTotalSize);
                chip.state = NandState::ReadDataReady;
            } else {
                chip.state = NandState::Idle;
            }
        }
        break;
    case 0x80u:                              /* PAGE PROGRAM (1st) */
        chip.state    = NandState::WriteAddr;
        chip.addr_idx = 0;
        break;
    case 0x10u:                              /* PAGE PROGRAM (2nd, confirm) */
        chip.state = NandState::Idle;
        break;
    case 0x60u:                              /* BLOCK ERASE (1st) */
        chip.state    = NandState::EraseAddr;
        chip.addr_idx = 0;
        break;
    case 0xD0u:                              /* BLOCK ERASE (2nd, confirm) */
        if (chip.state == NandState::EraseAddr && chip.addr_idx >= 3) {
            const uint32_t page = cerf::le::U24(chip.addr_bytes);
            const uint32_t block = page / kPagesPerBlock;
            if (block < kBlockCount && !chip.storage.empty()) {
                const size_t block_offset =
                    static_cast<size_t>(block) * kPagesPerBlock *
                    kPageTotalSize;
                const size_t block_bytes =
                    kPagesPerBlock * kPageTotalSize;
                std::memset(chip.storage.data() + block_offset, 0xFFu,
                            block_bytes);
            }
        }
        chip.state = NandState::Idle;
        break;
    default:
        LOG(Periph,
            "[GPMC] NAND CS%u command 0x%02X not modelled\n",
            cs, cmd8);
        break;
    }
}

void Omap3530Gpmc::WriteNandAddress(uint32_t cs, uint16_t addr) {
    if (cs != 0) return;
    std::lock_guard<std::mutex> lk(nand_mu_);
    auto& chip = nand_[cs];
    if (chip.addr_idx < 5) {
        chip.addr_bytes[chip.addr_idx++] =
            static_cast<uint8_t>(addr & 0xFFu);
    } else {
        LOG(Caution,
            "[GPMC] NAND CS%u address byte %d beyond 5 - chip "
            "geometry mismatch?\n", cs, chip.addr_idx);
    }
    if (chip.state == NandState::WriteAddr && chip.addr_idx >= 4) {
        const size_t offset = PageByteOffset(chip);
        if (offset < chip.storage.size()) {
            chip.data_offset    = offset;
            chip.data_remaining =
                kPageTotalSize - (offset % kPageTotalSize);
            chip.state = NandState::WriteData;
        }
    }
}

void Omap3530Gpmc::WriteNandData16(uint32_t cs, uint16_t value) {
    if (cs != 0) return;
    std::lock_guard<std::mutex> lk(nand_mu_);
    auto& chip = nand_[cs];
    if (chip.state == NandState::WriteData &&
        chip.data_offset + 2 <= chip.storage.size() &&
        chip.data_remaining >= 2) {
        uint8_t* const cell = chip.storage.data() + chip.data_offset;
        cerf::le::Put16(cell, static_cast<uint16_t>(cerf::le::U16(cell) & value));
        chip.data_offset    += 2;
        chip.data_remaining -= 2;
    }
}

uint16_t Omap3530Gpmc::ReadNandData16(uint32_t cs) {
    if (cs != 0) return 0xFFFFu;
    std::lock_guard<std::mutex> lk(nand_mu_);
    auto& chip = nand_[cs];
    switch (chip.state) {
    case NandState::ReadId: {
        static constexpr uint8_t kIdBytes[5] = {
            0x2Cu, 0xBAu, 0x00u, 0x15u, 0x00u,
        };
        const int idx = chip.id_byte_index;
        const uint8_t byte = (idx < static_cast<int>(sizeof(kIdBytes)))
            ? kIdBytes[idx] : 0x00u;
        ++chip.id_byte_index;
        return byte;
    }
    case NandState::ReadDataReady:
        if (chip.data_offset + 2 <= chip.storage.size() &&
            chip.data_remaining >= 2) {
            const uint16_t v = cerf::le::U16(chip.storage.data(), chip.data_offset);
            chip.data_offset    += 2;
            chip.data_remaining -= 2;
            return v;
        }
        return 0xFFFFu;
    case NandState::StatusRead:
    case NandState::Idle:
    default:
        return 0x00E0u;
    }
}

const char* Omap3530Gpmc::RegisterName(uint32_t off) const {
    switch (off) {
    case 0x000: return "GPMC_REVISION";
    case 0x010: return "GPMC_SYSCONFIG";
    case 0x014: return "GPMC_SYSSTATUS";
    case 0x018: return "GPMC_IRQSTATUS";
    case 0x01C: return "GPMC_IRQENABLE";
    case 0x040: return "GPMC_TIMEOUT_CONTROL";
    case 0x044: return "GPMC_ERR_ADDRESS";
    case 0x048: return "GPMC_ERR_TYPE";
    case 0x050: return "GPMC_CONFIG";
    case 0x054: return "GPMC_STATUS";
    case 0x1E0: return "GPMC_PREFETCH_CONFIG1";
    case 0x1E4: return "GPMC_PREFETCH_CONFIG2";
    case 0x1EC: return "GPMC_PREFETCH_CONTROL";
    case 0x1F0: return "GPMC_PREFETCH_STATUS";
    case 0x1F4: return "GPMC_ECC_CONFIG";
    case 0x1F8: return "GPMC_ECC_CONTROL";
    case 0x1FC: return "GPMC_ECC_SIZE_CONFIG";
    }
    if (off >= 0x060u && off < 0x060u + 8u * 0x30u) {
        const uint32_t rel = off - 0x060u;
        const uint32_t cs  = rel / 0x30u;
        const uint32_t sub = rel % 0x30u;
        (void)cs;
        switch (sub) {
        case 0x00: return "GPMC_CONFIG1_n";
        case 0x04: return "GPMC_CONFIG2_n";
        case 0x08: return "GPMC_CONFIG3_n";
        case 0x0C: return "GPMC_CONFIG4_n";
        case 0x10: return "GPMC_CONFIG5_n";
        case 0x14: return "GPMC_CONFIG6_n";
        case 0x18: return "GPMC_CONFIG7_n";
        case 0x1C: return "GPMC_NAND_COMMAND_n";
        case 0x20: return "GPMC_NAND_ADDRESS_n";
        case 0x24: return "GPMC_NAND_DATA_n";
        }
    }
    return nullptr;
}

REGISTER_SERVICE(Omap3530Gpmc);
