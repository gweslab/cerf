#pragma once

#include "omap3530_prcm_stub_block.h"

#include <cstdint>
#include <cstring>
#include <mutex>
#include <vector>

class Omap3530Gpmc : public Omap3530PrcmStubBlock {
public:
    using Omap3530PrcmStubBlock::Omap3530PrcmStubBlock;

    uint32_t MmioBase() const override { return 0x6E000000u; }
    uint32_t MmioSize() const override { return 0x00001000u; }

    void     OnReady()                                    override;
    uint16_t ReadHalf (uint32_t addr)                     override;
    uint8_t  ReadByte (uint32_t addr)                     override;
    void     WriteHalf(uint32_t addr, uint16_t value)     override;
    void     WriteWord(uint32_t addr, uint32_t value)     override;
    uint32_t ReadWord (uint32_t addr)                     override;

    uint16_t DrainPrefetchByte16(uint32_t cs);

    void PushPrefetchByte16(uint32_t cs, uint16_t value);

    /* Single-byte FIFO write - covers the byte-granular tail of an
       unaligned memcpy. Goes through the NAND state machine the
       same way as PushPrefetchByte16, but advances data_offset by 1
       instead of 2. */
    void PushPrefetchByte8 (uint32_t cs, uint8_t  value);

    void SaveState(StateWriter& w) override {
        Omap3530PrcmStubBlock::SaveState(w);   /* GPMC config regs_ */
        {
            std::lock_guard<std::mutex> lk(nand_mu_);
            for (const NandChip& c : nand_) {
                w.Write<uint32_t>(static_cast<uint32_t>(c.state));
                w.Write<int32_t>(c.id_byte_index);
                w.WriteBytes(c.addr_bytes, sizeof(c.addr_bytes));
                w.Write<int32_t>(c.addr_idx);
                w.Write<uint64_t>(static_cast<uint64_t>(c.data_offset));
                w.Write<uint64_t>(static_cast<uint64_t>(c.data_remaining));
                w.Write<uint64_t>(static_cast<uint64_t>(c.storage.size()));
                w.WriteBytes(c.storage.data(), c.storage.size());
            }
        }
        std::lock_guard<std::mutex> lk(irq_mu_);
        w.Write(irq_status_);
        w.Write(irq_enable_);
    }
    void RestoreState(StateReader& r) override {
        Omap3530PrcmStubBlock::RestoreState(r);
        {
            std::lock_guard<std::mutex> lk(nand_mu_);
            for (NandChip& c : nand_) {
                uint32_t st = 0; r.Read(st); c.state = static_cast<NandState>(st);
                int32_t  iv = 0;
                r.Read(iv); c.id_byte_index = iv;
                r.ReadBytes(c.addr_bytes, sizeof(c.addr_bytes));
                r.Read(iv); c.addr_idx = iv;
                uint64_t uv = 0;
                r.Read(uv); c.data_offset    = static_cast<size_t>(uv);
                r.Read(uv); c.data_remaining = static_cast<size_t>(uv);
                r.Read(uv); c.storage.assign(static_cast<size_t>(uv), 0u);
                r.ReadBytes(c.storage.data(), c.storage.size());
            }
        }
        std::lock_guard<std::mutex> lk(irq_mu_);
        r.Read(irq_status_);
        r.Read(irq_enable_);
    }

private:
    static constexpr int    kCsCount       = 8;
    static constexpr size_t kPageDataSize  = 2048;
    static constexpr size_t kPageSpareSize = 64;
    static constexpr size_t kPageTotalSize = kPageDataSize + kPageSpareSize;
    static constexpr size_t kPagesPerBlock = 64;
    static constexpr size_t kBlockCount    = 2048;
    static constexpr size_t kStorageSize   =
        kBlockCount * kPagesPerBlock * kPageTotalSize;

    enum class NandState {
        Idle,
        ReadId,
        StatusRead,
        ReadAddr,
        ReadDataReady,
        WriteAddr,
        WriteData,
        EraseAddr,
    };

    struct NandChip {
        NandState state          = NandState::Idle;
        int       id_byte_index  = 0;
        uint8_t   addr_bytes[5]  = {};
        int       addr_idx       = 0;
        size_t    data_offset    = 0;
        size_t    data_remaining = 0;
        std::vector<uint8_t> storage;
    };

    NandChip   nand_[kCsCount]{};
    std::mutex nand_mu_;

    static size_t PageByteOffset(const NandChip& chip);

    void WriteCeBootMbr();

    void     WriteNandCommand(uint32_t cs, uint16_t cmd);
    void     WriteNandAddress(uint32_t cs, uint16_t addr);
    void     WriteNandData16 (uint32_t cs, uint16_t value);
    uint16_t ReadNandData16  (uint32_t cs);

    /* Do NOT wire AssertIrq(20) on IRQENABLE writes - the EVM3530 OAL
       installs no ISR for GPMC, so dispatch lands at an uninitialised
       entry and the kernel prefetch-aborts on OAL static-IO. */
    std::mutex irq_mu_;
    uint32_t   irq_status_ = 0;
    uint32_t   irq_enable_ = 0;

protected:
    const char* Label() const override { return "GPMC"; }
    const char* RegisterName(uint32_t off) const override;
};
