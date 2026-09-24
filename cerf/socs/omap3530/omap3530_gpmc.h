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
            static_assert(StateVisitCoversAllBytes<NandChip>(
                              [](NandChip& c, StateFieldBytes& f) { NandChip::Visit(c, f); }),
                          "NandChip::Visit must name or skip every field of NandChip");
            StateWriteField field(w);
            for (NandChip& c : nand_) {
                NandChip::Visit(c, field);
                w.WriteBytes("storage", c.storage.data(), c.storage.size());
            }
        }
        std::lock_guard<std::mutex> lk(irq_mu_);
        w.Write("irq_status", irq_status_);
        w.Write("irq_enable", irq_enable_);
    }
    void RestoreState(StateReader& r) override {
        Omap3530PrcmStubBlock::RestoreState(r);
        {
            std::lock_guard<std::mutex> lk(nand_mu_);
            StateReadField field(r);
            for (NandChip& c : nand_) {
                NandChip::Visit(c, field);
                r.ReadBytes("storage", c.storage.data(), c.storage.size());
            }
        }
        std::lock_guard<std::mutex> lk(irq_mu_);
        r.Read("irq_status", irq_status_);
        r.Read("irq_enable", irq_enable_);
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
        uint8_t   pad[3]         = {};
        int       addr_idx       = 0;
        size_t    data_offset    = 0;
        size_t    data_remaining = 0;
        std::vector<uint8_t> storage;

        template <typename F>
        static constexpr void Visit(NandChip& c, F& field) {
            field("state", c.state);
            field("id_byte_index", c.id_byte_index);
            field("addr_bytes", c.addr_bytes);
            field.Skip(c.pad);
            field("addr_idx", c.addr_idx);
            field("data_offset", c.data_offset);
            field("data_remaining", c.data_remaining);
            field.Skip(c.storage);
        }
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
