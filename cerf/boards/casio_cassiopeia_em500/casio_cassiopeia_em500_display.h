#pragma once

#include "../../lcd/display_size_latch.h"

#include <cstdint>
#include <vector>

class CerfEmulator;
class StateWriter;
class StateReader;

class CasioCassiopeiaEm500Display {
public:
    void Init(CerfEmulator& emu);

    bool TryReadByte (uint32_t off, uint8_t&  out);
    bool TryReadHalf (uint32_t off, uint16_t& out);
    bool TryReadWord (uint32_t off, uint32_t& out);
    bool TryWriteByte(uint32_t off, uint8_t   value);
    bool TryWriteHalf(uint32_t off, uint16_t  value);
    bool TryWriteWord(uint32_t off, uint32_t  value);

    void SaveState(StateWriter& w) const;
    void RestoreState(StateReader& r);

    bool IsDisplayEnabled() const { return reg_0980_ == 1u; }
    /* nk_main_kernel.exe fill sub_9F0346B0: 0x1E0 bytes/row, row advance 0x200,
       extent 0x28000 from 0xAA200000; boot-logo @0x9F034408 (w=0xF0, h=0x140);
       ddi.dll sub_FC5538 VirtualCopy 0xAA200000 size 0x40000. */
    uint32_t GuestW()      const { return 240u; }
    uint32_t GuestH()      const { return 320u; }
    uint32_t StrideBytes() const { return 512u; }
    uint32_t FbPa()        const { return kBase + kFbOffset; }
    const uint8_t* FbBytes() const { return fb_.data(); }

private:
    static constexpr uint32_t kBase     = 0x0A000000u;
    static constexpr uint32_t kFbOffset = 0x00200000u;
    static constexpr uint32_t kFbSize   = 0x00040000u;

    bool InFb(uint32_t off) const { return off >= kFbOffset && off < kFbOffset + kFbSize; }
    void RunBlit();
    void RunFill();
    void MaybePublishDisplaySize();

    CerfEmulator* emu_ = nullptr;
    std::vector<uint8_t> fb_;

    /* ddi.dll sub_FC4E38 @0xFC4E38: [0xA00] go/busy, [0xA04] opcode 0x81,
       [0xA08] length words, [0xA10] source kseg1 addr, [0xA14] fb byte offset. */
    uint32_t blit_op_        = 0;
    uint32_t blit_len_words_ = 0;
    uint32_t blit_src_       = 0;
    uint32_t blit_dst_       = 0;

    /* ddi.dll sub_FC48A0 @0xFC48A0 (companion 0x200 window:
       0x210/0x214/0x208/0x20C/0x204/0x200). */
    uint32_t fill_dst_lo_ = 0;
    uint32_t fill_dst_hi_ = 0;
    uint32_t fill_w_      = 0;
    uint32_t fill_h_      = 0;
    uint32_t fill_color_  = 0;
    uint32_t fill_cmd_    = 0;

    /* nk_main_kernel.exe sub_9F03445C @0x9F03446C-0x9F034484 (0x984=1, 0x988=0x1B7,
       0x98C=0x1B7, 0x980=1), power-down @0x9F038B48-0x9F038B58 (0x980=0, 0x994=0);
       ddi.dll sub_FC2374 @0xFC2374 (0x98C brightness) / @0xFC276C (0x99C contrast). */
    uint32_t reg_0980_ = 0;
    uint32_t reg_0984_ = 0;
    uint32_t reg_0988_ = 0;
    uint32_t reg_098C_ = 0;
    uint32_t reg_0994_ = 0;
    uint32_t reg_099C_ = 0;

    DisplaySizeLatch size_latch_;
};
