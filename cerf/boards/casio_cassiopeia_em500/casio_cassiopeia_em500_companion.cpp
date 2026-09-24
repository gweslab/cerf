#include "casio_cassiopeia_em500_companion.h"

#include "../board_context.h"
#include "casio_cassiopeia_em500_id.h"
#include "../../core/cerf_emulator.h"
#include "../../core/log.h"
#include "../../peripherals/peripheral_dispatcher.h"
#include "../../socs/vr41xx/vr41xx_giu.h"
#include "../../state/state_stream.h"

REGISTER_SERVICE(CasioCassiopeiaEm500Companion);

namespace {

/* nk_main_kernel.exe sub_9F0389EC @0x9F0389EC */
constexpr uint32_t kOffCtrl8904 = 0x8904u;

/* nk_main_kernel.exe sub_9F038A58 @0x9F038A60 */
constexpr uint32_t kOffDataA040 = 0xA040u;

/* nk_main_kernel.exe sub_9F038AF0 @0x9F038AF8 */
constexpr uint32_t kOffSysCtrlLo = 0x0010u;
constexpr uint32_t kOffSysCtrlHi = 0x004Cu;

/* nk_main_kernel.exe @0x9F036130 lui $a0, 0xAA00 / @0x9F036134 lh 0xAA000004 /
   @0x9F036138-@0x9F036154 andi per source; bit8 -> loc_9F03703C, which reads
   0x089C bit7 and returns SYSINTR 0x14 @0x9F037248. */
constexpr uint32_t kOffIntStatus0004 = 0x0004u;
constexpr uint16_t kIntStatusAudio   = 0x100u;

/* nk_main_kernel.exe sub_9F08EE0C case 20 writes 12 to 0xAA000030; loc_9F03703C
   @0x9F0370B8 lw 0xAA000030 / and 0xFFFFFFF7 / @0x9F0370C4 sw clears bit3 while
   servicing. */
constexpr uint32_t kOffIntMask0030 = 0x0030u;
constexpr uint32_t kIntMaskAudio   = 0x8u;

/* nk_main_kernel.exe @0x9F03393C li $a0, 0xE01 = pins 0,9,10,11 -> @0x9F033948 sh ICU
   MGIUINTLREG 0xAF000094 and @0x9F0339C0 sh GIUINTENL 0xAF00014C ($a0 unclobbered
   between). @0x9F0339D0 sh $zero -> GIUINTTYPL 0xAF000150 = level; @0x9F0339D8 sh
   0x401 -> GIUINTALSELL 0xAF000154 = pin 0 high-active. */
constexpr int kCompanionGiuPin = 0;

/* nk_main_kernel.exe sub_9F03C140 @0x9F03C148, sub_9F03C104 @0x9F03C10C */
constexpr uint32_t kOffMboxCmd = 0x8900u;

/* nk_main_kernel.exe sub_9F032B60 @0x9F032C24, sub_9F03C104 @0x9F03C11C,
   sub_9F03C140 @0x9F03C158 */
constexpr uint32_t kOffMboxResp = 0x8910u;

/* nk_main_kernel.exe @0x9F033168/@0x9F0331AC (fold >>16 into the 0x2C2/0x2C1
   commands); wavedev.dll sub_F62520 (& 0x1D | 0x280). */
constexpr uint32_t kOffMboxResp2 = 0x890Cu;

/* bit0: nk_main_kernel.exe sub_9F03BF60 @0x9F03BF88, @0x9F033884 (ROMHDR ulRAMEnd);
   bit1: spimmc.dll sub_F71B5C @0xF71B5C, DSK_Init @0xF71E3A, pcmcia.dll sub_F817B8
   @0xF817B8; phonedb.net "Casio Cassiopeia EM-500" (MMC slot) */
constexpr uint32_t kOffVariantStrap = 0xA0E0u;
constexpr uint32_t kVariantStrap    = 0x3u;

/* nk_main_kernel.exe @0x9F033048/@0x9F0330B0 + @0x9F0335D4 (nibble-0 -> PMUINTREG
   0xAF0000C0 D9/D0 fallback); keybddr.dll sub_FB2D0C @0xFB2DB4 ("AppWakeUP"),
   @0xFB2E70. */
constexpr uint32_t kOffWakeStatus1 = 0xA042u;
constexpr uint32_t kOffWakeStatus2 = 0xA044u;

/* nk_main_kernel.exe @0x9F03308C, ISR loc_9F036C70. */
constexpr uint32_t kOffSocketStatus = 0xA03Cu;

/* nk_main_kernel.exe @0x9F0331FC-0x9F033208 (|1), @0x9F033238-0x9F033244 (&~1),
   @0x9F033248-0x9F033254 (|2), @0x9F033278-0x9F033284 (&~2). */
constexpr uint32_t kOffCtrlA0D4 = 0xA0D4u;

/* nk_main_kernel.exe @0x9F03C188-0x9F03C194 (lw; |1; sh); sub_9F08EE0C
   SYSINTR-19/28/30/31 cases. */
constexpr uint32_t kOffClk8004 = 0x8004u;

/* nk_main_kernel.exe @0x9F032CDC (sw 0), sub_9F03473C @0x9F034834/@0x9F034844,
   @0x9F038994 (sw 0). */
constexpr uint32_t kOffLatch1110 = 0x1110u;

/* nk_main_kernel.exe sub_9F08EE0C @0x9F08EF7C (sw 3), @0x9F03C330 (sw 0x30)/
   @0x9F03C338 (sw 2), + @0x9F0354C4/@0x9F08F21C/@0x9F08F48C. Write accepted
   (guarded downgrade); the read side sub_9F03C304 @0x9F03C308 (& 0x40 bit6) is
   born-FATAL until hit, so bit6 is grounded at its own halt. */
constexpr uint32_t kOffReg1054 = 0x1054u;

/* pcmcia.dll (MIPS16) per-socket table unk_F88288: RMW @0xF81878 (lw) + @0xF81880
   (sw |0x30); getters @0xF81840-46 (&4), @0xF8185A-62 (&0x30). */
constexpr uint32_t kOffSocketCtrlAC8 = 0x0AC8u;

/* pcmcia.dll (MIPS16) per-socket table unk_F8828C entry+0x38: RMW @0xF81D76 (lw) +
   @0xF81D80 (sw &~0xC); getter @0xF81D54-66 (not; srl 6; &1). */
constexpr uint32_t kOffSocketA038 = 0xA038u;

/* pcmcia.dll (MIPS16) card-detect getter @0xF818AA-0xF818B8 (lw 8; andi 2);
   bit1=1 = empty per consumers @0xF86B42 (nonzero -> power-down + re-poll) and
   @0xF86DEA (nonzero -> abort power-up). */
constexpr uint32_t kOffCardDetectA008 = 0xA008u;
constexpr uint32_t kCardDetectEmpty   = 0x2u;

/* wavedev.dll sub_F616F4 @0xF616FE (sw 1 -> 0x1118); 0x3C4 polls are lw+beqz. */
constexpr uint32_t kOffCodecCmd   = 0x03C0u;
constexpr uint32_t kOffCodecReady = 0x03C4u;
constexpr uint32_t kOffCodecData  = 0x03F4u;
constexpr uint32_t kOffLatch1118  = 0x1118u;

/* wavedev.dll 0x03C0 command = [bit15 write][bits14:12 register][bits11:0 data]:
   0x8083 reg0 @0xF62BAC, 0x900C reg1 @0xF62B76, 0xA010 reg2 @0xF62B88, 0xB047
   reg3 @0xF62B9A, 0xC000 reg4 @0xF61888, 0xD007 reg5 @0xF6172C. Read 0x5000 reg5
   @0xF629F6, consumed @0xF62A04 lw 0x3F4. */
constexpr uint32_t kCodecWriteBit   = 0x8000u;
constexpr uint32_t kCodecIndexShift = 12u;
constexpr uint32_t kCodecIndexMask  = 0x7u;
constexpr uint32_t kCodecDataMask   = 0x0FFFu;
constexpr uint32_t kCodecReadIndex  = 5u;
constexpr uint32_t kCodecRegCount   = 6u;

/* loc_F62984 @0xF62A20 sll $v1, $a1, 7 / @0xF62A24 or $v0(=0xD007) / @0xF62A26 sw
   0x3C0: the ladder's doubler lands in register 5 bit7. */
constexpr uint32_t kCodecRateReg    = 5u;
constexpr uint32_t kCodecDoublerBit = 0x80u;

/* nk_main_kernel.exe @0x9F035930 (sw 0x10), idle sub_9F038554 @0x9F0388F4
   (lw; andi 1). */
constexpr uint32_t kOffLatch130C  = 0x130Cu;

/* remocon.dll mapper @0xED181C-0xED1820; init RMW @0xED158C. */
constexpr uint32_t kOffAdcCtrl89C = 0x089Cu;

/* socket.dll init @0xF41966-0xF419A0 (sub_F42258 halfword stores; register
   table @0xF421BC-0xF421D6, descriptor 0xAA008000 @0xF421F8). */
constexpr uint32_t kOffStrap8000  = 0x8000u;
constexpr uint32_t kOffCfg8018    = 0x8018u;

/* Modem-socket accessory-ID pins, read-only (zero ROM writers). socket.dll
   @0xF422C0 (lhu; mask 0x1F @0xF416A0), index-0 code cmpi 1 @0xF41594;
   nk_main_kernel.exe sub_9F03C278/2A4/2D4 (&0xF ==15/==8/==12), suspend gate
   @0x9F038180. 0x1F = connector empty. */
constexpr uint32_t kOffSocketId8010 = 0x8010u;
constexpr uint32_t kSocketIdEmpty   = 0x1Fu;

/* nk_main_kernel.exe sub_9F08EE0C @0x9F08EE28 (lhu) + @0x9F08EE34 (sh &0xFDFF). */
constexpr uint32_t kOffIntCfg8404 = 0x8404u;

/* nk_main_kernel.exe @0x9F0332F0 (sw 2 after the PMUINTREG D4 ack),
   @0x9F0335A0-0x9F0335B4 / @0x9F03371C-0x9F033740 (lw; sw 2; bit0 -> RAM
   0xA0002520). */
constexpr uint32_t kOffCause8800 = 0x8800u;

/* nk_main_kernel.exe sub_9F08F334 case17 @0x9F08F388 / case24 @0x9F08F3A4
   (RMW enable config: (x & mask) | enable), @0x9F033A84 (sw 0); consumed
   @0x9F036608 (lw 0x304; raw & (raw>>8) = pending[7:0] & enable[15:8]). */
constexpr uint32_t kOffIntCause0304 = 0x0304u;

constexpr uint32_t kOffSibRegsLo = 0x0900u;
constexpr uint32_t kOffSibRegsHi = 0x0910u;

/* nk_main_kernel.exe sub_9F034498 @0x9F0344AC-0x9F0344E4 (lw; ==0x77 guard;
   sw 1/0x11/0x71/0x77), power-down @0x9F038B5C (lw; andi 0x79; sw). */
constexpr uint32_t kOffPanelState904 = 0x0904u;

constexpr uint32_t kOffEdgeCfgLo = 0xA060u;
constexpr uint32_t kOffEdgeCfgHi = 0xA07Eu;

}  /* namespace */

bool CasioCassiopeiaEm500Companion::ShouldRegister() {
    auto* bd = emu_.TryGet<BoardContext>();
    return bd && bd->GetBoardId() == BoardId::CasioCassiopeiaEm500;
}

void CasioCassiopeiaEm500Companion::OnReady() {
    audio_.Init(emu_, [this] { UpdateAudioIrqLine(); });
    display_.Init(emu_);
    modem_.Init();
    touch_.Init(emu_);
    emu_.Get<PeripheralDispatcher>().Register(this);
}

void CasioCassiopeiaEm500Companion::OnShutdown() {
    audio_.OnShutdown();
    touch_.OnShutdown();
}

uint8_t CasioCassiopeiaEm500Companion::ReadByte(uint32_t addr) {
    const uint32_t off = addr - kBase;
    if (uint8_t v; display_.TryReadByte(off, v)) return v;
    if (uint8_t v; modem_.TryReadByte(off, v)) return v;
    HaltUnsupportedAccess("EM-500 companion ReadByte", addr, 0);
}

uint16_t CasioCassiopeiaEm500Companion::ReadHalf(uint32_t addr) {
    const uint32_t off = addr - kBase;
    if (uint16_t v; display_.TryReadHalf(off, v)) return v;
    if (off == kOffIntStatus0004)
        return audio_.IrqPending() ? kIntStatusAudio : 0u;
    if (off == kOffWakeStatus1 || off == kOffWakeStatus2) return 0u;
    /* mailbox cmd 0x8900 bit9 (0x200) = busy; cdm.dll sub_EE15EC @0xEE1624
       busy-waits `while (*0x8900 & 0x200)`. Not-busy: command completes instantly
       (no sub-CPU), matching ReadWord 0x8900 = 0. */
    if (off == kOffMboxCmd) return 0u;
    /* mailbox response 0x8910: cdm.dll sub_EE15EC @0xEE1636 folds `~v1 & *0x8910`
       into the next 0x8900 command, never validates it (S13 closure); return 0,
       matching ReadWord 0x8910 = 0. */
    if (off == kOffMboxResp) return 0u;
    if (off == kOffIntCfg8404) return intcfg8404_;
    /* socket.dll sub_F42258 @0xF42284 (lhu) / @0xF42292 (sh), mask 0x1010
       call @0xF41986-0xF41990, table[5]=+4 @0xF421D6. */
    if (off == kOffClk8004) return static_cast<uint16_t>(clk8004_);
    /* socket.dll table[4]=+0 (0x8000): sub_F42258 RMW read-back only; the sole
       consuming read sub_F422A8 @0xF416A0 targets table[2]=0x8010, never 0x8000. */
    if (off == kOffStrap8000) return static_cast<uint16_t>(strap8000_);
    if (uint16_t mv; modem_.TryReadHalf(off, mv)) return mv;
    if (off == kOffSocketId8010) return kSocketIdEmpty;
    /* nk_main_kernel.exe @0x9F038904/@0x9F03890C/@0x9F038914 (lh x3, $t1
       overwritten untested, before cop0 0x22); xref-complete, no writer. */
    if (off == 0x0404u) return 0u;
    if (uint16_t av; audio_.TryReadHalf(off, av)) return av;
    /* keybddr.dll sub_FB2AB8 @0xFB2ACC RMW read-back (companion 0xA060-0xA07E). */
    if (off >= kOffEdgeCfgLo && off <= kOffEdgeCfgHi && (off & 1u) == 0u)
        return edge_cfg_[(off - kOffEdgeCfgLo) / 2u];
    HaltUnsupportedAccess("EM-500 companion ReadHalf", addr, 0);
}

uint32_t CasioCassiopeiaEm500Companion::ReadWord(uint32_t addr) {
    const uint32_t off = addr - kBase;
    if (uint32_t v; display_.TryReadWord(off, v)) return v;
    if (uint32_t mv; modem_.TryReadWord(off, mv)) return mv;
    if (uint32_t tv; touch_.TryReadWord(off, tv)) return tv;
    if (off == kOffCtrl8904) return ctrl8904_;
    if (off == kOffMboxCmd) return 0u;
    if (off == kOffMboxResp) return 0u;
    if (off == kOffMboxResp2) return 0u;
    if (off == kOffVariantStrap) return kVariantStrap;
    if (off == kOffSocketStatus) return 0u;
    if (off == kOffLatch1110) return reg_1110_;
    if (off == kOffSocketCtrlAC8) return socket_ctrl_ac8_;
    if (off == kOffSocketA038) return socket_a038_;
    if (off == kOffCardDetectA008) return kCardDetectEmpty;
    if (off == kOffLatch1118) return latch1118_;
    if (off == kOffLatch130C) return latch130C_;
    if (off == kOffAdcCtrl89C) return adc_ctrl_89C_;
    if (uint32_t ev; eeprom_.TryReadWord(off, ev)) return ev;
    if (uint32_t av; audio_.TryReadWord(off, av)) return av;
    /* wavedev.dll 0x3C4 ready polls (lw+beqz, e.g. @0xF6255E-0xF62578). */
    if (off == kOffCodecReady) return 1u;
    if (off == kOffCodecData) {
        if (!codec_data_valid_) {
            LOG(Caution, "EM-500 companion codec data port 0x03F4 read with no "
                         "preceding 0x03C0 read command\n");
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        return codec_data_;
    }
    if (off == kOffCtrlA0D4) return ctrl_a0d4_;
    if (off == kOffClk8004) return clk8004_;
    if (off == kOffCause8800) return 0u;
    /* touch.dll loc_F91958 @0xF91A82 (0x304 & 0x18 acquire cause), @0xF91A38
       (0x304 & 1 pen-event cause -> ACK path @0xF91A3C resets median index). */
    if (off == kOffIntCause0304)
        return reg_0304_ | (touch_.SamplePending() ? 0x18u : 0u)
                         | (touch_.ReleaseAckPending() ? 0x1u : 0u);
    if (off == kOffPanelState904) return sib_regs_[1];
    /* ddi.dll sub_FC838C @0xFC8394 RMW read-back (companion 0x0900). */
    if (off == kOffSibRegsLo) return sib_regs_[0];
    /* nk_main_kernel.exe @0x9F03C1C4 (lw 0x1C; &~8 after the 0x30 write @0x9F03C1C0). */
    if (off == 0x001Cu)
        return sys_ctrl_[(0x001Cu - kOffSysCtrlLo) / 4u].load(std::memory_order_acquire);
    /* nk_main_kernel.exe sub_9F08EE0C case 30 @0x9F08F0C0/@0x9F08F0CC (lw 0x20; |=; sw). */
    if (off == 0x0020u)
        return sys_ctrl_[(0x0020u - kOffSysCtrlLo) / 4u].load(std::memory_order_acquire);
    if (off == kOffIntMask0030)
        return sys_ctrl_[(kOffIntMask0030 - kOffSysCtrlLo) / 4u].load(std::memory_order_acquire);
    HaltUnsupportedAccess("EM-500 companion ReadWord", addr, 0);
}

void CasioCassiopeiaEm500Companion::WriteByte(uint32_t addr, uint8_t value) {
    const uint32_t off = addr - kBase;
    if (display_.TryWriteByte(off, value)) return;
    if (modem_.TryWriteByte(off, value)) return;
    HaltUnsupportedAccess("EM-500 companion WriteByte", addr, value);
}

void CasioCassiopeiaEm500Companion::WriteHalf(uint32_t addr, uint16_t value) {
    const uint32_t off = addr - kBase;
    if (display_.TryWriteHalf(off, value)) return;
    if (off == kOffDataA040) { data_a040_ = value; return; }
    /* nk_main_kernel.exe sub_9F032B60 @0x9F032C44 */
    if (off == kOffCtrl8904) { ctrl8904_ = value; return; }
    /* mailbox cmd 0x8900 write (cdm.dll sub_EE15EC @0xEE1648, bit9 busy set);
       stored, not processed (no sub-CPU, S13), as WriteReg 0x8900. */
    if (off == kOffMboxCmd) { mbox_cmd_ = value; return; }
    /* nk_main_kernel.exe @0x9F03C194 (sh of the |1 write-back). */
    if (off == kOffClk8004) { clk8004_ = value; return; }
    if (off == kOffIntCfg8404) { intcfg8404_ = value; return; }
    if (off == kOffStrap8000) { strap8000_ = value; return; }
    if (off == kOffCfg8018) return;
    if (modem_.TryWriteHalf(off, value)) return;
    if (audio_.TryWriteHalf(off, value)) return;
    if (off >= kOffEdgeCfgLo && off <= kOffEdgeCfgHi && (off & 1u) == 0u) {
        edge_cfg_[(off - kOffEdgeCfgLo) / 2u] = value;
        return;
    }
    /* nk_main_kernel.exe sub_9F08F334 @0x9F08F4E8 (offset 0x0010) / @0x9F08F4EC
       (offset 0x003C), sh of 0x30/4/0xC @0x9F08F4FC-@0x9F08F50C. */
    if (off >= kOffSysCtrlLo && off <= kOffSysCtrlHi && (off & 3u) == 0u) {
        WriteSysCtrl(off, value, 0xFFFF0000u);
        return;
    }
    HaltUnsupportedAccess("EM-500 companion WriteHalf", addr, value);
}

void CasioCassiopeiaEm500Companion::WriteWord(uint32_t addr, uint32_t value) {
    const uint32_t off = addr - kBase;
    if (display_.TryWriteWord(off, value)) return;
    if (modem_.TryWriteWord(off, value)) return;
    if (touch_.TryWriteWord(off, value)) return;
    if (eeprom_.TryWriteWord(off, value)) return;
    if (audio_.TryWriteWord(off, value)) return;
    WriteReg(off, value);
}

void CasioCassiopeiaEm500Companion::WriteReg(uint32_t off, uint32_t value) {
    switch (off) {
        case kOffCtrl8904: ctrl8904_ = value; return;
        case kOffLatch1110: reg_1110_ = value; return;
        case kOffReg1054: reg_1054_ = value; return;
        case kOffSocketCtrlAC8: socket_ctrl_ac8_ = value; return;
        case kOffSocketA038: socket_a038_ = value; return;
        case kOffLatch1118: latch1118_ = value; return;
        case kOffLatch130C: latch130C_ = value; return;
        case kOffAdcCtrl89C: adc_ctrl_89C_ = value; return;
        /* nk_main_kernel.exe sub_9F08EE0C cases 19/28/30/31 @0x9F08F0AC (lw 0x8004; |=; sw). */
        case kOffClk8004: clk8004_ = value; return;
        case kOffStrap8000: strap8000_ = value; return;
        case kOffCfg8018: return;
        case kOffCodecCmd: WriteCodecCommand(value); return;
        /* nk_main_kernel.exe @0x9F033174/@0x9F0331B8 (sw of the folded 0x2C2/0x2C1),
           sub_9F03C104 @0x9F03C120, sub_9F03C140 @0x9F03C160 (0x301/0x300). */
        case kOffMboxCmd: mbox_cmd_ = value; return;
        case kOffCtrlA0D4: ctrl_a0d4_ = value; return;
        case kOffCause8800: return;
        /* touch.dll loc_F91958 @0xF91B48/@0xF91BFE (0x304 |= 0x18 ack). */
        case kOffIntCause0304:
            reg_0304_ = value & ~0x19u;
            if (value & 0x18u) touch_.AckSample();
            return;
        case 0x0900u: case 0x0904u: case 0x0908u: case 0x090Cu: case 0x0910u:
            sib_regs_[(off - kOffSibRegsLo) / 4u] = value;
            return;
        default: break;
    }
    /* nk_main_kernel.exe sub_9F032B60: 0xA0C4/0xA0CC @0x9F032C84, 0xA0DC @0x9F032CEC,
       0x1100-0x1130 @0x9F032C98, 0x0008 @0x9F032D24; 0x1300
       @0x9F033828/@0x9F033854/@0x9F038970, 0x1338 @0x9F03383C/@0x9F03384C. */
    if (off == 0x0008u ||
        off == 0xA0C4u || off == 0xA0CCu || off == 0xA0DCu ||
        off == 0x1300u || off == 0x1338u ||
        (off >= 0x1100u && off <= 0x1130u && (off & 3u) == 0u)) {
        return;
    }
    if (off >= kOffSysCtrlLo && off <= kOffSysCtrlHi && (off & 3u) == 0u) {
        WriteSysCtrl(off, value, 0u);
        return;
    }
    HaltUnsupportedAccess("EM-500 companion WriteWord", kBase + off, value);
}

void CasioCassiopeiaEm500Companion::WriteSysCtrl(uint32_t off, uint32_t value,
                                                   uint32_t keep_mask) {
    std::atomic<uint32_t>& w = sys_ctrl_[(off - kOffSysCtrlLo) / 4u];
    const uint32_t prev = w.load(std::memory_order_acquire);
    w.store((prev & keep_mask) | (value & ~keep_mask), std::memory_order_release);
    if (off == kOffIntMask0030) UpdateAudioIrqLine();
}

void CasioCassiopeiaEm500Companion::UpdateAudioIrqLine() {
    const uint32_t mask =
        sys_ctrl_[(kOffIntMask0030 - kOffSysCtrlLo) / 4u].load(std::memory_order_acquire);
    emu_.Get<Vr41xxGiu>().SetPinLevel(
        kCompanionGiuPin, audio_.IrqPending() && (mask & kIntMaskAudio) != 0u);
}

void CasioCassiopeiaEm500Companion::WriteCodecCommand(uint32_t value) {
    const uint32_t index = (value >> kCodecIndexShift) & kCodecIndexMask;
    if (value & kCodecWriteBit) {
        if (index >= kCodecRegCount) {
            LOG(Caution, "EM-500 companion codec write command 0x%X targets "
                         "register %u\n", value, index);
            CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
        }
        codec_regs_[index] = static_cast<uint16_t>(value & kCodecDataMask);
        codec_written_ |= static_cast<uint8_t>(1u << index);
        if (index == kCodecRateReg)
            audio_.SetRateDoubler((value & kCodecDoublerBit) != 0u);
        return;
    }
    if (index != kCodecReadIndex ||
        (codec_written_ & static_cast<uint8_t>(1u << index)) == 0u) {
        LOG(Caution, "EM-500 companion codec read command 0x%X targets register %u "
                     "(written mask 0x%02X)\n", value, index, codec_written_);
        CerfFatalExit(CERF_FATAL_RUNTIME_ERROR);
    }
    codec_data_ = codec_regs_[index];
    codec_data_valid_ = true;
}

void CasioCassiopeiaEm500Companion::SaveState(StateWriter& w) {
    w.Write("mbox_cmd", mbox_cmd_);
    w.Write("ctrl8904", ctrl8904_);
    w.Write("ctrl_a0d4", ctrl_a0d4_);
    w.Write("clk8004", clk8004_);
    w.Write("data_a040", data_a040_);
    for (uint32_t v : sib_regs_) w.Write("sib_regs", v);
    for (const std::atomic<uint32_t>& v : sys_ctrl_)
        w.Write("sys_ctrl", v.load(std::memory_order_acquire));
    for (uint16_t v : edge_cfg_) w.Write("edge_cfg", v);
    w.Write("reg_1110", reg_1110_);
    w.Write("reg_1054", reg_1054_);
    w.Write("socket_ctrl_ac8", socket_ctrl_ac8_);
    w.Write("socket_a038", socket_a038_);
    w.Write("intcfg8404", intcfg8404_);
    for (uint16_t v : codec_regs_) w.Write("codec_regs", v);
    w.Write("codec_written", codec_written_);
    w.Write("codec_data", codec_data_);
    w.Write<uint8_t>("codec_data_valid", codec_data_valid_ ? 1u : 0u);
    w.Write("latch1118", latch1118_);
    w.Write("latch130C", latch130C_);
    w.Write("strap8000", strap8000_);
    w.Write("adc_ctrl_89C", adc_ctrl_89C_);
    w.Write("reg_0304", reg_0304_);
    eeprom_.SaveState(w);
    audio_.SaveState(w);
    display_.SaveState(w);
    modem_.SaveState(w);
    touch_.SaveState(w);
}

void CasioCassiopeiaEm500Companion::RestoreState(StateReader& r) {
    r.Read("mbox_cmd", mbox_cmd_);
    r.Read("ctrl8904", ctrl8904_);
    r.Read("ctrl_a0d4", ctrl_a0d4_);
    r.Read("clk8004", clk8004_);
    r.Read("data_a040", data_a040_);
    for (uint32_t& v : sib_regs_) r.Read("sib_regs", v);
    for (std::atomic<uint32_t>& v : sys_ctrl_) {
        uint32_t t = 0;
        r.Read("sys_ctrl", t);
        v.store(t, std::memory_order_release);
    }
    for (uint16_t& v : edge_cfg_) r.Read("edge_cfg", v);
    r.Read("reg_1110", reg_1110_);
    r.Read("reg_1054", reg_1054_);
    r.Read("socket_ctrl_ac8", socket_ctrl_ac8_);
    r.Read("socket_a038", socket_a038_);
    r.Read("intcfg8404", intcfg8404_);
    for (uint16_t& v : codec_regs_) r.Read("codec_regs", v);
    r.Read("codec_written", codec_written_);
    r.Read("codec_data", codec_data_);
    uint8_t data_valid = 0;
    r.Read("codec_data_valid", data_valid);
    codec_data_valid_ = data_valid != 0;
    r.Read("latch1118", latch1118_);
    r.Read("latch130C", latch130C_);
    r.Read("strap8000", strap8000_);
    r.Read("adc_ctrl_89C", adc_ctrl_89C_);
    r.Read("reg_0304", reg_0304_);
    eeprom_.RestoreState(r);
    audio_.RestoreState(r);
    display_.RestoreState(r);
    modem_.RestoreState(r);
    touch_.RestoreState(r);
}

void CasioCassiopeiaEm500Companion::PostRestore() {
    audio_.PostRestore();
    UpdateAudioIrqLine();
    modem_.PostRestore();
    touch_.PostRestore();
}
