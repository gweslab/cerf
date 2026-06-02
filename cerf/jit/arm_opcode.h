#pragma once

#include <cstdint>

union ArmOpcode {
    uint32_t word;

    struct {
        uint32_t reserved          : 25;
        uint32_t instruction_class : 3;
        uint32_t cond              : 4;
    } generic;

    struct {  /* "Never" cond + opcode marker for v5+ extensions
                 (BLX, STC2, LDC2, CDP2, MCR2, MRC2, PLD). */
        uint32_t any1      : 4;
        uint32_t reserved1 : 1;
        uint32_t any2      : 20;
        uint32_t cond      : 4;
    } undefined_extension;

    struct {  /* MUL / MLA / UMULL / SMULL / UMLAL / SMLAL. */
        uint32_t rm         : 4;
        uint32_t reserved1  : 4;
        uint32_t rs         : 4;
        uint32_t rn         : 4;
        uint32_t rd         : 4;
        uint32_t s          : 1;
        uint32_t op1        : 3;
        uint32_t reserved2  : 4;
        uint32_t cond       : 4;
    } arithmetic_extension;

    struct {  /* MSR / MRS / BX / BKPT / CLZ. */
        uint32_t operand2   : 12;
        uint32_t rd         : 4;
        uint32_t rn         : 4;
        uint32_t reserved2  : 1;
        uint32_t op1        : 2;
        uint32_t reserved3  : 5;
        uint32_t cond       : 4;
    } control_extension;

    struct {  /* Halfword / signed-byte load/store + SWP/SWPB. */
        uint32_t rm         : 4;
        uint32_t reserved1  : 1;
        uint32_t op1        : 2;
        uint32_t reserved2  : 1;
        uint32_t rs         : 4;
        uint32_t rd         : 4;
        uint32_t rn         : 4;
        uint32_t l          : 1;
        uint32_t w          : 1;
        uint32_t b          : 1;
        uint32_t u          : 1;
        uint32_t p          : 1;
        uint32_t reserved3  : 3;
        uint32_t cond       : 4;
    } load_store_extension;

    struct {  /* LDRD / STRD (v5TE+). */
        uint32_t rm         : 4;
        uint32_t reserved1  : 1;
        uint32_t l          : 1;
        uint32_t reserved2  : 2;
        uint32_t rs         : 4;
        uint32_t rd         : 4;
        uint32_t rn         : 4;
        uint32_t reserved3  : 1;
        uint32_t w          : 1;
        uint32_t i          : 1;
        uint32_t u          : 1;
        uint32_t p          : 1;
        uint32_t reserved4  : 3;
        uint32_t cond       : 4;
    } double_load_store_extension;

    struct {  /* CDP / LDC / STC / MCR / MRC coprocessor envelope. */
        uint32_t offset     : 8;
        uint32_t cp_num     : 4;
        uint32_t crd        : 4;
        uint32_t rn         : 4;
        uint32_t x1         : 1;
        uint32_t reserved1  : 1;
        uint32_t x2         : 1;
        uint32_t reserved2  : 5;
        uint32_t cond       : 4;
    } coprocessor_extension;

    struct {  /* Cond=15 extension envelope (PLD, BLX-imm, etc.). */
        uint32_t x1         : 4;
        uint32_t opcode2    : 4;
        uint32_t x2         : 12;
        uint32_t opcode1    : 8;
        uint32_t cond       : 4;
    } unconditional_extension;

    struct {  /* Advanced SIMD element/structure load/store (cond=15,
                 bits[27:24]=0b0100). DDI0406C A7.7. */
        uint32_t rm         : 4;   /* [3:0]            */
        uint32_t align      : 2;   /* [5:4]            */
        uint32_t size       : 2;   /* [7:6]            */
        uint32_t type       : 4;   /* [11:8]           */
        uint32_t vd         : 4;   /* [15:12]          */
        uint32_t rn         : 4;   /* [19:16]          */
        uint32_t reserved0  : 1;   /* [20] = 0         */
        uint32_t l          : 1;   /* [21] L           */
        uint32_t d          : 1;   /* [22] D           */
        uint32_t a          : 1;   /* [23] A           */
        uint32_t marker     : 4;   /* [27:24] = 0b0100 */
        uint32_t cond       : 4;   /* [31:28]          */
    } neon_load_store;

    struct {  /* Adv SIMD single-element to one lane (A==1, size!=11). A7.7. */
        uint32_t rm          : 4;   /* [3:0]            */
        uint32_t index_align : 4;   /* [7:4]            */
        uint32_t n_minus1    : 2;   /* [9:8] VLD/VST 1/2/3/4 = 00/01/10/11 */
        uint32_t size        : 2;   /* [11:10]          */
        uint32_t vd          : 4;   /* [15:12]          */
        uint32_t rn          : 4;   /* [19:16]          */
        uint32_t reserved0   : 1;   /* [20] = 0         */
        uint32_t l           : 1;   /* [21] L           */
        uint32_t d           : 1;   /* [22] D           */
        uint32_t a           : 1;   /* [23] = 1         */
        uint32_t marker      : 4;   /* [27:24] = 0b0100 */
        uint32_t cond        : 4;   /* [31:28]          */
    } neon_load_store_single;

    struct {  /* Adv SIMD data-processing dispatch fields (0xF2/F3,
                 bits[27:25]=001). Bit positions of u/bit23/opc/c are
                 fixed across the A7.4 sub-spaces, so they serve as the
                 top-level discriminators. A7.4. */
        uint32_t vm     : 4;   /* [3:0]            */
        uint32_t c      : 1;   /* [4]              */
        uint32_t m      : 1;   /* [5]              */
        uint32_t q      : 1;   /* [6]              */
        uint32_t n      : 1;   /* [7]              */
        uint32_t opc    : 4;   /* [11:8]           */
        uint32_t vd     : 4;   /* [15:12]          */
        uint32_t vn     : 4;   /* [19:16]          */
        uint32_t size   : 2;   /* [21:20]          */
        uint32_t d      : 1;   /* [22]             */
        uint32_t bit23  : 1;   /* [23]             */
        uint32_t u      : 1;   /* [24]             */
        uint32_t marker : 3;   /* [27:25] = 001    */
        uint32_t cond   : 4;   /* [31:28]          */
    } neon_data_3reg;

    struct {  /* AND/EOR/SUB/RSB/ADD/ADC/SBC/RSC/TST/TEQ/CMP/CMN/ORR/MOV/BIC/MVN. */
        uint32_t operand2   : 12;
        uint32_t rd         : 4;
        uint32_t rn         : 4;
        uint32_t s          : 1;
        uint32_t opcode     : 4;
        uint32_t i          : 1;
        uint32_t reserved1  : 2;
        uint32_t cond       : 4;
    } data_processing;

    struct {  /* BX Rm. */
        uint32_t rd         : 4;
        uint32_t reserved1  : 24;
        uint32_t cond       : 4;
    } branch_exchange;

    struct {  /* LDRH / STRH / LDRSB / LDRSH — register-offset form. */
        uint32_t rm         : 4;
        uint32_t reserved1  : 1;
        uint32_t h          : 1;
        uint32_t s          : 1;
        uint32_t reserved2  : 5;
        uint32_t rd         : 4;
        uint32_t rn         : 4;
        uint32_t l          : 1;
        uint32_t w          : 1;
        uint32_t reserved3  : 1;
        uint32_t u          : 1;
        uint32_t p          : 1;
        uint32_t reserved4  : 3;
        uint32_t cond       : 4;
    } half_word_signed_transfer_register;

    struct {  /* LDRH / STRH / LDRSB / LDRSH — immediate-offset form. */
        uint32_t offset_low : 4;
        uint32_t reserved1  : 1;
        uint32_t h          : 1;
        uint32_t s          : 1;
        uint32_t reserved2  : 1;
        uint32_t offset_high: 4;
        uint32_t rd         : 4;
        uint32_t rn         : 4;
        uint32_t l          : 1;
        uint32_t w          : 1;
        uint32_t reserved3  : 1;
        uint32_t u          : 1;
        uint32_t p          : 1;
        uint32_t reserved4  : 3;
        uint32_t cond       : 4;
    } half_word_signed_transfer_immediate;

    struct {  /* LDR / STR / LDRB / STRB. */
        uint32_t offset     : 12;
        uint32_t rd         : 4;
        uint32_t rn         : 4;
        uint32_t l          : 1;
        uint32_t w          : 1;
        uint32_t b          : 1;
        uint32_t u          : 1;
        uint32_t p          : 1;
        uint32_t i          : 1;
        uint32_t reserved1  : 2;
        uint32_t cond       : 4;
    } single_data_transfer;

    struct {  /* Undefined Instruction encoding (class 0b011 + bit[4]=1). */
        uint32_t reserved1  : 4;
        uint32_t reserved2  : 1;
        uint32_t reserved3  : 20;
        uint32_t reserved4  : 3;
        uint32_t cond       : 4;
    } undefined;

    struct {  /* LDM / STM. */
        uint32_t register_list : 16;
        uint32_t rn            : 4;
        uint32_t l             : 1;
        uint32_t w             : 1;
        uint32_t s             : 1;
        uint32_t u             : 1;
        uint32_t p             : 1;
        uint32_t reserved1     : 3;
        uint32_t cond          : 4;
    } block_data_transfer;

    struct {  /* B / BL. Offset is sign-extended, scaled << 2. */
        int32_t  offset    : 24;
        uint32_t l         : 1;
        uint32_t reserved1 : 3;
        uint32_t cond      : 4;
    } branch;

    struct {  /* LDC / STC. */
        uint32_t offset     : 8;
        uint32_t cp_num     : 4;
        uint32_t crd        : 4;
        uint32_t rn         : 4;
        uint32_t l          : 1;
        uint32_t w          : 1;
        uint32_t n          : 1;
        uint32_t u          : 1;
        uint32_t p          : 1;
        uint32_t reserved1  : 3;
        uint32_t cond       : 4;
    } coproc_data_transfer;

    struct {  /* CDP. */
        uint32_t crm        : 4;
        uint32_t reserved1  : 1;
        uint32_t cp         : 3;
        uint32_t cp_num     : 4;
        uint32_t crd        : 4;
        uint32_t crn        : 4;
        uint32_t cp_opc     : 4;
        uint32_t reserved2  : 4;
        uint32_t cond       : 4;
    } coproc_data_operation;

    struct {  /* MCR / MRC. */
        uint32_t crm        : 4;
        uint32_t reserved1  : 1;
        uint32_t cp         : 3;
        uint32_t cp_num     : 4;
        uint32_t rd         : 4;
        uint32_t crn        : 4;
        uint32_t l          : 1;
        uint32_t cp_opc     : 3;
        uint32_t reserved2  : 4;
        uint32_t cond       : 4;
    } coproc_register_transfer;

    struct {  /* SWI (SVC). */
        uint32_t ignored   : 24;
        uint32_t reserved1 : 4;
        uint32_t cond      : 4;
    } software_interrupt;

    struct {  /* DSP saturating multiply / accumulate (v5TE+). */
        uint32_t rm         : 4;
        uint32_t reserved1  : 1;
        uint32_t x          : 1;
        uint32_t y          : 1;
        uint32_t reserved2  : 1;
        uint32_t rs         : 4;
        uint32_t rd         : 4;
        uint32_t rn         : 4;
        uint32_t reserved3  : 1;
        uint32_t op1        : 2;
        uint32_t reserved4  : 5;
        uint32_t cond       : 4;
    } dsp_extension;
};
static_assert(sizeof(ArmOpcode) == 4, "ArmOpcode must be 32 bits");
