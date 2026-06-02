#pragma once

#include <cstdint>

#include "jit_block.h"

struct DecodedInsn;
struct BlockContext;

using ArmPlaceFn = uint8_t* (*)(uint8_t* code_cursor, DecodedInsn* d, BlockContext* ctx);

struct DecodedInsn {
    /* Translator function pointer assigned by the decoder. */
    ArmPlaceFn place_fn;

    /* The original guest VA of this instruction, raw (before FCSE
       fold). */
    uint32_t guest_address;

    /* Post-FCSE guest VA — used as the lookup key in the block
       index and in TLB entries. */
    uint32_t actual_guest_address;

    /* Operand2 — for data-processing instructions this is the
       12-bit encoded shifter operand (immediate or register+shift
       descriptor). Decoders fill it directly from opcode bits[11:0]. */
    uint32_t operand2;

    /* rs reused as BFI/SBFX/UBFX width (1..32); 4 bits silently
       truncate width 16..32 → wrong src_mask. */
    uint32_t rd            : 4;
    uint32_t rn            : 4;
    uint32_t rm            : 4;
    uint32_t rs            : 6;
    uint16_t register_list;

    /* Coprocessor fields — for MCR/MRC/CDP/LDC/STC. */
    uint32_t cp            : 3;
    uint32_t crd           : 4;
    uint32_t crm           : 4;
    uint32_t crn           : 4;
    uint32_t cp_num        : 4;
    uint32_t cp_opc        : 4;

    /* Signed offset — load/store immediate offsets, branch displacement. */
    int32_t offset;

    /* Generic immediate for SWI / data-proc / etc. */
    uint32_t immediate;

    /* Reserved word used by extension placers — left here for binary
       compatibility with the place-fn calling convention. */
    uint32_t reserved3;

    /* Encoding bit-flags from the original opcode. */
    uint32_t b             : 1;
    uint32_t cond          : 4;
    uint32_t h             : 1;
    uint32_t i             : 1;
    uint32_t l             : 1;
    uint32_t n             : 1;
    uint32_t op1           : 5;  /* widened for BFI/BFC/SBFX/UBFX lsb (0..31) */
    uint32_t opcode        : 4;
    uint32_t p             : 1;
    uint32_t s             : 1;
    uint32_t u             : 1;
    uint32_t w             : 1;
    uint32_t x1            : 4;
    uint32_t x2            : 12;
    uint32_t r15_modified  : 1;  /* set when the decoder proves the insn writes PC */
    /* DO NOT collapse into r15_modified — plain BX / MOV PC, Rm set
       r15_modified but are NOT exception returns (ddi0406c §A2.3.1
       line 2079 lists them as interworking branches); the emit-side
       CPSR-from-SPSR restore (§B1.8) must fire ONLY for this subset. */
    uint32_t is_exception_return : 1;

    /* DSP instruction extras. */
    uint32_t x             : 1;
    uint32_t y             : 1;

    /* Per-block flag-pack optimiser tracking — which CPSR flag bits
       this insn consumes (FlagsNeeded) and which it produces
       (FlagsSet). The peephole pass uses these to drop redundant
       packs when the next consumer overwrites the producer. */
    uint8_t flags_needed   : 4;
    uint8_t flags_set      : 4;

    /* Thumb-only extra fields used by instructions whose form has
       no direct ARM equivalent. */
    uint32_t h2            : 1;
    uint32_t h_two_bits    : 2;
    uint32_t rs_hs         : 3;
    uint32_t word8         : 8;

    /* Pointers wired up by the block emitter — the entry point this
       insn belongs to and (for forward branches) the location of
       the rel32 displacement that the back-patcher needs to fix
       once the branch target is known. */
    JitBlock* entry_point;
    uint8_t*  jmp_fixup_location;
};
