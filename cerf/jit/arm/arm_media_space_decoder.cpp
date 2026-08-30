#include "arm_media_space_decoder.h"

#include "../../boards/board_context.h"
#include "../../core/cerf_emulator.h"
#include "../../cpu/arm_processor_config.h"
#include "arm_opcode.h"
#include "cpu_state.h"
#include "decoded_insn.h"
#include "place_fns.h"

REGISTER_SERVICE(ArmMediaSpaceDecoder);

bool ArmMediaSpaceDecoder::ShouldRegister() {
    return emu_.Get<BoardContext>().GetCpuArch() == CpuArch::Arm;
}

void ArmMediaSpaceDecoder::OnReady() {
    processor_config_ = &emu_.Get<ArmProcessorConfig>();
}

/* DDI 0406C.c Table A5-16 (p. A5-209): op1 = insn[24:20], op2 = insn[7:5].
   DDI 0100I A3.16.1 (p. A3-33): "The meaning of unallocated instructions in
   the media instruction space is UNDEFINED on all versions of the ARM
   architecture"; every allocated Table A3-3 row is ARMv6 and above. */
bool ArmMediaSpaceDecoder::Decode(DecodedInsn* insn, ArmOpcode op) {
    if (!processor_config_->HasCp15V6()) {
        return false;
    }
    const uint32_t op1 = (op.word >> 20) & 0x1Fu;
    const uint32_t op2 = (op.word >>  5) & 0x7u;
    /* Table A5-16 op1 == 11111, op2 == 111: UDF, permanently UNDEFINED
       (p. A8-758). */
    if (op1 == 0x1Fu && op2 == 0x7u) {
        return false;
    }
    /* SBFX (1101x, x10), BFC/BFI (1110x, x00), UBFX (1111x, x10) rows of
       Table A5-16 (p. A5-209). */
    if (((op1 & 0x1Eu) == 0x1Au && (op2 & 0x3u) == 0x2u) ||
        ((op1 & 0x1Eu) == 0x1Cu && (op2 & 0x3u) == 0x0u) ||
        ((op1 & 0x1Eu) == 0x1Eu && (op2 & 0x3u) == 0x2u)) {
        return DecodeBitfield(insn, op);
    }
    /* Table A5-16 op1 == 01xxx: Table A5-19, p. A5-212. */
    if ((op1 & 0x18u) == 0x08u) {
        return DecodePackSatReverse(insn, op);
    }
    /* Parallel addition and subtraction, signed Table A5-17 (p. A5-210) and
       unsigned Table A5-18 (p. A5-211): both allocate insn[21:20] 01, 10 and
       11 and insn[7:5] 000, 001, 010, 011, 100 and 111; "Other encodings in
       this space are UNDEFINED". */
    if ((op1 & 0x18u) == 0x00u) {
        if ((op1 & 0x3u) == 0x0u || op2 == 0x5u || op2 == 0x6u) {
            return false;
        }
        return MarkArmUnimplemented(insn, op.word);
    }
    /* Table A5-16 (p. A5-209) op1 10xxx: signed multiply, signed and unsigned
       divide, Table A5-20 (p. A5-213), op1 = insn[22:20], op2 = insn[7:5];
       "Other encodings in this space are UNDEFINED". */
    if ((op1 & 0x18u) == 0x10u) {
        switch (op1 & 0x7u) {
        case 0x0u:
        case 0x4u:
            if ((op2 & 0x4u) != 0x0u) {
                return false;
            }
            return DecodeDualMultiply(insn, op, (op1 & 0x7u) == 0x4u);
        case 0x5u:
            if ((op2 & 0x6u) != 0x0u && (op2 & 0x6u) != 0x6u) {
                return false;
            }
            return DecodeMostSignificantMultiply(insn, op);
        case 0x1u:
        case 0x3u:
            if (op2 != 0x0u || !processor_config_->HasIntegerDivide()) {
                return false;
            }
            return MarkArmUnimplemented(insn, op.word);
        default:
            return false;
        }
    }
    /* USAD8 (A8-792) / USADA8 (A8-794) row (11000, 000) of Table A5-16. */
    if (op1 == 0x18u && op2 == 0x0u) {
        return MarkArmUnimplemented(insn, op.word);
    }
    /* A5.4 (p. A5-209): "Other encodings in this space are UNDEFINED." */
    return false;
}

bool ArmMediaSpaceDecoder::DecodeBitfield(DecodedInsn* insn, ArmOpcode op) {
    if (!processor_config_->HasBitField()) {
        return false;
    }

    const uint32_t bits27_21 = (op.word >> 21) & 0x7Fu;
    const uint32_t bits6_4   = (op.word >>  4) & 0x07u;

    const uint32_t rd        = (op.word >> 12) & 0xFu;
    const uint32_t rn        =  op.word        & 0xFu;
    const uint32_t lsb       = (op.word >>  7) & 0x1Fu;
    const uint32_t field_bits16_20 = (op.word >> 16) & 0x1Fu;

    if (bits27_21 == 0x3Eu && bits6_4 == 0x1u) {
        /* BFI (Rn != 15) or BFC (Rn == 15). bits[20:16] encode msb. */
        const uint32_t msb   = field_bits16_20;
        if (msb < lsb || rd == ArmGpr::kR15) {
            return false;  /* UNPREDICTABLE encodings */
        }
        const uint32_t width = msb - lsb + 1u;
        const uint32_t mask  = (width == 32u)
            ? 0xFFFFFFFFu
            : (((1u << width) - 1u) << lsb);
        insn->rd        = rd;
        insn->rn        = rn;
        insn->op1       = lsb;
        insn->rs        = width;
        insn->immediate = mask;
        insn->place_fn  = (rn == 15u) ? &PlaceBfc : &PlaceBfi;
        return true;
    }

    if ((bits27_21 == 0x3Du || bits27_21 == 0x3Fu) && bits6_4 == 0x5u) {
        /* SBFX (0x3D) or UBFX (0x3F). bits[20:16] encode width-1. */
        const uint32_t width = field_bits16_20 + 1u;
        if (lsb + width > 32u || rd == ArmGpr::kR15 || rn == ArmGpr::kR15) {
            return false;
        }
        insn->rd        = rd;
        insn->rn        = rn;
        insn->op1       = lsb;
        insn->rs        = width;
        insn->place_fn  = (bits27_21 == 0x3Du) ? &PlaceSbfx : &PlaceUbfx;
        return true;
    }

    return false;
}

/* DDI 0406C.c Table A5-20 (p. A5-213) op1 000 and 100; A1 encodings SMLAD
   p. A8-622, SMUAD A8-642, SMLSD A8-632, SMUSD A8-650, SMLALD A8-628,
   SMLSLD A8-634. A == 1111 SEEs SMUAD / SMUSD; the long rows take RdHi from
   bits[19:16], RdLo from bits[15:12], "if dHi == dLo then UNPREDICTABLE". */
bool ArmMediaSpaceDecoder::DecodeDualMultiply(DecodedInsn* insn, ArmOpcode op,
                                              bool is_long) {
    const uint32_t rd = (op.word >> 16) & 0xFu;
    const uint32_t ra = (op.word >> 12) & 0xFu;
    const uint32_t rm = (op.word >>  8) & 0xFu;
    const uint32_t rn =  op.word        & 0xFu;

    if (rd == ArmGpr::kR15 || rm == ArmGpr::kR15 || rn == ArmGpr::kR15) {
        return false;
    }
    if (is_long && (ra == ArmGpr::kR15 || ra == rd)) {
        return false;
    }

    const bool no_acc = !is_long && ra == ArmGpr::kR15;

    insn->op1      = is_long ? 2u : (no_acc ? 0u : 1u);
    insn->n        = (op.word >> 6) & 0x1u;
    insn->u        = (op.word >> 5) & 0x1u;
    insn->rd       = rd;
    insn->rs       = ra;
    insn->rm       = rm;
    insn->rn       = rn;
    insn->place_fn = &PlaceDualMultiply;
    return true;
}

/* DDI 0406C.c Table A5-20 (p. A5-213) op1 101; A1 encodings SMMLA p. A8-636,
   SMMLS A8-638, SMMUL A8-640: bits[7:4] are sub-sub-R-1, A == 1111 selects
   SMMUL, and SMMLS adds "|| a == 15 then UNPREDICTABLE" (p. A8-638). */
bool ArmMediaSpaceDecoder::DecodeMostSignificantMultiply(DecodedInsn* insn,
                                                         ArmOpcode    op) {
    const uint32_t rd  = (op.word >> 16) & 0xFu;
    const uint32_t ra  = (op.word >> 12) & 0xFu;
    const uint32_t rm  = (op.word >>  8) & 0xFu;
    const uint32_t rn  =  op.word        & 0xFu;
    const uint32_t sub = (op.word >>  6) & 0x1u;

    if (rd == ArmGpr::kR15 || rm == ArmGpr::kR15 || rn == ArmGpr::kR15) {
        return false;
    }
    if (sub != 0u && ra == ArmGpr::kR15) {
        return false;
    }

    insn->op1      = (ra == ArmGpr::kR15) ? 0u : 1u;
    insn->n        = sub;
    insn->u        = (op.word >> 5) & 0x1u;
    insn->rd       = rd;
    insn->rs       = ra;
    insn->rm       = rm;
    insn->rn       = rn;
    insn->place_fn = &PlaceMostSignificantMultiply;
    return true;
}

/* DDI 0406C.c A8.8.193 SSAT A1 (p. A8-652): "cond 0110101 sat_imm Rd imm5 sh
   0 1 Rn", saturate_to = UInt(sat_imm)+1, "(shift_t, shift_n) =
   DecodeImmShift(sh:'0', imm5)", "if d == 15 || n == 15 then UNPREDICTABLE". */
bool ArmMediaSpaceDecoder::DecodeSignedSaturate(DecodedInsn* insn,
                                                ArmOpcode    op) {
    const uint32_t sat_imm = (op.word >> 16) & 0x1Fu;
    const uint32_t rd      = (op.word >> 12) & 0xFu;
    const uint32_t imm5    = (op.word >>  7) & 0x1Fu;
    const uint32_t sh      = (op.word >>  6) & 0x1u;
    const uint32_t rn      =  op.word        & 0xFu;

    if (rd == ArmGpr::kR15 || rn == ArmGpr::kR15) {
        return false;
    }

    uint32_t shift_t = 0;
    uint32_t shift_n = 0;
    DecodeImmShift(sh << 1, imm5, &shift_t, &shift_n);

    insn->rd        = rd;
    insn->rn        = rn;
    insn->op1       = shift_t;
    insn->rs        = shift_n;
    insn->immediate = sat_imm + 1u;
    insn->place_fn  = &PlaceSsat;
    return true;
}

/* DDI 0406C.c Table A5-19 (p. A5-212): op1 = insn[22:20], A = insn[19:16],
   op2 = insn[7:5]; other encodings in this space are UNDEFINED. */
bool ArmMediaSpaceDecoder::DecodePackSatReverse(DecodedInsn* insn,
                                                ArmOpcode    op) {
    const uint32_t fop1     = (op.word >> 20) & 0x7u;
    const uint32_t fop2     = (op.word >>  5) & 0x7u;
    const uint32_t rd       = (op.word >> 12) & 0xFu;
    const uint32_t rm       =  op.word        & 0xFu;
    const uint32_t bits11_8 = (op.word >>  8) & 0xFu;

    if ((fop2 & 0x1u) == 0u) {
        /* PKH (000, xx0), SSAT (01x, xx0), USAT (11x, xx0) rows of
           Table A5-19 (p. A5-212). */
        if ((fop1 & 0x6u) == 0x2u) {
            return DecodeSignedSaturate(insn, op);
        }
        if (fop1 == 0x0u || (fop1 & 0x6u) == 0x6u) {
            return MarkArmUnimplemented(insn, op.word);
        }
        return false;
    }

    if (fop2 == 0x1u || fop2 == 0x5u) {
        const bool rev_cell = (fop1 == 0x3u) ||
                              (fop1 == 0x7u && fop2 == 0x5u);
        if (rev_cell) {
            /* REV (011, 001) A8-562 / REV16 (011, 101) A8-564 /
               REVSH (111, 101) A8-566 - Table A5-19 (p. A5-212). */
            if (!processor_config_->HasRev()) {
                return false;
            }
            if (((op.word >> 16) & 0xFu) != 0xFu || bits11_8 != 0xFu) {
                return false;
            }
            if (rd == ArmGpr::kR15 || rm == ArmGpr::kR15) {
                return false;
            }
            insn->rd       = rd;
            insn->rm       = rm;
            insn->place_fn = (fop2 == 0x1u) ? &PlaceRev
                           : (fop1 == 0x3u) ? &PlaceRev16
                                            : &PlaceRevsh;
            return true;
        }
        if (fop2 == 0x1u && ((fop1 & 0x3u) == 0x2u)) {
            /* SSAT16 (010, 001) / USAT16 (110, 001) - Table A5-19. */
            return MarkArmUnimplemented(insn, op.word);
        }
        if (fop2 == 0x1u && fop1 == 0x7u) {
            /* RBIT (111, 001), v6T2 - Table A5-19. */
            if (!processor_config_->HasBitField()) {
                return false;
            }
            return MarkArmUnimplemented(insn, op.word);
        }
        if (fop2 == 0x5u && fop1 == 0x0u) {
            /* SEL (000, 101) - Table A5-19. */
            return MarkArmUnimplemented(insn, op.word);
        }
        return false;
    }

    if (fop2 == 0x3u) {
        const uint32_t a = (op.word >> 16) & 0xFu;
        switch (fop1) {
        case 0x2u:
        case 0x3u:
        case 0x6u:
        case 0x7u: {
            if (a != 0xFu) {
                /* SXTAB (010) / SXTAH (011) / UXTAB (110) / UXTAH (111),
                   A != 1111 rows - Table A5-19 (p. A5-212). */
                return MarkArmUnimplemented(insn, op.word);
            }
            /* SXTB A8-730 / SXTH A8-734 / UXTB A8-812 / UXTH A8-816,
               A == 1111 rows - Table A5-19 (p. A5-212). */
            if (!processor_config_->HasExtendRotate()) {
                return false;
            }
            if ((bits11_8 & 0x3u) != 0u) {
                return false;  /* bits[9:8] SBZ */
            }
            if (rd == ArmGpr::kR15 || rm == ArmGpr::kR15) {
                return false;
            }
            insn->rd  = rd;
            insn->rm  = rm;
            /* bits[11:8] = rot << 2 | 0. The rot field is bits[11:10]. */
            insn->op1 = (bits11_8 >> 2) & 0x3u;
            switch (fop1) {
            case 0x2u: insn->place_fn = &PlaceSxtb; break;
            case 0x3u: insn->place_fn = &PlaceSxth; break;
            case 0x6u: insn->place_fn = &PlaceUxtb; break;
            default:   insn->place_fn = &PlaceUxth; break;
            }
            return true;
        }
        case 0x0u:
        case 0x4u:
            /* SXT(A)B16 (000) / UXT(A)B16 (100) rows - Table A5-19. */
            return MarkArmUnimplemented(insn, op.word);
        default:
            return false;
        }
    }

    return false;
}
