#include "arm_neon_shift_imm_decoder.h"

#include "../core/cerf_emulator.h"
#include "arm_neon_sat.h"
#include "arm_neon_shift_imm.h"
#include "arm_opcode.h"
#include "decoded_insn.h"
#include "place_fns.h"

REGISTER_SERVICE(ArmNeonShiftImmDecoder);

bool ArmNeonShiftImmDecoder::Decode(DecodedInsn* insn, ArmOpcode op) {
    const uint32_t L_   = (op.word >> 7) & 1u;
    const uint32_t imm6 = (op.word >> 16) & 0x3Fu;
    const uint32_t L_imm6 = (L_ << 6) | imm6;
    if ((L_imm6 >> 3) == 0u) {
        /* L:imm6 == 0000xxx → 1-reg-modified-immediate (A7.4.6). */
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->place_fn  = &PlaceNeonOneRegImm;
        return true;
    }

    const uint32_t opc = op.neon_data_3reg.opc;
    if (opc == 0x0u) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = op.neon_data_3reg.u
                              ? ArmNeonShiftImm::kSiShrU
                              : ArmNeonShiftImm::kSiShrS;
        insn->place_fn  = &PlaceNeonShiftImm;
        return true;
    }
    if (opc == 0x2u) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = op.neon_data_3reg.u
                              ? ArmNeonShiftImm::kSiRshrU
                              : ArmNeonShiftImm::kSiRshrS;
        insn->place_fn  = &PlaceNeonShiftImm;
        return true;
    }
    /* VSRA: opc=0001, U->S/U (A8.8.402). */
    if (opc == 0x1u) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = op.neon_data_3reg.u
                              ? ArmNeonShiftImm::kSiSraU
                              : ArmNeonShiftImm::kSiSraS;
        insn->place_fn  = &PlaceNeonShiftImm;
        return true;
    }
    /* VRSRA: opc=0011, U->S/U (A8.8.393). */
    if (opc == 0x3u) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = op.neon_data_3reg.u
                              ? ArmNeonShiftImm::kSiRsraU
                              : ArmNeonShiftImm::kSiRsraS;
        insn->place_fn  = &PlaceNeonShiftImm;
        return true;
    }
    /* VSHL imm (opc=0x5, u=0) vs VSLI (opc=0x5, u=1). VSHL fixes bit24=0;
       VSLI fixes bit24=1. */
    if (opc == 0x5u) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = op.neon_data_3reg.u
                              ? ArmNeonShiftImm::kSiSli
                              : ArmNeonShiftImm::kSiShl;
        insn->place_fn  = &PlaceNeonShiftImm;
        return true;
    }
    /* VSRI: opc=0x4, U fixed to 1 (A8.8.403). */
    if (opc == 0x4u && op.neon_data_3reg.u == 1u) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = ArmNeonShiftImm::kSiSri;
        insn->place_fn  = &PlaceNeonShiftImm;
        return true;
    }
    /* VQSHL imm: opc=0x7 (op-bit=1). U=0 -> VQSHL.S, U=1 -> VQSHL.U
       (A8.8.380). */
    if (opc == 0x7u) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = op.neon_data_3reg.u
                              ? ArmNeonSat::kSatShlImmU
                              : ArmNeonSat::kSatShlImmS;
        insn->place_fn  = &PlaceNeonShiftImmSat;
        return true;
    }
    /* VQSHLU: opc=0x6, U=1 only (signed-in, unsigned-out). U=0 with
       opc=0x6 is explicitly UNDEFINED per A8.8.380 line 48690. */
    if (opc == 0x6u && op.neon_data_3reg.u == 1u) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = ArmNeonSat::kSatShlImmSU;
        insn->place_fn  = &PlaceNeonShiftImmSat;
        return true;
    }
    /* VSHRN (A8.8.399) / VRSHRN (A8.8.390): opc=0x8, u=0.
       bit6: 0 truncating, 1 rounding. */
    if (opc == 0x8u && op.neon_data_3reg.u == 0u) {
        const uint32_t bit6 = (op.word >> 6) & 1u;
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = bit6 ? ArmNeonShiftImm::kSiRshrn
                               : ArmNeonShiftImm::kSiShrn;
        insn->place_fn  = &PlaceNeonShiftImmNarrow;
        return true;
    }
    /* VQSHRUN (A8.8.381) / VQRSHRUN (A8.8.378): opc=0x8, u=1. Signed src,
       unsigned out. bit6 discriminates truncating vs rounding. */
    if (opc == 0x8u && op.neon_data_3reg.u == 1u) {
        const uint32_t bit6 = (op.word >> 6) & 1u;
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = bit6 ? ArmNeonSat::kSatRShrnSU
                               : ArmNeonSat::kSatShrnSU;
        insn->place_fn  = &PlaceNeonShiftImmNarrowSat;
        return true;
    }
    /* VQSHRN (A8.8.381) / VQRSHRN (A8.8.378): opc=0x9. bit6: 0 truncating,
       1 rounding. U=0 signed, U=1 unsigned. */
    if (opc == 0x9u) {
        const uint32_t bit6 = (op.word >> 6) & 1u;
        uint32_t op_sel;
        if (op.neon_data_3reg.u == 0u) {
            op_sel = bit6 ? ArmNeonSat::kSatRShrnS
                          : ArmNeonSat::kSatShrnS;
        } else {
            op_sel = bit6 ? ArmNeonSat::kSatRShrnU
                          : ArmNeonSat::kSatShrnU;
        }
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = op_sel;
        insn->place_fn  = &PlaceNeonShiftImmNarrowSat;
        return true;
    }
    /* VSHLL T1/A1 (A8.8.397): opc=0xA, L=0 (place_fn checks). U=0 signed,
       U=1 unsigned. T2/A2 lives in 2-reg-misc and is not matched here. */
    if (opc == 0xAu) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = op.neon_data_3reg.u
                              ? ArmNeonShiftImm::kSiShllU
                              : ArmNeonShiftImm::kSiShllS;
        insn->place_fn  = &PlaceNeonShiftImmWiden;
        return true;
    }
    return false;
}
