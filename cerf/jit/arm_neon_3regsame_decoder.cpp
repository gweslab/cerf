#include "arm_neon_3regsame_decoder.h"

#include "../core/cerf_emulator.h"
#include "arm_neon.h"
#include "arm_neon_3same_fp_arith.h"
#include "arm_neon_3same_fp_fma.h"
#include "arm_neon_3same_fp_min_max.h"
#include "arm_neon_3same_fp_mul_acc.h"
#include "arm_neon_3same_fp_abs_compare.h"
#include "arm_neon_3same_fp_compare.h"
#include "arm_neon_3same_fp_recip_step.h"
#include "arm_neon_3same_fp_pair_add.h"
#include "arm_neon_3same_fp_pair_min_max.h"
#include "arm_neon_sat.h"
#include "arm_neon_simd_3same.h"
#include "arm_opcode.h"
#include "decoded_insn.h"
#include "place_fns.h"

REGISTER_SERVICE(ArmNeon3RegSameDecoder);

bool ArmNeon3RegSameDecoder::Decode(DecodedInsn* insn, ArmOpcode op) {
    /* VADD/VSUB (integer): opc=1000, C=0; U=0 -> VADD (A8.8.282),
       U=1 -> VSUB (A8.8.414). */
    if (op.neon_data_3reg.opc == 0x8u && op.neon_data_3reg.c == 0u) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = op.neon_data_3reg.u ? ArmNeonSimd3Same::kS3Sub
                                              : ArmNeonSimd3Same::kS3Add;
        insn->place_fn  = &PlaceNeonData3Same;
        return true;
    }

    /* Logical ops: opc=0001, C=1.
       U=0 size 00/01/10/11 -> VAND/VBIC/VORR/VORN (A8.8.287/289/360/358);
       U=1 size 00/01/10/11 -> VEOR/VBSL/VBIT/VBIF (A8.8.315/A8.8.290). */
    if (op.neon_data_3reg.opc == 0x1u && op.neon_data_3reg.c == 1u) {
        uint32_t op_sel = 0u;
        if (op.neon_data_3reg.u == 0u) {
            switch (op.neon_data_3reg.size) {
                case 0u: op_sel = ArmNeonSimd3Same::kS3And; break;
                case 1u: op_sel = ArmNeonSimd3Same::kS3Bic; break;
                case 2u: op_sel = ArmNeonSimd3Same::kS3Orr; break;
                default: op_sel = ArmNeonSimd3Same::kS3Orn; break;  /* size==3 */
            }
        } else {
            switch (op.neon_data_3reg.size) {
                case 0u: op_sel = ArmNeonSimd3Same::kS3Eor; break;
                case 1u: op_sel = ArmNeonSimd3Same::kS3Bsl; break;
                case 2u: op_sel = ArmNeonSimd3Same::kS3Bit; break;
                default: op_sel = ArmNeonSimd3Same::kS3Bif; break;  /* size==3 */
            }
        }
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = op_sel;
        insn->place_fn  = &PlaceNeonData3Same;
        return true;
    }

    /* VMUL (A8.8.350): opc=1001, C=1. bit24 = op bit (not U):
       0 -> integer VMUL, 1 -> polynomial VMUL.P8. */
    if (op.neon_data_3reg.opc == 0x9u && op.neon_data_3reg.c == 1u) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = op.neon_data_3reg.u ? ArmNeonSimd3Same::kS3MulP
                                              : ArmNeonSimd3Same::kS3Mul;
        insn->place_fn  = &PlaceNeonData3Same;
        return true;
    }

    /* VTST / VCEQ (integer): opc=1000, C=1.
       U=0 -> VTST (A8.8.421), U=1 -> VCEQ (A8.8.291). */
    if (op.neon_data_3reg.opc == 0x8u && op.neon_data_3reg.c == 1u) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = op.neon_data_3reg.u ? ArmNeonSimd3Same::kS3Ceq
                                              : ArmNeonSimd3Same::kS3Tst;
        insn->place_fn  = &PlaceNeonData3Same;
        return true;
    }

    /* VCGT (register, integer): opc=0011, C=0. U=0 signed, U=1 unsigned. */
    if (op.neon_data_3reg.opc == 0x3u && op.neon_data_3reg.c == 0u) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = op.neon_data_3reg.u ? ArmNeonSimd3Same::kS3CgtU
                                              : ArmNeonSimd3Same::kS3CgtS;
        insn->place_fn  = &PlaceNeonData3Same;
        return true;
    }

    /* VCGE (register, integer): opc=0011, C=1. U=0 signed, U=1 unsigned. */
    if (op.neon_data_3reg.opc == 0x3u && op.neon_data_3reg.c == 1u) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = op.neon_data_3reg.u ? ArmNeonSimd3Same::kS3CgeU
                                              : ArmNeonSimd3Same::kS3CgeS;
        insn->place_fn  = &PlaceNeonData3Same;
        return true;
    }

    /* VMAX / VMIN (integer): opc=0110. C=op: 0->VMAX, 1->VMIN. */
    if (op.neon_data_3reg.opc == 0x6u) {
        uint32_t op_sel;
        if (op.neon_data_3reg.c == 0u) {
            op_sel = op.neon_data_3reg.u ? ArmNeonSimd3Same::kS3MaxU
                                         : ArmNeonSimd3Same::kS3MaxS;
        } else {
            op_sel = op.neon_data_3reg.u ? ArmNeonSimd3Same::kS3MinU
                                         : ArmNeonSimd3Same::kS3MinS;
        }
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = op_sel;
        insn->place_fn  = &PlaceNeonData3Same;
        return true;
    }

    /* VHADD (integer): opc=0000, C=0. U=0 signed, U=1 unsigned. */
    if (op.neon_data_3reg.opc == 0x0u && op.neon_data_3reg.c == 0u) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = op.neon_data_3reg.u ? ArmNeonSimd3Same::kS3HaddU
                                              : ArmNeonSimd3Same::kS3HaddS;
        insn->place_fn  = &PlaceNeonData3Same;
        return true;
    }

    /* VHSUB (integer): opc=0010, C=0. */
    if (op.neon_data_3reg.opc == 0x2u && op.neon_data_3reg.c == 0u) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = op.neon_data_3reg.u ? ArmNeonSimd3Same::kS3HsubU
                                              : ArmNeonSimd3Same::kS3HsubS;
        insn->place_fn  = &PlaceNeonData3Same;
        return true;
    }

    /* VRHADD (integer): opc=0001, C=0. */
    if (op.neon_data_3reg.opc == 0x1u && op.neon_data_3reg.c == 0u) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = op.neon_data_3reg.u ? ArmNeonSimd3Same::kS3RhaddU
                                              : ArmNeonSimd3Same::kS3RhaddS;
        insn->place_fn  = &PlaceNeonData3Same;
        return true;
    }

    /* VABD (integer): opc=0111, C=0. */
    if (op.neon_data_3reg.opc == 0x7u && op.neon_data_3reg.c == 0u) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = op.neon_data_3reg.u ? ArmNeonSimd3Same::kS3AbdU
                                              : ArmNeonSimd3Same::kS3AbdS;
        insn->place_fn  = &PlaceNeonData3Same;
        return true;
    }

    /* VSHL (register): opc=0100, C=0. */
    if (op.neon_data_3reg.opc == 0x4u && op.neon_data_3reg.c == 0u) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = op.neon_data_3reg.u ? ArmNeonSimd3Same::kS3ShlU
                                              : ArmNeonSimd3Same::kS3ShlS;
        insn->place_fn  = &PlaceNeonData3Same;
        return true;
    }

    /* VRSHL (register): opc=0101, C=0. */
    if (op.neon_data_3reg.opc == 0x5u && op.neon_data_3reg.c == 0u) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = op.neon_data_3reg.u ? ArmNeonSimd3Same::kS3RshlU
                                              : ArmNeonSimd3Same::kS3RshlS;
        insn->place_fn  = &PlaceNeonData3Same;
        return true;
    }

    /* VMLA / VMLS (integer): opc=1001, C=0. bit24 is op-bit (not U):
       0 -> VMLA, 1 -> VMLS (A8.8.336). */
    if (op.neon_data_3reg.opc == 0x9u && op.neon_data_3reg.c == 0u) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = op.neon_data_3reg.u ? ArmNeon::kAccMls
                                              : ArmNeon::kAccMla;
        insn->place_fn  = &PlaceNeonData3SameAcc;
        return true;
    }

    /* VABA (integer): opc=0111, C=1. */
    if (op.neon_data_3reg.opc == 0x7u && op.neon_data_3reg.c == 1u) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = op.neon_data_3reg.u ? ArmNeon::kAccAbaU
                                              : ArmNeon::kAccAbaS;
        insn->place_fn  = &PlaceNeonData3SameAcc;
        return true;
    }

    /* VQADD (saturating): opc=0000, C=1. */
    if (op.neon_data_3reg.opc == 0x0u && op.neon_data_3reg.c == 1u) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = op.neon_data_3reg.u ? ArmNeonSat::kSatAddU
                                              : ArmNeonSat::kSatAddS;
        insn->place_fn  = &PlaceNeonData3SameSat;
        return true;
    }

    /* VQSUB (saturating): opc=0010, C=1. */
    if (op.neon_data_3reg.opc == 0x2u && op.neon_data_3reg.c == 1u) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = op.neon_data_3reg.u ? ArmNeonSat::kSatSubU
                                              : ArmNeonSat::kSatSubS;
        insn->place_fn  = &PlaceNeonData3SameSat;
        return true;
    }

    /* VQSHL (register, saturating): opc=0100, C=1. */
    if (op.neon_data_3reg.opc == 0x4u && op.neon_data_3reg.c == 1u) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = op.neon_data_3reg.u ? ArmNeonSat::kSatShlU
                                              : ArmNeonSat::kSatShlS;
        insn->place_fn  = &PlaceNeonData3SameSat;
        return true;
    }

    /* VQRSHL (register, saturating + rounding right): opc=0101, C=1. */
    if (op.neon_data_3reg.opc == 0x5u && op.neon_data_3reg.c == 1u) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = op.neon_data_3reg.u ? ArmNeonSat::kSatRshlU
                                              : ArmNeonSat::kSatRshlS;
        insn->place_fn  = &PlaceNeonData3SameSat;
        return true;
    }

    /* VPADD (integer pairwise): opc=1011, C=1, U=0 fixed. */
    if (op.neon_data_3reg.opc == 0xBu && op.neon_data_3reg.c == 1u &&
        op.neon_data_3reg.u == 0u) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = ArmNeon::kPwAdd;
        insn->place_fn  = &PlaceNeonData3SamePairwise;
        return true;
    }

    /* VPMAX / VPMIN (integer pairwise): opc=1010. C=op: 0->VPMAX, 1->VPMIN. */
    if (op.neon_data_3reg.opc == 0xAu) {
        uint32_t op_sel;
        if (op.neon_data_3reg.c == 0u) {
            op_sel = op.neon_data_3reg.u ? ArmNeon::kPwMaxU
                                         : ArmNeon::kPwMaxS;
        } else {
            op_sel = op.neon_data_3reg.u ? ArmNeon::kPwMinU
                                         : ArmNeon::kPwMinS;
        }
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = op_sel;
        insn->place_fn  = &PlaceNeonData3SamePairwise;
        return true;
    }

    /* VADD.F32 / VSUB.F32 (A8.8.283 / A8.8.415): opc=1101, B=0, U=0.
       bit[21] (high bit of `size`) selects: 0=ADD, 1=SUB. */
    if (op.neon_data_3reg.opc == 0xDu &&
        op.neon_data_3reg.c == 0u &&
        op.neon_data_3reg.u == 0u) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = ((op.neon_data_3reg.size >> 1) & 1u)
                              ? ArmNeon3SameFpArith::kSub
                              : ArmNeon3SameFpArith::kAdd;
        insn->place_fn  = &PlaceNeonData3SameFpArith;
        return true;
    }
    /* VABD.F32 (A8.8.279): opc=1101, B=0, U=1, bit[21]=1. */
    if (op.neon_data_3reg.opc == 0xDu &&
        op.neon_data_3reg.c == 0u &&
        op.neon_data_3reg.u == 1u &&
        ((op.neon_data_3reg.size >> 1) & 1u) == 1u) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = ArmNeon3SameFpArith::kAbd;
        insn->place_fn  = &PlaceNeonData3SameFpArith;
        return true;
    }
    /* VPADD.F32 (A8.8.363): opc=1101, C=0, U=1, bit[21]=0. */
    if (op.neon_data_3reg.opc == 0xDu &&
        op.neon_data_3reg.c == 0u &&
        op.neon_data_3reg.u == 1u &&
        ((op.neon_data_3reg.size >> 1) & 1u) == 0u) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->place_fn  = &PlaceNeonData3SameFpPairAdd;
        return true;
    }
    /* VMUL.F32 (A8.8.351): opc=1101, B=1, U=1, bit[21]=0. */
    if (op.neon_data_3reg.opc == 0xDu &&
        op.neon_data_3reg.c == 1u &&
        op.neon_data_3reg.u == 1u &&
        ((op.neon_data_3reg.size >> 1) & 1u) == 0u) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = ArmNeon3SameFpArith::kMul;
        insn->place_fn  = &PlaceNeonData3SameFpArith;
        return true;
    }
    /* VMLA.F32 / VMLS.F32 (A8.8.337): opc=1101, B=1, U=0. bit[21]=op selects. */
    if (op.neon_data_3reg.opc == 0xDu &&
        op.neon_data_3reg.c == 1u &&
        op.neon_data_3reg.u == 0u) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = ((op.neon_data_3reg.size >> 1) & 1u)
                              ? ArmNeon3SameFpMulAcc::kMls
                              : ArmNeon3SameFpMulAcc::kMla;
        insn->place_fn  = &PlaceNeonData3SameFpMulAcc;
        return true;
    }
    /* VFMA / VFMS (A8.8.317): opc=1100, C=1, U=0. bit[21]=op selects. */
    if (op.neon_data_3reg.opc == 0xCu &&
        op.neon_data_3reg.c == 1u &&
        op.neon_data_3reg.u == 0u) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = ((op.neon_data_3reg.size >> 1) & 1u)
                              ? ArmNeon3SameFpFma::kFms
                              : ArmNeon3SameFpFma::kFma;
        insn->place_fn  = &PlaceNeonData3SameFpFma;
        return true;
    }
    /* VMAX.F32 / VMIN.F32 (A8.8.335): opc=1111, B=0, U=0. bit[21]=op selects. */
    if (op.neon_data_3reg.opc == 0xFu &&
        op.neon_data_3reg.c == 0u &&
        op.neon_data_3reg.u == 0u) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = ((op.neon_data_3reg.size >> 1) & 1u)
                              ? ArmNeon3SameFpMinMax::kMin
                              : ArmNeon3SameFpMinMax::kMax;
        insn->place_fn  = &PlaceNeonData3SameFpMinMax;
        return true;
    }
    /* VPMAX.F32 / VPMIN.F32 (A8.8.366): opc=1111, C=0, U=1. bit[21]=op selects. */
    if (op.neon_data_3reg.opc == 0xFu &&
        op.neon_data_3reg.c == 0u &&
        op.neon_data_3reg.u == 1u) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = ((op.neon_data_3reg.size >> 1) & 1u)
                              ? ArmNeon3SameFpPairMinMax::kMin
                              : ArmNeon3SameFpPairMinMax::kMax;
        insn->place_fn  = &PlaceNeonData3SameFpPairMinMax;
        return true;
    }
    /* VCEQ.F32 / VCGE.F32 / VCGT.F32 (A8.8.291 / A8.8.293 / A8.8.295):
       opc=1110, C=0. (u, bit[21]): (0,0)→EQ, (1,0)→GE, (1,1)→GT.
       (0,1) is UND in this slot — return false to fall to PlaceNeonUnimplemented. */
    if (op.neon_data_3reg.opc == 0xEu &&
        op.neon_data_3reg.c == 0u) {
        const uint32_t u_bit = op.neon_data_3reg.u;
        const uint32_t b21   = (op.neon_data_3reg.size >> 1) & 1u;
        uint32_t op_sel;
        if (u_bit == 0u && b21 == 0u)      op_sel = ArmNeon3SameFpCompare::kEq;
        else if (u_bit == 1u && b21 == 0u) op_sel = ArmNeon3SameFpCompare::kGe;
        else if (u_bit == 1u && b21 == 1u) op_sel = ArmNeon3SameFpCompare::kGt;
        else return false;
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = op_sel;
        insn->place_fn  = &PlaceNeonData3SameFpCompare;
        return true;
    }
    /* VACGE / VACGT (A8.8.281): opc=1110, C=1, U=1. bit[21]=op selects
       ACGE (0) / ACGT (1). */
    if (op.neon_data_3reg.opc == 0xEu &&
        op.neon_data_3reg.c == 1u &&
        op.neon_data_3reg.u == 1u) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = ((op.neon_data_3reg.size >> 1) & 1u)
                              ? ArmNeon3SameFpAbsCompare::kAcgt
                              : ArmNeon3SameFpAbsCompare::kAcge;
        insn->place_fn  = &PlaceNeonData3SameFpAbsCompare;
        return true;
    }
    /* VRECPS / VRSQRTS (A8.8.385 / A8.8.392): opc=1111, C=1, U=0.
       bit[21]=op selects RECPS (0) / RSQRTS (1). */
    if (op.neon_data_3reg.opc == 0xFu &&
        op.neon_data_3reg.c == 1u &&
        op.neon_data_3reg.u == 0u) {
        insn->cond      = 14;
        insn->immediate = op.word;
        insn->op1       = ((op.neon_data_3reg.size >> 1) & 1u)
                              ? ArmNeon3SameFpRecipStep::kRsqrts
                              : ArmNeon3SameFpRecipStep::kRecps;
        insn->place_fn  = &PlaceNeonData3SameFpRecipStep;
        return true;
    }

    return false;
}
