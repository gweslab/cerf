#pragma once

#include <cstdint>

#include "block_context.h"
#include "decoded_insn.h"

/* Bit i (i < 16) = Ri in LDM/STM list; high half encodes S/SPANS/
   LOAD/W. W gets Rn OR'd at bits[27:24] so the helper knows which
   base to write back — dropping the OR loses the writeback target. */
constexpr uint32_t kLdmStmS     = 1u << 16;
constexpr uint32_t kLdmStmSpans = 2u << 16;
constexpr uint32_t kLdmStmLoad  = 4u << 16;
constexpr uint32_t kLdmStmW     = 8u << 16;

/* Standard ArmPlaceFn signature — assigned to DecodedInsn::place_fn
   by the decoder, invoked once per guest instruction during emit. */
uint8_t* PlaceIdleLoop                     (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNop                          (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceRaiseUndefinedException      (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceRaiseAbortPrefetchException  (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceShifterCarryOut              (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceArithmeticExtension          (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceDataProcessing               (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceDataProcessingCALL           (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceMSRImmediate                 (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceWfi                          (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceMRSorMSR                     (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceSoftwareInterrupt            (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceSyscall                      (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceIllegalCoproc                (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceCoprocDataTransfer           (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceCoprocDataOperation          (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceCoprocRegisterTransfer       (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceCoprocExtension              (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceBKPT                         (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlacePowerDown                    (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceR15ModifiedHelper            (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceBx                           (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceBxCALL                       (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlacePushShadowStack              (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceBranch                       (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceInterruptPoll                (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceEntrypointMiddle             (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceEntrypointEnd                (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceSingleDataTransfer           (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceSingleDataTransferCALL       (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceSingleDataTransferRET        (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceBlockDataTransfer            (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceLoadStoreExtension           (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceDoubleLoadStoreExtension     (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceQAdd                         (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceDspMul                       (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceClz                          (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceMovw                         (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceMovt                         (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceBlxReg                       (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceBfi                          (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceBfc                          (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceSbfx                         (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceUbfx                         (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceRev                          (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceRev16                        (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceRevsh                        (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceSxtb                         (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceSxth                         (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceUxtb                         (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceUxth                         (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceLdrex                        (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceStrex                        (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceThumbBranchAndExchange       (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceThumbLoadAddressPC           (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceThumbLongBranch              (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceRfe                          (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceSrs                          (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

/* Non-ArmPlaceFn translators called by sibling Place fns. */

uint8_t* PlaceUpdateLLX86Flags(uint8_t* cursor);

uint8_t* PlaceUpdateX86Flags(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx, bool fAdd);

uint8_t* PlaceDecodedShift(uint8_t* cursor, const DecodedInsn* d, BlockContext* ctx,
                           uint8_t result_reg, bool needs_shifter_carry_out);

uint8_t* PlaceBasicTwoAddrWithResult(uint8_t* cursor,
                                     uint8_t       arith_reg_opcode,
                                     uint8_t       arith_imm32_opcode,
                                     uint8_t       arith_imm32_reg,
                                     DecodedInsn*  d,
                                     BlockContext* ctx,
                                     uint8_t       immediate_reg);

uint8_t* PlaceBasicTwoAddrNoResult(uint8_t* cursor,
                                   uint8_t       arith_reg_opcode,
                                   uint8_t       arith_imm32_opcode,
                                   uint8_t       arith_imm32_reg,
                                   DecodedInsn*  d,
                                   BlockContext* ctx,
                                   uint8_t       immediate_reg,
                                   bool          fOpcodeHasSideEffect);

uint8_t* PlaceBxImpl(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx, bool is_call);

uint8_t* PlaceCoprocessorPermissionCheck(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* EmitRaiseUndAndReturn(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

/* Loud stub: a real-but-unimplemented coprocessor instruction. Runtime FATAL
   naming the access. CoprocEmitters use this (not the UND path) for an access
   that is architecturally valid on the core but not yet emitted. */
uint8_t* EmitCoprocUnimplementedFatal(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

/* In: EAX = raw target. Out: EAX masked, CPSR.T set iff bit 0 was set.
   Do NOT call from Thumb-state emit — Thumb PC writes halfword-align
   without ISA switch (ddi0406c §A2.3.1, lines 2062-2066). */
uint8_t* EmitArmInterworkingMaskEax(uint8_t* cursor);

uint8_t* EmitCp15RegisterTransfer(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* EmitCp15Cacr(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* EmitVfpRegisterTransfer(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* EmitVfpDataTransfer    (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* EmitVfpDataOperation   (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* EmitVfpSystemRegTransfer(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* EmitVfpSingleMove       (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* EmitVfpSingleMoveIdx    (uint8_t* cursor, DecodedInsn* d, BlockContext* ctx,
                                  uint32_t sn);

uint8_t* EmitVfpBlockTransfer(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* EmitVfpSingleTransfer(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* EmitNeonVdup(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonLoadStoreMultiple(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonLoadStoreInterleaved(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonLoadStoreSingleLane(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonUnimplemented(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonData3Same(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonData3SameAcc(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonData3SameSat(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonData3SamePairwise(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonShiftImm(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonOneRegImm(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonShiftImmSat(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonShiftImmNarrow(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonShiftImmNarrowSat(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonShiftImmWiden(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonData3DiffLen(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonData3DiffLenHN(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonData3DiffLenAbs(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonData3DiffLenMul(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonData3DiffLenMulSat(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonData2RegScalarLong(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonData2RegScalarMulSat(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonData2RegScalarMulhSat(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonData2RegScalarMul(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonData2RegReverse(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonData2RegBitcount(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonData2RegBitwiseNot(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonData2RegUnaryArith(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonData2RegCompareZero(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonData2RegPairwiseAddLong(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonData2RegSatAbsNeg(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonData2RegSwap(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonData2RegShuffle(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonData2RegNarrow(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonData2RegWiden(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonData2RegReciprocal(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonData2RegCvtIntFp(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonData2RegCvtHalfSingle(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonData3SameFpArith(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonData3SameFpMulAcc(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonData3SameFpMinMax(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonData3SameFpFma(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonData3SameFpPairAdd(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonData3SameFpPairMinMax(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonData3SameFpCompare(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonData3SameFpAbsCompare(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonData3SameFpRecipStep(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonDataVext(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceNeonDataVtbl(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* EmitNeonCoreToScalar(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* EmitNeonScalarToCore(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

/* SWP / SWPB — atomic swap (PlaceLoadStoreExtension d->op1 == 0 path). */
uint8_t* EmitSwap(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

/* LDRH / STRH / LDRSB / LDRSH — miscellaneous halfword + signed-byte
   transfer encodings (PlaceLoadStoreExtension d->op1 != 0 path). */
uint8_t* EmitHalfwordSignedTransfer(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* EmitCp15CacheOp(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* EmitCp15TlbOp(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

/* DO NOT reuse EDI for the writeback transient — EDI holds the
   per-block PC-cache for consecutive LDR [PC+imm] reads in the
   same 1 KB page and gets silently clobbered otherwise. EBP is
   the writeback slot (callee-saved, survives MMU helper CALLs). */
uint8_t* PlaceSingleDataTransferOffset(uint8_t*           cursor,
                                       const DecodedInsn* d,
                                       BlockContext*      ctx,
                                       bool*              needs_alignment_check);

/* Inline DTLB probe emitted before the slow Translate*Helper call.
   ECX = guest EA in; EAX = host pointer out (or null fault from the helper). */
enum class TlbAccess { kRead, kWrite, kReadWrite };
uint8_t* EmitTlbFastPath(uint8_t* cursor, BlockContext* ctx, TlbAccess access);

struct PbdtCrossPageInputs {
    uint8_t* possibly_two_pages;
    uint8_t* abort_destination;
    uint8_t* raise_unaligned;
    uint8_t  block_size;
    uint32_t pc_store_offset;
    bool     alignment_check_on;
};

struct PbdtCrossPageOutputs {
    uint8_t* perform_io_transfer_multiple;
    uint8_t* done_instruction_2;
};

uint8_t* EmitLdmStmCrossPage(uint8_t*                    cursor,
                             DecodedInsn*                d,
                             BlockContext*               ctx,
                             const PbdtCrossPageInputs&  in,
                             PbdtCrossPageOutputs*       out);

struct SdtLdrWordInputs {
    uint8_t* abort_exception_or_io;     /* JZ-label fixup at body entry */
    uint8_t* raise_alignment_exception; /* JNZ-label fixup on alignment fault */
    bool     needs_alignment_check;
    bool     alignment_check_on;
    bool     base_restored_abort_model;
    bool     memory_before_writeback_model;
    bool     cache_hit;                 /* PC-cache fast path skipped translation */
};

uint8_t* EmitLdrWord(uint8_t*                  cursor,
                     DecodedInsn*              d,
                     BlockContext*             ctx,
                     const SdtLdrWordInputs&   in);
