#pragma once

#include <cstdint>

#include "block_context.h"
#include "decoded_insn.h"

enum class TlbAccess { kRead, kWrite, kReadWrite };

/* DDI 0406C.c A8.4.3 (p. A8-293): Shift_C(amount == 0) returns carry_in,
   else the shifter carry-out; A5.2.4 (p. A5-200): the immediate form's
   carry-out is a translate-time constant. */
enum class DpLogicalCarry { kUnchanged, kSetImm, kClearImm, kFromDl };

/* ARM DDI 0100I A7.1, p. A7-3. */
inline uint32_t ArmPcReadValue(const DecodedInsn* d, const BlockContext* ctx) {
    return d->guest_address + (ctx->thumb ? 4u : 8u);
}

uint8_t* EmitAbortDataTail(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* EmitArmInterworkingFullEax(uint8_t* cursor);
uint8_t* EmitArmInterworkingMaskEax(uint8_t* cursor);
uint8_t* EmitCoprocDataOperationUnimplementedFatal(uint8_t* cursor, DecodedInsn* d,
                                                   BlockContext* ctx);
uint8_t* EmitCoprocDataTransferUnimplementedFatal(uint8_t* cursor, DecodedInsn* d,
                                                  BlockContext* ctx);
uint8_t* EmitCoprocUnimplementedFatal(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* EmitCpsrUserModeTest(uint8_t* cursor);
uint8_t* EmitRaiseUndIfUserMode(uint8_t* cursor, DecodedInsn* d,
                                BlockContext* ctx);
uint8_t* EmitCp15CacheOp(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* EmitCp15RegisterTransfer(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* EmitCp15TlbOp(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* EmitDpArithFlagTail(uint8_t* cursor, DecodedInsn* d);
uint8_t* EmitDpLogicalFlagTail(uint8_t* cursor, DpLogicalCarry carry);
uint8_t* EmitDpPcWriteTail(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
void EmitHalfwordAlignCheck(uint8_t*& cursor, bool sctlr_a,
                            uint8_t** align_fault_label,
                            uint8_t** cross_label);
uint8_t* EmitHalfwordSignedTransfer(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* EmitIoIrqPreciseBackout(uint8_t* cursor, DecodedInsn* d,
                                 BlockContext* ctx);
uint8_t* EmitIoIrqPreciseBackoutIfIo(uint8_t* cursor, DecodedInsn* d,
                                     BlockContext* ctx);
uint8_t* EmitItStateStore(uint8_t* cursor, uint32_t itstate);
uint8_t* EmitLoadedPcWrite(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* EmitMsrWriteTail(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* EmitNeonCoreToScalar(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* EmitNeonScalarToCore(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* EmitNeonVdup(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* EmitRaiseUndAndReturn(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* EmitRaiseUndTail(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* EmitSpsrModeGuard(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* EmitSwap(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* EmitTlbFastPath(uint8_t* cursor, BlockContext* ctx, TlbAccess access);
uint8_t* EmitTranslateAccess(uint8_t* cursor, BlockContext* ctx,
                             TlbAccess access, bool unpriv);
uint8_t* EmitVfpBlockTransfer(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* EmitVfpDataOperation(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* EmitVfpDataTransfer(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* EmitVfpRegisterTransfer(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* EmitVfpSingleMove(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* EmitVfpSingleMoveIdx(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx,
                              uint32_t sn);
uint8_t* EmitVfpSingleTransfer(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* EmitVfpSystemRegTransfer(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* PlaceArmUnimplemented(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceBfc(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceBfi(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceBlockDataTransfer(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceBlxReg(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceBranch(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceBx(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceBxImpl(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx, bool is_call);
uint8_t* PlaceCbz(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceClrex(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceClz(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceCoprocDataOperation(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceCoprocDataTransfer(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceCoprocExtension(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceCoprocRegisterTransfer(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceCoprocessorPermissionCheck(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceCps(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceDataProcessing(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceDataProcessingReg(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceDataProcessingShiftedReg(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceDualMultiply(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceHalfwordMultiply(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceLdrex(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceLoadStoreExtension(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceMRSorMSR(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceMSRImmediate(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceMostSignificantMultiply(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceMovt(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceMovw(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceMultiply(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonData2RegBitcount(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonData2RegBitwiseNot(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonData2RegCompareZero(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonData2RegCvtHalfSingle(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonData2RegCvtIntFp(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonData2RegNarrow(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonData2RegPairwiseAddLong(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonData2RegReciprocal(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonData2RegReverse(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonData2RegSatAbsNeg(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonData2RegScalarLong(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonData2RegScalarMul(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonData2RegScalarMulSat(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonData2RegScalarMulhSat(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonData2RegShuffle(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonData2RegSwap(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonData2RegUnaryArith(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonData2RegWiden(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonData3DiffLen(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonData3DiffLenAbs(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonData3DiffLenHN(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonData3DiffLenMul(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonData3DiffLenMulSat(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonData3Same(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonData3SameAcc(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonData3SameFpAbsCompare(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonData3SameFpArith(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonData3SameFpCompare(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonData3SameFpFma(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonData3SameFpMinMax(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonData3SameFpMulAcc(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonData3SameFpPairAdd(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonData3SameFpPairMinMax(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonData3SameFpRecipStep(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonData3SamePairwise(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonData3SameSat(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonDataVext(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonDataVtbl(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonLoadStoreInterleaved(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonLoadStoreMultiple(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonLoadStoreSingleLane(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonOneRegImm(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonShiftImm(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonShiftImmNarrow(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonShiftImmNarrowSat(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonShiftImmSat(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonShiftImmWiden(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNeonUnimplemented(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceNop(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceR15ModifiedHelper(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

uint8_t* EmitJumpCacheProbe(uint8_t* cursor, BlockContext* ctx);
uint8_t* EmitChainToBlock(uint8_t* cursor, BlockContext* ctx,
                          uint32_t target_va, uint32_t slot);
uint8_t* PlaceRev(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceRev16(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceRevsh(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceRfe(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceSaturatingArith(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceSbfx(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceSingleDataTransfer(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceSrs(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceSsat(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceStrex(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceSvc(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceSxtb(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceSxth(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceTableBranchByte(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceThumbBlPrefix(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceThumbBlSuffix(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceThumbBlxImm(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceUbfx(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceUxtb(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceUxth(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);
uint8_t* PlaceWfi(uint8_t* cursor, DecodedInsn* d, BlockContext* ctx);

inline bool MarkArmUnimplemented(DecodedInsn* insn, uint32_t word) {
    insn->immediate = word;
    insn->place_fn  = &PlaceArmUnimplemented;
    return true;
}
