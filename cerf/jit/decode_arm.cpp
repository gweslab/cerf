#include "arm_decoder.h"

#include <intrin.h>

#include "../core/cerf_emulator.h"
#include "../cpu/arm_processor_config.h"
#include "arm_cpu.h"
#include "arm_opcode.h"
#include "cpu_state.h"
#include "decoded_insn.h"
#include "neon_unconditional_decoder.h"
#include "place_fns.h"

REGISTER_SERVICE(ArmDecoder);

void ArmDecoder::OnReady() {
    processor_config_           = &emu_.Get<ArmProcessorConfig>();
    cpu_                        = &emu_.Get<ArmCpu>();
    neon_unconditional_decoder_ = &emu_.Get<NeonUnconditionalDecoder>();
}

bool ArmDecoder::DecodeArm(DecodedInsn* insn, uint32_t opcode_word) {
    ArmOpcode op;
    op.word = opcode_word;

    insn->r15_modified       = 0;
    insn->is_exception_return = 0;
    insn->cond               = op.generic.cond;

    if (insn->cond == 15) {
        if (DecodeArmUnconditional(insn, op)) return true;
        if (processor_config_->HasArmv5UnconditionalSpace()) goto RaiseException;
        insn->place_fn = &PlaceNop;
        insn->cond     = 14;
        return true;
    }

    switch (op.generic.instruction_class) {
    case 0:
        /* 000 — DataProcessing OR Multiply OR SingleDataSwap OR
           BX OR BKPT OR LDRH/STRH/LDRSB/LDRSH OR LDRD/STRD OR
           QADD-family OR DSP-Mul-family OR ControlExtension. */
        if (DecodeArmLdrexStrex(insn, op)) return true;
        if (op.control_extension.reserved3 == 2u && op.control_extension.reserved2 == 0u &&
            ((op.control_extension.operand2 & 0x10u) == 0u ||
             (op.control_extension.operand2 & 0x90u) == 0x10u)) {
            switch ((op.control_extension.operand2 >> 4) & 0xFu) {
            case 0:  /* MSR (register form) or MRS. */
                insn->place_fn = &PlaceMRSorMSR;
                insn->s        = 1;
                insn->rd       = op.control_extension.rd;
                insn->rn       = op.control_extension.rn;
                insn->rm       = op.control_extension.operand2 & 0xFu;
                insn->op1      = op.control_extension.op1;
                if (insn->op1 == 0 && insn->rd == ArmGpr::kR15) {
                    insn->r15_modified = true;
                }
                return true;

            case 1:
                switch (op.control_extension.op1) {
                case 1:  /* BX. */
                    insn->place_fn     = &PlaceBx;
                    insn->rd           = op.branch_exchange.rd;
                    insn->r15_modified = true;
                    return true;
                case 3:
                    /* Rd==15 writes PC slot without r15_modified —
                       bypasses JIT branch-dispatch, corrupts flow. */
                    if (!processor_config_->HasClz()) {
                        goto RaiseException;
                    }
                    insn->rd       = op.control_extension.rd;
                    insn->rm       = op.control_extension.operand2 & 0xFu;
                    if (insn->rd == ArmGpr::kR15 || insn->rm == ArmGpr::kR15) {
                        goto RaiseException;
                    }
                    insn->place_fn = &PlaceClz;
                    return true;
                default:
                    goto RaiseException;
                }
                break;

            case 3:
                if (!processor_config_->HasBlxReg()) goto RaiseException;
                insn->rd           = op.control_extension.operand2 & 0xFu;
                if (insn->rd == ArmGpr::kR15) goto RaiseException;
                insn->place_fn     = &PlaceBlxReg;
                insn->r15_modified = true;
                return true;

            case 5:
                /* QADD / QSUB / QDADD / QDSUB (DSP extension). */
                if (!processor_config_->HasDsp()) {
                    goto RaiseException;
                }
                insn->rn = op.dsp_extension.rn;
                insn->rm = op.dsp_extension.rm;
                insn->rd = op.dsp_extension.rd;
                if (insn->rn == ArmGpr::kR15 || insn->rm == ArmGpr::kR15 ||
                    insn->rd == ArmGpr::kR15) {
                    goto RaiseException;
                }
                insn->op1      = op.dsp_extension.op1;
                insn->place_fn = &PlaceQAdd;
                return true;

            case 7:
                if (op.control_extension.op1 == 1) {  /* BKPT. */
                    insn->place_fn = &PlaceBKPT;
                    return true;
                }
                goto RaiseException;

            case 8: case 0xA: case 0xC: case 0xE:
                /* SMLA<x><y> / SMLAW<y> / SMULW<y> / SMLAL<x><y> /
                   SMUL<x><y> — DSP multiply family. */
                if (!processor_config_->HasDsp()) {
                    goto RaiseException;
                }
                insn->rn = op.dsp_extension.rn;
                insn->rm = op.dsp_extension.rm;
                insn->rd = op.dsp_extension.rd;
                insn->rs = op.dsp_extension.rs;
                if (insn->rn == ArmGpr::kR15 || insn->rm == ArmGpr::kR15 ||
                    insn->rd == ArmGpr::kR15 || insn->rs == ArmGpr::kR15) {
                    goto RaiseException;
                }
                insn->op1      = op.dsp_extension.op1;
                insn->x        = op.dsp_extension.x;
                insn->y        = op.dsp_extension.y;
                insn->place_fn = &PlaceDspMul;
                return true;

            default:
                goto RaiseException;
            }
        } else if (op.arithmetic_extension.reserved2 == 0u &&
                   op.arithmetic_extension.reserved1 == 9u) {
            /* Multiply / multiply-accumulate / long-multiply family. */
            insn->rm  = op.arithmetic_extension.rm;
            insn->rs  = op.arithmetic_extension.rs;
            insn->rn  = op.arithmetic_extension.rn;
            insn->rd  = op.arithmetic_extension.rd;
            insn->op1 = op.arithmetic_extension.op1;
            if ((insn->op1 != 0 && (insn->rd == 15 || insn->rn == 15 ||
                                    insn->rm == 15 || insn->rs == 15)) ||
                (insn->op1 == 0 && (insn->rd == 15 || insn->rn != 0 ||
                                    insn->rm == 15 || insn->rs == 15))) {
                goto RaiseException;
            }
            insn->place_fn = &PlaceArithmeticExtension;
            insn->s        = op.arithmetic_extension.s;
            return true;
        } else if (op.load_store_extension.reserved1 == 1u &&
                   op.load_store_extension.reserved2 == 1u &&
                   !(op.load_store_extension.p == 0 &&
                     op.load_store_extension.op1 == 0)) {
            if (op.double_load_store_extension.reserved3 == 0u &&
                op.double_load_store_extension.reserved2 == 3u) {
                /* LDRD / STRD. */
                if (!processor_config_->HasLoadStoreDouble()) {
                    goto RaiseException;
                }
                insn->l  = !op.double_load_store_extension.l;
                insn->rm = op.double_load_store_extension.rm;
                insn->rs = op.double_load_store_extension.rs;
                insn->rd = op.double_load_store_extension.rd;
                if ((insn->rd & 1u) || insn->rd == ArmGpr::kR14) {
                    /* Rd must be even, R14 disallowed (R14 even
                       would alias with R15 in the pair). */
                    goto RaiseException;
                }
                insn->rn = op.double_load_store_extension.rn;
                insn->w  = op.double_load_store_extension.w;
                insn->p  = op.double_load_store_extension.p;
                insn->i  = op.double_load_store_extension.i;
                insn->u  = op.double_load_store_extension.u;
                if (insn->i == 0 && insn->rm == 15) {
                    goto RaiseException;
                }
                if (insn->p == 0) {
                    /* Post-index always writes back. */
                    insn->w = 1;
                }
                if (insn->w && insn->rn == ArmGpr::kR15) {
                    goto RaiseException;
                }
                insn->place_fn = &PlaceDoubleLoadStoreExtension;
                return true;
            }

            /* Halfword / signed-byte load/store OR SWP/SWPB. */
            insn->op1       = op.load_store_extension.op1;
            insn->rm        = op.load_store_extension.rm;
            insn->rs        = op.load_store_extension.rs;
            insn->rd        = op.load_store_extension.rd;
            insn->rn        = op.load_store_extension.rn;
            insn->w         = op.load_store_extension.w;
            insn->p         = op.load_store_extension.p;
            insn->l         = op.load_store_extension.l;
            insn->reserved3 = op.half_word_signed_transfer_register.reserved3;
            if (insn->op1 == 0) {
                /* SWP / SWPB — R15 disallowed as Rd/Rm/Rn. */
                if (insn->rd == 15 || insn->rm == 15 || insn->rn == 15) {
                    goto RaiseException;
                }
            } else {
                /* Halfword/signed-byte transfer. */
                if (insn->reserved3 == 0 && insn->rm == 15) {
                    goto RaiseException;
                }
                if (insn->p == 0) {
                    insn->w = 1;  /* post-index implies writeback */
                }
                if (insn->w && insn->rn == ArmGpr::kR15) {
                    goto RaiseException;
                }
                if (insn->l && insn->rd == ArmGpr::kR15) {
                    insn->r15_modified = true;
                }
            }
            insn->place_fn = &PlaceLoadStoreExtension;
            insn->b        = op.load_store_extension.b;
            insn->u        = op.load_store_extension.u;
            insn->offset =
                (op.half_word_signed_transfer_immediate.offset_high << 4) |
                 op.half_word_signed_transfer_immediate.offset_low;
            insn->h = op.half_word_signed_transfer_register.h;
            insn->s = op.half_word_signed_transfer_register.s;
            return true;
        }
        /* Fall through to data-processing decode. */
        goto DataProcessing;

    case 1:
        if (op.control_extension.reserved3 == 6u &&
            op.control_extension.reserved2 == 0u &&
            (op.control_extension.op1 & 1u) == 1u) {
            /* ARMv7 WFI hint, encoding A1 (ARM ARM §A8.8.425): MSR-imm
               with mask=0, Rd=SBO=15, imm12=3. Other imm12 hints
               (NOP/YIELD/WFE/SEV/DBG) stay on the PlaceMSRImmediate
               empty-mask no-op path. */
            if (op.control_extension.op1 == 1u &&
                op.control_extension.rn  == 0u &&
                op.control_extension.rd  == 15u &&
                op.control_extension.operand2 == 3u) {
                insn->place_fn = &PlaceWfi;
                return true;
            }
            insn->place_fn  = &PlaceMSRImmediate;
            insn->s         = 1;
            insn->op1       = op.control_extension.op1;
            insn->rn        = op.control_extension.rn;
            insn->immediate = _rotr(
                static_cast<uint8_t>(op.control_extension.operand2),
                (op.control_extension.operand2 >> 8) << 1);
            return true;
        }
        goto DataProcessing;

    case 2:
        /* 010 — SingleDataTransfer. */
        goto SingleDataTransfer;

    case 3:
        /* 011 — SingleDataTransfer OR Undefined (which v6T2+ reuses
           for the bit-field insertion / extraction family). */
        if (op.undefined_extension.reserved1 == 1u) {
            if (DecodeArmBitfield(insn, op))   return true;
            if (DecodeArmClass3Misc(insn, op)) return true;
            goto RaiseException;
        }
        goto SingleDataTransfer;

    case 4: {
        /* 100 — BlockDataTransfer (LDM / STM). */
        insn->rn = op.block_data_transfer.rn;
        if (insn->rn == ArmGpr::kR15) {
            goto RaiseException;
        }
        insn->place_fn     = &PlaceBlockDataTransfer;
        insn->register_list = op.block_data_transfer.register_list;
        insn->l            = op.block_data_transfer.l;
        insn->w            = op.block_data_transfer.w;
        insn->s            = op.block_data_transfer.s;
        insn->u            = op.block_data_transfer.u;
        insn->p            = op.block_data_transfer.p;
        if ((insn->register_list & (1u << ArmGpr::kR15)) && insn->l) {
            insn->r15_modified = true;
            if (insn->s) {
                insn->is_exception_return = 1;
            }
        }
        return true;
    }

    case 5:
        /* 101 — Branch / Branch with Link. The encoded offset is
           sign-extended 24-bit, scaled << 2; the reference pre-folds
           the absolute destination into d->Offset by adding PC+8. */
        insn->place_fn     = &PlaceBranch;
        insn->offset       = static_cast<int32_t>(
            insn->guest_address + 8u +
            static_cast<uint32_t>(4 * op.branch.offset));
        insn->l            = op.branch.l;
        insn->r15_modified = true;
        return true;

    case 6:
        /* 110 — CoprocDataTransfer (LDC / STC) OR two-register
           coprocessor extension (MCRR / MRRC). */
        if (op.coprocessor_extension.reserved2 == 24u &&
            op.coprocessor_extension.reserved1 == 0u) {
            /* MCRR / MRRC — v5TE+ register-pair coprocessor moves.
               Dispatch to the named Place fn whose default body is
               UND; per-SoC strategies that DO support v5TE coprocs
               can replace it without touching this decoder route. */
            insn->place_fn = &PlaceCoprocExtension;
            insn->offset   = op.coprocessor_extension.offset;
            insn->cp_num   = op.coprocessor_extension.cp_num;
            insn->crd      = op.coprocessor_extension.crd;
            insn->rn       = op.coprocessor_extension.rn;
            insn->x1       = op.coprocessor_extension.x1;
            insn->x2       = op.coprocessor_extension.x2;
            return true;
        }
        insn->w  = op.coproc_data_transfer.w;
        insn->rn = op.coproc_data_transfer.rn;
        insn->p  = op.coproc_data_transfer.p;
        if (insn->p == 0) {
            insn->w = 1;
        }
        if (insn->w && insn->rn == ArmGpr::kR15) {
            goto RaiseException;
        }
        insn->offset = static_cast<uint32_t>(op.coproc_data_transfer.offset) << 2;
        if (!op.coproc_data_transfer.u) {
            insn->offset = static_cast<int32_t>(-insn->offset);
        }
        insn->place_fn = &PlaceCoprocDataTransfer;
        insn->cp_num   = op.coproc_data_transfer.cp_num;
        insn->crd      = op.coproc_data_transfer.crd;
        insn->l        = op.coproc_data_transfer.l;
        insn->n        = op.coproc_data_transfer.n;
        insn->u        = op.coproc_data_transfer.u;
        return true;

    case 7:
        /* 111 — CoprocDataOperation (CDP) OR CoprocRegisterTransfer
           (MCR/MRC) OR SoftwareInterrupt (SWI). */
        if (op.software_interrupt.reserved1 == 15u) {
            if (processor_config_->GenerateSyscalls() &&
                op.software_interrupt.ignored == 0x123456u) {
                insn->place_fn = &PlaceSyscall;
            } else {
                insn->place_fn     = &PlaceSoftwareInterrupt;
                insn->r15_modified = true;
            }
            return true;
        }
        if (op.coproc_data_operation.reserved1 == 0u) {
            insn->place_fn = &PlaceCoprocDataOperation;
            insn->crm      = op.coproc_data_operation.crm;
            insn->cp       = op.coproc_data_operation.cp;
            insn->cp_num   = op.coproc_data_operation.cp_num;
            insn->crd      = op.coproc_data_operation.crd;
            insn->crn      = op.coproc_data_operation.crn;
            insn->cp_opc   = op.coproc_data_operation.cp_opc;
            return true;
        }
        insn->place_fn = &PlaceCoprocRegisterTransfer;
        insn->crm      = op.coproc_register_transfer.crm;
        insn->cp       = op.coproc_register_transfer.cp;
        insn->cp_num   = op.coproc_register_transfer.cp_num;
        insn->rd       = op.coproc_register_transfer.rd;
        insn->crn      = op.coproc_register_transfer.crn;
        insn->l        = op.coproc_register_transfer.l;
        insn->cp_opc   = op.coproc_register_transfer.cp_opc;
        return true;

    default:
        goto RaiseException;
    }

DataProcessing:
    insn->s      = op.data_processing.s;
    insn->opcode = op.data_processing.opcode;
    insn->i      = op.data_processing.i;

    if (processor_config_->HasMovwMovt() && insn->i == 1 && insn->s == 0 &&
        (insn->opcode == 8 || insn->opcode == 10)) {
        insn->rd        = op.data_processing.rd;
        if (insn->rd == ArmGpr::kR15) goto RaiseException;
        insn->immediate = (op.data_processing.rn << 12) |
                          (op.data_processing.operand2 & 0xFFFu);
        insn->place_fn  = (insn->opcode == 8) ? &PlaceMovw : &PlaceMovt;
        return true;
    }

    insn->place_fn = &PlaceDataProcessing;
    insn->operand2 = op.data_processing.operand2;
    if (insn->i) {
        /* 8-bit operand rotated right by 2*rot; pre-fold for the
           emit-time fast path. */
        insn->reserved3 = _rotr(
            static_cast<uint8_t>(insn->operand2),
            (insn->operand2 >> 8) << 1);
    }
    switch (insn->opcode) {
    case 0:  case 1:  case 2:  case 3:
    case 4:  case 5:  case 6:  case 7:
    case 12: case 14:
        /* AND/EOR/SUB/RSB/ADD/ADC/SBC/RSC/ORR/BIC — write Rd. */
        insn->rn = op.data_processing.rn;
        insn->rd = op.data_processing.rd;
        if (insn->rd == ArmGpr::kR15) {
            insn->r15_modified = true;
            if (insn->s) {
                insn->is_exception_return = 1;
            }
        }
        break;

    case 8:  case 9:  case 10: case 11:
        /* TST/TEQ/CMP/CMN — flags-only, no Rd write. */
        insn->rn = op.data_processing.rn;
        insn->rd = 0;
        break;

    case 13: case 15:
        /* MOV / MVN — write Rd, ignore Rn. */
        insn->rd = op.data_processing.rd;
        if (insn->rd == ArmGpr::kR15) {
            insn->r15_modified = true;
            if (insn->s) {
                insn->is_exception_return = 1;
            }
        }
        insn->rm = insn->operand2 & 0xFu;
        break;

    default:
        break;
    }
    return true;

SingleDataTransfer:
    insn->offset    = op.single_data_transfer.offset;
    insn->i         = op.single_data_transfer.i;
    insn->rn        = op.single_data_transfer.rn;
    insn->w         = op.single_data_transfer.w;
    insn->p         = op.single_data_transfer.p;
    insn->u         = op.single_data_transfer.u;
    insn->place_fn  = &PlaceSingleDataTransfer;
    insn->rd        = op.single_data_transfer.rd;
    insn->l         = op.single_data_transfer.l;
    insn->b         = op.single_data_transfer.b;
    insn->operand2  = op.data_processing.operand2;
    if (insn->p == 0) {
        insn->w = 1;  /* post-index implies writeback */
    }
    if (insn->w && insn->rn == ArmGpr::kR15) {
        goto RaiseException;
    }
    if (insn->rd == ArmGpr::kR15 && insn->l) {
        insn->r15_modified = true;
    }
    if (insn->rn == ArmGpr::kR15 && insn->i == 0) {
        /* PC-relative LDR/STR with immediate offset — pre-fold the
           absolute address into reserved3. PC pipeline offset is +8
           in ARM mode, +4 in Thumb mode (this decoder is reused by
           DecodeThumb* helpers that synthesize an ARM equivalent). */
        const uint32_t pipe_off =
            cpu_->State()->cpsr.bits.thumb_mode ? 4u : 8u;
        const uint32_t pc = insn->guest_address + pipe_off;
        insn->reserved3 = insn->u
            ? (pc + insn->offset)
            : (pc - insn->offset);
    }
    if (insn->i && (insn->offset & 0xFu) == ArmGpr::kR15) {
        /* Rm == R15 disallowed in register-offset form. */
        goto RaiseException;
    }
    return true;

RaiseException:
    /* Do NOT force cond=14 here: a conditional undefined encoding whose
       condition fails must do nothing, not trap (DDI0100I A1.2). Forcing
       it defeats the generator's cond guard, faulting the guest where
       ARM720T skips the instruction. */
    insn->immediate = opcode_word;  /* raw bytes for the decode-gap log */
    insn->place_fn  = &PlaceRaiseUndefinedException;
    return false;
}
