#pragma once
#include <cstdint>
#include <cstdio>
#include <functional>
#include <string>
#include "mem.h"

/* ARM condition codes (bits 31:28 of every ARM instruction) */
enum ArmCondition {
    COND_EQ = 0,  /* Z set */
    COND_NE = 1,  /* Z clear */
    COND_CS = 2,  /* C set (HS) */
    COND_CC = 3,  /* C clear (LO) */
    COND_MI = 4,  /* N set */
    COND_PL = 5,  /* N clear */
    COND_VS = 6,  /* V set */
    COND_VC = 7,  /* V clear */
    COND_HI = 8,  /* C set and Z clear */
    COND_LS = 9,  /* C clear or Z set */
    COND_GE = 10, /* N == V */
    COND_LT = 11, /* N != V */
    COND_GT = 12, /* Z clear and N == V */
    COND_LE = 13, /* Z set or N != V */
    COND_AL = 14, /* Always */
    COND_NV = 15  /* Never / unconditional in ARMv5+ */
};

/* PSR (Program Status Register) flags */
#define PSR_N (1u << 31) /* Negative */
#define PSR_Z (1u << 30) /* Zero */
#define PSR_C (1u << 29) /* Carry */
#define PSR_V (1u << 28) /* Overflow */
#define PSR_T (1u << 5)  /* Thumb state */
#define PSR_MODE_MASK 0x1F

/* ARM register indices */
enum {
    REG_SP = 13,
    REG_LR = 14,
    REG_PC = 15,
    REG_CPSR = 16
};

/* Thunk callback: called when ARM code calls a thunked API.
   Returns true if handled. */
typedef std::function<bool(uint32_t addr, uint32_t* regs, EmulatedMemory& mem)> ThunkCallback;

class ArmCpu {
public:
    /* General purpose registers R0-R15 */
    uint32_t r[16];
    /* Current Program Status Register */
    uint32_t cpsr;
    /* Saved PSR (for exception returns) */
    uint32_t spsr;

    EmulatedMemory* mem;

    /* Thunk callback for intercepting API calls */
    ThunkCallback thunk_handler;

    /* Instruction counter */
    uint64_t insn_count;
    bool     halted;
    uint32_t halt_code;

    /* Debug/trace flag */
    bool trace;

    ArmCpu() : mem(nullptr), insn_count(0), halted(false), halt_code(0), trace(false) {
        Reset();
    }

    void Reset() {
        memset(r, 0, sizeof(r));
        cpsr = 0x13; /* SVC mode, ARM state */
        spsr = 0;
        insn_count = 0;
        halted = false;
        halt_code = 0;
    }

    /* Run until halted or max instructions */
    void Run(uint64_t max_insns = 0);

    /* Execute a single instruction */
    void Step();

    /* Check if in Thumb mode */
    bool IsThumb() const { return (cpsr & PSR_T) != 0; }

    /* Get/Set PSR flags */
    bool GetN() const { return (cpsr & PSR_N) != 0; }
    bool GetZ() const { return (cpsr & PSR_Z) != 0; }
    bool GetC() const { return (cpsr & PSR_C) != 0; }
    bool GetV() const { return (cpsr & PSR_V) != 0; }

    void SetN(bool v) { if (v) cpsr |= PSR_N; else cpsr &= ~PSR_N; }
    void SetZ(bool v) { if (v) cpsr |= PSR_Z; else cpsr &= ~PSR_Z; }
    void SetC(bool v) { if (v) cpsr |= PSR_C; else cpsr &= ~PSR_C; }
    void SetV(bool v) { if (v) cpsr |= PSR_V; else cpsr &= ~PSR_V; }

    void SetNZ(uint32_t result) {
        SetN((result >> 31) & 1);
        SetZ(result == 0);
    }

    /* Check condition code */
    bool CheckCondition(uint32_t cond) const;

private:
    /* ARM mode instruction execution */
    void ExecuteArm(uint32_t insn);

    /* Thumb mode instruction execution */
    void ExecuteThumb(uint16_t insn);

    /* ARM instruction handlers */
    void ArmDataProcessing(uint32_t insn);
    void ArmMultiply(uint32_t insn);
    void ArmMultiplyLong(uint32_t insn);
    void ArmSingleDataTransfer(uint32_t insn);
    void ArmHalfwordTransfer(uint32_t insn);
    void ArmBlockDataTransfer(uint32_t insn);
    void ArmBranch(uint32_t insn);
    void ArmBranchExchange(uint32_t insn);
    void ArmSwap(uint32_t insn);
    void ArmSoftwareInterrupt(uint32_t insn);
    void ArmMRS(uint32_t insn);
    void ArmMSR(uint32_t insn);
    void ArmCLZ(uint32_t insn);

    /* Barrel shifter */
    uint32_t BarrelShift(uint32_t val, uint32_t shift_type, uint32_t shift_amount, bool& carry_out, bool reg_shift);

    /* Thumb instruction handlers */
    void ThumbShiftImm(uint16_t insn);
    void ThumbAddSub(uint16_t insn);
    void ThumbMovCmpAddSub(uint16_t insn);
    void ThumbALU(uint16_t insn);
    void ThumbHiRegBX(uint16_t insn);
    void ThumbPCRelLoad(uint16_t insn);
    void ThumbLoadStoreReg(uint16_t insn);
    void ThumbLoadStoreSBH(uint16_t insn);
    void ThumbLoadStoreImm(uint16_t insn);
    void ThumbLoadStoreHalf(uint16_t insn);
    void ThumbSPRelLoadStore(uint16_t insn);
    void ThumbLoadAddr(uint16_t insn);
    void ThumbAdjustSP(uint16_t insn);
    void ThumbPushPop(uint16_t insn);
    void ThumbMultiLoadStore(uint16_t insn);
    void ThumbCondBranch(uint16_t insn);
    void ThumbSWI(uint16_t insn);
    void ThumbUncondBranch(uint16_t insn);
    void ThumbLongBranch(uint16_t insn);
};
