#pragma once

#include <cmath>
#include <cstdint>
#include <cstring>

#include "../core/service.h"

class ArmVfp : public Service {
public:
    using Service::Service;

    /* FPSCR.QC bit[27] — sticky Advanced SIMD saturation flag (B4.1.58). */
    static constexpr uint32_t kFpscrQcMask = 1u << 27;

    /* Per-element IEEE 754 primitives — shared by VFP (ExecuteCdp) and
       NEON .F32 element code so the host-IEEE choice (FZ/DN spec
       divergence) lives in exactly one place. */
    static inline float  FPAddS (float a, float b)  { return a + b; }
    static inline float  FPSubS (float a, float b)  { return a - b; }
    static inline float  FPMulS (float a, float b)  { return a * b; }
    static inline float  FPDivS (float a, float b)  { return a / b; }
    static inline float  FPNegS (float a)           { return -a; }
    static inline float  FPAbsS (float a)           { return std::fabs(a); }
    static inline float  FPSqrtS(float a)           { return std::sqrt(a); }
    static inline float  FPFmaS (float a, float b, float c) { return std::fma(a, b, c); }

    static inline bool IsZeroOrDenormS(float a) {
        uint32_t bits;
        std::memcpy(&bits, &a, 4);
        return (bits & 0x7F800000u) == 0u;
    }

    static inline float RecipStepProductS(float op1, float op2) {
        const bool inf1 = std::isinf(op1);
        const bool inf2 = std::isinf(op2);
        const bool zd1  = IsZeroOrDenormS(op1);
        const bool zd2  = IsZeroOrDenormS(op2);
        if ((inf1 && zd2) || (zd1 && inf2)) return 0.0f;
        return op1 * op2;
    }

    static inline float FPRecipStepS(float op1, float op2) {
        return 2.0f - RecipStepProductS(op1, op2);
    }
    static inline float FPRSqrtStepS(float op1, float op2) {
        return (3.0f - RecipStepProductS(op1, op2)) * 0.5f;
    }

    static inline double FPAddD (double a, double b){ return a + b; }
    static inline double FPSubD (double a, double b){ return a - b; }
    static inline double FPMulD (double a, double b){ return a * b; }
    static inline double FPDivD (double a, double b){ return a / b; }
    static inline double FPNegD (double a)          { return -a; }
    static inline double FPAbsD (double a)          { return std::fabs(a); }
    static inline double FPSqrtD(double a)          { return std::sqrt(a); }

    /* Quiet-NaN-aware comparison primitives: host `==`/`<`/`>`/`<=`/`>=`
       return false for any NaN operand, matching ARM's ordered FPCompareXX. */
    static inline bool FPCompareEqS(float a, float b)  { return a == b; }
    static inline bool FPCompareGtS(float a, float b)  { return a >  b; }
    static inline bool FPCompareGeS(float a, float b)  { return a >= b; }
    static inline bool FPCompareLtS(float a, float b)  { return a <  b; }
    static inline bool FPCompareLeS(float a, float b)  { return a <= b; }

    static inline bool FPCompareEqD(double a, double b){ return a == b; }
    static inline bool FPCompareGtD(double a, double b){ return a >  b; }
    static inline bool FPCompareLtD(double a, double b){ return a <  b; }

    /* IEEE FPMax / FPMin: any-NaN → NaN; equal-value tiebreak uses sign
       (max prefers +0, min prefers -0) per ARM ARM FPMax / FPMin spec. */
    static inline float FPMaxS(float a, float b) {
        if (std::isnan(a) || std::isnan(b)) return std::nanf("");
        if (a > b) return a;
        if (b > a) return b;
        uint32_t ba, bb;
        std::memcpy(&ba, &a, 4);
        std::memcpy(&bb, &b, 4);
        const uint32_t r = ba & bb;  /* sign(+0 if either +0) */
        float result;
        std::memcpy(&result, &r, 4);
        return result;
    }
    static inline float FPMinS(float a, float b) {
        if (std::isnan(a) || std::isnan(b)) return std::nanf("");
        if (a < b) return a;
        if (b < a) return b;
        uint32_t ba, bb;
        std::memcpy(&ba, &a, 4);
        std::memcpy(&bb, &b, 4);
        const uint32_t r = ba | bb;  /* sign(-0 if either -0) */
        float result;
        std::memcpy(&result, &r, 4);
        return result;
    }

    /* Integer element loaders — read an `esize`-bit element from a byte
       pointer (NEON D-register slot), sign- or zero-extend to 64-bit.
       Shared by every NEON handler that iterates over lanes. */
    static inline int64_t LoadIntS(const uint8_t* p, uint32_t esize) {
        if (esize == 8u)  { int8_t  v; std::memcpy(&v, p, 1); return v; }
        if (esize == 16u) { int16_t v; std::memcpy(&v, p, 2); return v; }
        if (esize == 32u) { int32_t v; std::memcpy(&v, p, 4); return v; }
        int64_t v; std::memcpy(&v, p, 8); return v;
    }
    static inline uint64_t LoadIntU(const uint8_t* p, uint32_t esize) {
        if (esize == 8u)  { return *p; }
        if (esize == 16u) { uint16_t v; std::memcpy(&v, p, 2); return v; }
        if (esize == 32u) { uint32_t v; std::memcpy(&v, p, 4); return v; }
        uint64_t v; std::memcpy(&v, p, 8); return v;
    }

    /* Spec helpers from ARM ARM A2.7 "Floating-point reciprocal estimate
       and step" / "square root estimate and step" (page A2-85 / A2-87).
       a ∈ [0.5, 1.0) for RecipEstimate; a ∈ [0.25, 1.0) for RecipSqrt. */
    static inline double RecipEstimate(double a) {
        int q = static_cast<int>(a * 512.0);
        double r = 1.0 / ((static_cast<double>(q) + 0.5) / 512.0);
        int s = static_cast<int>(256.0 * r + 0.5);
        return static_cast<double>(s) / 256.0;
    }
    static inline double RecipSqrtEstimate(double a) {
        int q;
        double r;
        if (a < 0.5) {
            q = static_cast<int>(a * 512.0);
            r = 1.0 / std::sqrt((static_cast<double>(q) + 0.5) / 512.0);
        } else {
            q = static_cast<int>(a * 256.0);
            r = 1.0 / std::sqrt((static_cast<double>(q) + 0.5) / 256.0);
        }
        int s = static_cast<int>(256.0 * r + 0.5);
        return static_cast<double>(s) / 256.0;
    }

    /* Flag bit packing for HandleBlockTransfer's `flags` arg. */
    static constexpr uint32_t kFlagL  = 1u << 0;  /* 1=load (VLDM), 0=store (VSTM) */
    static constexpr uint32_t kFlagW  = 1u << 1;  /* writeback */
    static constexpr uint32_t kFlagP  = 1u << 2;  /* pre-decrement */
    static constexpr uint32_t kFlagDp = 1u << 3;  /* cp_num=11 doubleword */

    /* Returns 0 on successful transfer (block continues), non-zero
       when UND or data abort fired (state has been redirected to
       the vector PC by Raise*; emit code MUST RETN the block on
       non-zero so the dispatcher picks up the vector). */
    uint32_t HandleBlockTransfer(uint32_t pc, uint32_t rn_idx, uint32_t vd,
                                 uint32_t imm8, uint32_t flags);

    static uint32_t __cdecl HandleBlockTransferHelper(ArmVfp*  vfp,
                                                      uint32_t pc,
                                                      uint32_t rn_idx,
                                                      uint32_t vd,
                                                      uint32_t imm8,
                                                      uint32_t flags);

    /* VLDR / VSTR — single-register VFP load/store. signed_off is
       the already-signed byte displacement from Rn (decoder applies
       the U-bit sign to d->offset). Same 0/non-zero status as
       HandleBlockTransfer. */
    uint32_t HandleSingleTransfer(uint32_t pc, uint32_t rn_idx, uint32_t vd,
                                  int32_t signed_off, uint32_t flags);

    static uint32_t __cdecl HandleSingleTransferHelper(ArmVfp*  vfp,
                                                      uint32_t pc,
                                                      uint32_t rn_idx,
                                                      uint32_t vd,
                                                      int32_t  signed_off,
                                                      uint32_t flags);

    uint32_t ExecuteCdp(uint32_t pc, uint32_t packed);

    static uint32_t __cdecl ExecuteCdpHelper(ArmVfp*  vfp,
                                             uint32_t pc,
                                             uint32_t packed);
};
