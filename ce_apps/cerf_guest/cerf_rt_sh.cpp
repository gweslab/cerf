#if defined(SHx)

namespace {

typedef unsigned long Word;

struct Pair {
    Word lo;
    Word hi;
};

Pair Load(const void* p) {
    const Word* w = (const Word*)p;
    Pair v;
    v.lo = w[0];
    v.hi = w[1];
    return v;
}

void* Store(void* p, Pair v) {
    Word* w = (Word*)p;
    w[0] = v.lo;
    w[1] = v.hi;
    return p;
}

bool IsNegative(Pair v) {
    return (v.hi >> 31) != 0u;
}

Pair Negate(Pair v) {
    Pair r;
    r.lo = ~v.lo + 1u;
    r.hi = ~v.hi + (r.lo == 0u ? 1u : 0u);
    return r;
}

Pair Magnitude(Pair v) {
    return IsNegative(v) ? Negate(v) : v;
}

Word Divide32(Word dividend, Word divisor, Word* remainder) {
    Word quotient = 0u;
    Word rem      = 0u;
    if (divisor == 0u) {
        *remainder = 0u;
        return 0u;
    }
    for (int i = 31; i >= 0; --i) {
        const Word shifted_out = rem >> 31;
        rem = (rem << 1) | ((dividend >> i) & 1u);
        if (shifted_out != 0u || rem >= divisor) {
            rem -= divisor;
            quotient |= 1u << i;
        }
    }
    *remainder = rem;
    return quotient;
}

Word Magnitude32(long v) {
    return v < 0 ? 0u - (Word)v : (Word)v;
}

Pair Divide64(Pair dividend, Pair divisor, Pair* remainder) {
    Pair q = { 0u, 0u };
    Pair r = { 0u, 0u };
    if ((divisor.lo | divisor.hi) == 0u) {
        *remainder = r;
        return q;
    }
    for (int i = 63; i >= 0; --i) {
        const Word shifted_out = r.hi >> 31;
        const Word bit = i >= 32 ? (dividend.hi >> (i - 32)) & 1u
                                 : (dividend.lo >> i) & 1u;
        r.hi = (r.hi << 1) | (r.lo >> 31);
        r.lo = (r.lo << 1) | bit;
        if (shifted_out != 0u || r.hi > divisor.hi ||
            (r.hi == divisor.hi && r.lo >= divisor.lo)) {
            const Word borrow = r.lo < divisor.lo ? 1u : 0u;
            r.lo = r.lo - divisor.lo;
            r.hi = r.hi - divisor.hi - borrow;
            if (i >= 32) q.hi |= 1u << (i - 32);
            else         q.lo |= 1u << i;
        }
    }
    *remainder = r;
    return q;
}

Pair Multiply32(Word a, Word b) {
    const Word a0 = a & 0xFFFFu, a1 = a >> 16;
    const Word b0 = b & 0xFFFFu, b1 = b >> 16;
    const Word p00 = a0 * b0;
    const Word p01 = a0 * b1;
    const Word p10 = a1 * b0;
    const Word p11 = a1 * b1;
    const Word mid = (p00 >> 16) + (p01 & 0xFFFFu) + (p10 & 0xFFFFu);
    Pair r;
    r.lo = (p00 & 0xFFFFu) | (mid << 16);
    r.hi = p11 + (p01 >> 16) + (p10 >> 16) + (mid >> 16);
    return r;
}

Pair Multiply64(Pair a, Pair b) {
    Pair r = Multiply32(a.lo, b.lo);
    r.hi += a.lo * b.hi + a.hi * b.lo;
    return r;
}

Pair ShiftLeft(Pair v, Word n) {
    Pair r = { 0u, 0u };
    if (n == 0u) return v;
    if (n >= 64u) return r;
    if (n >= 32u) {
        r.hi = v.lo << (n - 32u);
        return r;
    }
    r.lo = v.lo << n;
    r.hi = (v.hi << n) | (v.lo >> (32u - n));
    return r;
}

Pair ShiftRight(Pair v, Word n, Word fill) {
    Pair r = { fill, fill };
    if (n == 0u) return v;
    if (n >= 64u) return r;
    if (n >= 32u) {
        r.lo = n == 32u ? v.hi : (v.hi >> (n - 32u)) | (fill << (64u - n));
        return r;
    }
    r.lo = (v.lo >> n) | (v.hi << (32u - n));
    r.hi = (v.hi >> n) | (fill << (32u - n));
    return r;
}

}

extern "C" unsigned long _divlu(unsigned long dividend, unsigned long divisor) {
    Word remainder;
    return Divide32(dividend, divisor, &remainder);
}

extern "C" unsigned long _modlu(unsigned long dividend, unsigned long divisor) {
    Word remainder;
    Divide32(dividend, divisor, &remainder);
    return remainder;
}

extern "C" long _divls(long dividend, long divisor) {
    Word remainder;
    const Word q = Divide32(Magnitude32(dividend), Magnitude32(divisor), &remainder);
    return (long)(((dividend < 0) != (divisor < 0)) ? 0u - q : q);
}

extern "C" long _modls(long dividend, long divisor) {
    Word remainder;
    Divide32(Magnitude32(dividend), Magnitude32(divisor), &remainder);
    return (long)(dividend < 0 ? 0u - remainder : remainder);
}

extern "C" void* _mului64(void* result, const void* a, const void* b) {
    return Store(result, Multiply64(Load(a), Load(b)));
}

extern "C" void* _muli64(void* result, const void* a, const void* b) {
    return Store(result, Multiply64(Load(a), Load(b)));
}

extern "C" void* _divui64(void* result, const void* dividend, const void* divisor) {
    Pair remainder;
    return Store(result, Divide64(Load(dividend), Load(divisor), &remainder));
}

extern "C" void* _modui64(void* result, const void* dividend, const void* divisor) {
    Pair remainder;
    Divide64(Load(dividend), Load(divisor), &remainder);
    return Store(result, remainder);
}

extern "C" void* _divi64(void* result, const void* dividend, const void* divisor) {
    const Pair n = Load(dividend);
    const Pair d = Load(divisor);
    Pair remainder;
    const Pair q = Divide64(Magnitude(n), Magnitude(d), &remainder);
    return Store(result, IsNegative(n) != IsNegative(d) ? Negate(q) : q);
}

extern "C" void* _modi64(void* result, const void* dividend, const void* divisor) {
    const Pair n = Load(dividend);
    Pair remainder;
    Divide64(Magnitude(n), Magnitude(Load(divisor)), &remainder);
    return Store(result, IsNegative(n) ? Negate(remainder) : remainder);
}

extern "C" void* _lshi64(void* result, const void* value, int count) {
    return Store(result, ShiftLeft(Load(value), (Word)count));
}

extern "C" void* _rshi64(void* result, const void* value, int count) {
    const Pair v = Load(value);
    return Store(result, ShiftRight(v, (Word)count, IsNegative(v) ? 0xFFFFFFFFu : 0u));
}

extern "C" void* _rshui64(void* result, const void* value, int count) {
    return Store(result, ShiftRight(Load(value), (Word)count, 0u));
}

#endif
