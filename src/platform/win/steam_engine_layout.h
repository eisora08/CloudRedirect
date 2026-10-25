#pragma once

#include <cstddef>
#include <cstdint>
#include <cstring>

// Small, deliberately restrictive operand decoders. Unknown instruction forms
// fail closed; these functions inspect bytes and never call Steam code.
namespace SteamEngineLayout {

inline uint32_t U32(const uint8_t* p) {
    uint32_t v;
    std::memcpy(&v, p, sizeof(v));
    return v;
}
inline uintptr_t Relative(uintptr_t end, const uint8_t* p) {
    int32_t v;
    std::memcpy(&v, p, sizeof(v));
    return end + v;
}
inline bool Offset(uint32_t v) { return v >= 0x40 && v <= 0x10000 && !(v & 7); }

struct KvReference {
    uintptr_t global = 0;
    uintptr_t key = 0;
    uint32_t cache = 0;
};

// Follow the argument setup of a UFS config reader that starts at a RIP-
// relative load of the engine global into nonvolatile RBX:
//
//   mov  rbx, [rip+global]     ; 48 8B 1D xx xx xx xx
//   lea  rcx, [rbx+cache]      ; 48 8D 8B xx xx xx xx   (app-info cache)
//   call <cache lock>          ; E8 xx xx xx xx
//   lea  r9, [rip+key]         ; 4C 8D 0D xx xx xx xx   ("quota"/"maxnumfiles")
//   mov  [rsp+20h], <default>  ; 48 C7 44 24 20 ...  /  48-4C 89 44 24 20
//   mov  r8d, 10               ; 41 B8 0A 00 00 00      (UFS section)
//   lea  rcx, [rbx+cache]      ; 48 8D 8B xx xx xx xx
//   call ReadConfigU64         ; E8 xx xx xx xx
//
// The callee's exact address is deliberately NOT required: ReadConfigU64 has
// overload siblings sharing one prologue, and which sibling sits next to
// GetAppInfo differs between builds. Instead the full argument structure must
// be proven straight-line and the terminal call must land inside .text.
// Callers additionally verify the key against .rdata strings and require two
// agreeing readers, so a structural match cannot survive on a coincidence.
// Only straight-line argument setup is accepted; branches and unknown
// opcodes fail closed, and RBX may not be overwritten.
inline bool DecodeKvReference(const uint8_t* p, size_t size, uintptr_t address,
                              uintptr_t textBase, uintptr_t textEnd,
                              KvReference& out) {
    out = {};
    if (!p || size < 7 || !textBase || textEnd <= textBase) return false;
    if (std::memcmp(p, "\x48\x8B\x1D", 3)) return false;

    KvReference found;
    found.global = Relative(address + 7, p + 3);
    bool rcxCache = false, sectionUfs = false, lockSeen = false;
    for (size_t i = 7; i < size && i < 256;) {
        const auto* q = p + i;
        const size_t n = size - i;
        if (n >= 7 && !std::memcmp(q, "\x48\x8D\x8B", 3)) {
            const uint32_t cache = U32(q + 3);
            if (!Offset(cache) || (found.cache && found.cache != cache)) return false;
            found.cache = cache;
            rcxCache = true;
            i += 7;
        } else if (n >= 7 && !std::memcmp(q, "\x4C\x8D\x0D", 3)) {
            found.key = Relative(address + i + 7, q + 3);
            i += 7;
        } else if (n >= 6 && q[0] == 0x41 && q[1] == 0xB8) {
            sectionUfs = U32(q + 2) == 10; // UFS section
            i += 6;
        } else if (n >= 9 && !std::memcmp(q, "\x48\xC7\x44\x24\x20", 5)) {
            i += 9; // default value, [rsp+20h]
        } else if (n >= 5 && (q[0] == 0x48 || q[0] == 0x4C) &&
                   q[1] == 0x89 && (q[2] & 0xC7) == 0x44 && q[3] == 0x24 && q[4] == 0x20) {
            i += 5; // default value from a register
        } else if (n >= 5 && q[0] == 0xE8) {
            const uintptr_t target = Relative(address + i + 5, q + 1);
            if (rcxCache && lockSeen && sectionUfs && found.key) {
                // Every argument is proven straight-line; the reader call
                // itself must target real code inside this module.
                if (target < textBase || target >= textEnd) return false;
                out = found;
                return true;
            }
            // Exactly one intermediate call (the cache lock) may precede the
            // reader. It must directly follow the RCX cache setup and kills
            // every volatile argument.
            if (!rcxCache || lockSeen) return false;
            lockSeen = true;
            rcxCache = sectionUfs = false;
            found.key = 0;
            i += 5;
        } else {
            // MOV/XOR register setup. Track volatile argument clobbers and
            // reject writes to RBX; never step over a branch or unknown opcode.
            size_t rex = (q[0] >= 0x40 && q[0] <= 0x4F) ? 1 : 0;
            if (n < rex + 2) return false;
            const uint8_t op = q[rex], mod = q[rex + 1];
            if ((op != 0x8B && op != 0x33) || (mod & 0xC0) != 0xC0) return false;
            const unsigned dest = ((mod >> 3) & 7) + (rex && (q[0] & 4) ? 8 : 0);
            if (dest == 3 || dest == 4) return false;
            if (dest == 1) rcxCache = false;
            if (dest == 8) sectionUfs = false;
            if (dest == 9) found.key = 0;
            i += rex + 2;
        }
    }
    return false;
}

// CUtlSortedVector lookup used by the engine's current-user accessors. Validate
// the count, array, comparator and context offsets, the 16-byte stride and the
// returned pointer at entry+8. Displacements vary; control flow/operands do not.
inline bool DecodeUserMap(const uint8_t* p, size_t n, uint32_t& map) {
    map = 0;
    static constexpr uint8_t prefix[] = {
        0x40,0x53,0x55,0x56,0x57,0x41,0x56,0x41,0x57,0x48,0x83,0xEC,0x38,
        0x8B,0xB9
    };
    if (!p || n < 0xAD || std::memcmp(p, prefix, sizeof(prefix))) return false;
    const uint32_t count = U32(p + 0x0F);
    if (count < 16 || !Offset(count - 16)) return false;
    const uint32_t base = count - 16;
    struct Part { size_t at; const char* bytes; size_t length; };
    const Part parts[] = {
        {0x13,"\x48\x8B\xF1\x83\xEF\x01\x89\x54\x24\x20\x78\x61\x4C\x8B\xB9",15},
        {0x26,"\x33\xED\x0F\x1F\x84\x00\x00\x00\x00\x00",10},
        {0x30,"\x48\x8B\x8E",3},
        {0x37,"\x8D\x1C\x2F\xD1\xFB\x48\x8D\x54\x24\x20\x4C\x63\xF3\x4D\x8B\xC7\x49\xC1\xE6\x04\x49\x03\xCE\xFF\x96",25},
        {0x54,"\x84\xC0\x74\x05\x8D\x6B\x01\xEB\x1F",9},
        {0x5D,"\x48\x8B\x96",3},
        {0x64,"\x48\x8D\x4C\x24\x20\x49\x03\xD6\x4D\x8B\xC7\xFF\x96",13},
        {0x75,"\x84\xC0\x74\x16\x8D\x7B\xFF\x3B\xEF\x7E\xB0\x33\xC0\x48\x83\xC4\x38\x41\x5F\x41\x5E\x5F\x5E\x5D\x5B\xC3",26},
        {0x8F,"\x83\xFB\xFF\x74\xEC\x48\x8B\x86",8},
        {0x9B,"\x49\x8B\x44\x06\x08\x48\x83\xC4\x38\x41\x5F\x41\x5E\x5F\x5E\x5D\x5B\xC3",18}
    };
    for (const auto& part : parts)
        if (std::memcmp(p + part.at, part.bytes, part.length)) return false;
    if (U32(p + 0x22) != base + 32 || U32(p + 0x33) != base ||
        U32(p + 0x50) != base + 24 || U32(p + 0x60) != base ||
        U32(p + 0x71) != base + 24 || U32(p + 0x97) != base) return false;
    map = base;
    return true;
}

// Pick the real GetAppInfo among several prologue-matching candidates by
// proving caller intent: the true one is called with the app-info cache
// member (engine + cacheOff) in RCX right before the call, i.e. the window
// before the call site contains:
//   lea rcx,[reg+disp32]  // REX 48..4B, 8D, modrm(mod=10, reg=001), disp32
// (mod=10 forces disp32 for member offsets >= 0x80; SIB shifts disp32 by one).
// Returns the index of the unique best candidate or -1 (no evidence, thin
// evidence, or a tie at the top: fail closed). `*outConfirming` (optional)
// receives the winning caller count.
inline int ValidateByCacheCallers(const uint8_t* text, size_t size,
                                  uintptr_t base, const uintptr_t* cands,
                                  size_t nCands, uint32_t cacheOff,
                                  unsigned minConfirming,
                                  unsigned* outConfirming) {
    if (outConfirming) *outConfirming = 0;
    if (!text || !size || !cands || !nCands || nCands > 128 || !cacheOff)
        return -1;
    unsigned counts[128] = {};
    for (size_t i = 0; i + 5 <= size; ++i) {
        if (text[i] != 0xE8) continue;
        const uintptr_t callee = Relative(base + i + 5, text + i + 1);
        int idx = -1;
        for (size_t c = 0; c < nCands; ++c)
            if (cands[c] == callee) { idx = (int)c; break; }
        if (idx < 0) continue;
        const size_t w0 = (i >= 48) ? i - 48 : 0;
        for (size_t b = w0; b + 7 <= i; ++b) {
            const uint8_t rex = text[b];
            if (rex < 0x48 || rex > 0x4B || text[b + 1] != 0x8D) continue;
            const uint8_t modrm = text[b + 2];
            if ((modrm & 0xF8) != 0x88) continue; // mod=10, reg=001 (rcx)
            size_t disp = b + 3;
            if ((modrm & 7) == 4) ++disp;         // SIB byte precedes disp32
            if (disp + 4 > i) continue;
            if (U32(text + disp) == cacheOff) { ++counts[idx]; break; }
        }
    }
    int best = -1, second = -1;
    for (size_t c = 0; c < nCands; ++c) {
        if (best < 0 || counts[c] > counts[best]) { second = best; best = (int)c; }
        else if (second < 0 || counts[c] > counts[second]) second = (int)c;
    }
    if (best < 0 || counts[best] < minConfirming) return -1;
    if (second >= 0 && counts[best] == counts[second]) return -1; // tie
    if (outConfirming) *outConfirming = counts[best];
    return best;
}

} // namespace SteamEngineLayout
