#pragma once

#include <cstddef>
#include <cstdint>

#include "jit_block.h"

class JitBlockIndex {
public:
    JitBlockIndex() = default;

    /* Wire the NIL sentinel and empty the root. */
    void Initialize();

    /* Per-record memory sizes — JitCompile multiplies by
       entrypoint_count and folds into the slab allocation size. */
    static constexpr size_t OuterEntrySize();
    static constexpr size_t SubEntrySize();

    JitBlock* PlaceOuterAt(void* memory, const JitBlock& block);

    /* Place a sub-entrypoint (bare JitBlock) at `memory`. `parent`
       is the outer entrypoint this sub belongs to; the new sub is
       prepended to parent->sub_block. Returns the placed JitBlock. */
    JitBlock* PlaceSubAt(void* memory, JitBlock* parent, const JitBlock& block);

    /* Find the outer entrypoint whose folded-VA range contains
       folded_va, then walk its sub_block chain for an exact guest_start
       match; fall back to the outer entrypoint on no sub match. */
    JitBlock* FindContaining(uint32_t folded_va);

    /* Like FindContaining but returns nullptr unless the result's
       guest_start == folded_va. */
    JitBlock* FindExact(uint32_t folded_va);

    /* First outer with guest_start > folded_va. */
    JitBlock* FindNext(uint32_t folded_va);

    /* Any outer entry's folded-VA range intersects [va_lo, va_hi]? */
    bool ContainsRange(uint32_t va_lo, uint32_t va_hi) const;

    /* Invoked once per removed block (outer entry + each of its sub-entries)
       just before unlink, so the caller can drop that block's jump-cache slot. */
    using RemovedCb = void (*)(uint32_t guest_start, void* ctx);

    /* RbDelete one outer entry the caller already located (via the
       IsaBlockSpace phys-page list or FindOuter); fires cb for it + each
       sub-entry first. Arena memory is not freed (reclaimed on full Flush). */
    void RemoveNode(JitBlock* outer, RemovedCb cb, void* ctx);

    /* Outer entry whose folded-VA range contains folded_va (the RB node's
       embedded block), or nullptr — locates an FCSE-PID-reuse stale block. */
    JitBlock* FindOuter(uint32_t folded_va);

    /* FlushEntrypoints equivalent — forget all references. The
       backing memory is in the arena and is freed by arena flush;
       this method just resets the tree root to NIL. */
    void Flush();

    bool Empty() const;

private:
    enum class NodeColor : uint8_t { kRed, kBlack };

    /* EPNODE equivalent. JitBlock `ep` is the first field so a
       reinterpret_cast<JitBlock*>(node_memory) gives the embedded
       block — matching the reference's ((PENTRYPOINT)CodeLocation)
       cast. */
    struct Node {
        JitBlock   ep;
        Node*      left;
        Node*      right;
        Node*      parent;
        NodeColor  color;
    };

    Node          nil_storage_{};
    Node*         nil_  = nullptr;
    Node*         root_ = nullptr;

    /* CLR RB-tree primitives ("Introduction to Algorithms" Ch. 13). */
    Node* LeftRotate (Node* root, Node* x);
    Node* RightRotate(Node* root, Node* x);
    Node* TreeInsertBst(Node* root, Node* z);
    Node* RbInsert(Node* root, Node* z);
    Node* RbFind(Node* root, uint32_t addr) const;
    Node* RbFindNext(Node* root, uint32_t addr) const;
    bool  RbContainsRange(Node* root, uint32_t start_addr, uint32_t end_addr) const;

    /* CLRS RB-delete (Ch. 13). Same root-returning style as RbInsert. */
    Node* Transplant(Node* root, Node* u, Node* v);
    Node* TreeMinimum(Node* x);
    Node* RbDelete(Node* root, Node* z);
    Node* RbDeleteFixup(Node* root, Node* x);
};

constexpr size_t JitBlockIndex::OuterEntrySize() {
    return sizeof(Node);
}

constexpr size_t JitBlockIndex::SubEntrySize() {
    return sizeof(JitBlock);
}
