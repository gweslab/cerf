#include "jit_block_index.h"

#include <cstring>
#include <new>

void JitBlockIndex::Initialize() {
    nil_ = &nil_storage_;
    nil_->left   = nil_;
    nil_->right  = nil_;
    nil_->parent = nil_;
    nil_->color  = NodeColor::kBlack;
    root_ = nil_;
}

JitBlock* JitBlockIndex::PlaceOuterAt(void* memory, const JitBlock& block) {
    Node* node = new (memory) Node{};
    node->ep            = block;
    node->ep.sub_block  = nullptr;
    node->left          = nil_;
    node->right         = nil_;
    node->parent        = nil_;
    node->color         = NodeColor::kRed;
    root_ = RbInsert(root_, node);
    return &node->ep;
}

JitBlock* JitBlockIndex::PlaceSubAt(void* memory, JitBlock* parent, const JitBlock& block) {
    JitBlock* sub = new (memory) JitBlock{block};
    sub->sub_block      = parent->sub_block;
    parent->sub_block   = sub;
    return sub;
}

JitBlock* JitBlockIndex::FindContaining(uint32_t folded_va) {
    Node* node = RbFind(root_, folded_va);
    if (!node) return nullptr;
    JitBlock* ep = &node->ep;
    do {
        if (ep->guest_start == folded_va) return ep;
        ep = ep->sub_block;
    } while (ep);
    /* No sub-entrypoint matches exactly — return the outer block. */
    return &node->ep;
}

JitBlock* JitBlockIndex::FindExact(uint32_t folded_va) {
    JitBlock* hit = FindContaining(folded_va);
    if (hit && hit->guest_start == folded_va) return hit;
    return nullptr;
}

JitBlock* JitBlockIndex::FindNext(uint32_t folded_va) {
    Node* node = RbFindNext(root_, folded_va);
    if (!node || node == nil_) return nullptr;
    return &node->ep;
}

bool JitBlockIndex::ContainsRange(uint32_t va_lo, uint32_t va_hi) const {
    if (root_ == nil_) return false;
    return RbContainsRange(root_, va_lo, va_hi);
}

void JitBlockIndex::RemoveNode(JitBlock* outer, RemovedCb cb, void* ctx) {
    if (cb) {
        cb(outer->guest_start, ctx);
        for (JitBlock* sub = outer->sub_block; sub; sub = sub->sub_block) {
            cb(sub->guest_start, ctx);
        }
    }
    /* outer is the JitBlock at the head of its Node (first field), so the
       Node* recovers by reinterpret_cast — outer blocks only (subs chain
       off the outer and leave with it). */
    root_ = RbDelete(root_, reinterpret_cast<Node*>(outer));
}

JitBlock* JitBlockIndex::FindOuter(uint32_t folded_va) {
    Node* n = RbFind(root_, folded_va);
    return n ? &n->ep : nullptr;
}

void JitBlockIndex::Flush() {
    /* Arena owns the node memory; caller flushes the arena to
       actually free it. We just forget every reference. */
    root_ = nil_;
}

bool JitBlockIndex::Empty() const {
    return root_ == nil_;
}

JitBlockIndex::Node* JitBlockIndex::LeftRotate(Node* root, Node* x) {
    Node* y = x->right;
    x->right = y->left;
    if (y->left != nil_) y->left->parent = x;
    y->parent = x->parent;
    if (x->parent == nil_) {
        root = y;
    } else if (x == x->parent->left) {
        x->parent->left = y;
    } else {
        x->parent->right = y;
    }
    y->left = x;
    x->parent = y;
    return root;
}

JitBlockIndex::Node* JitBlockIndex::RightRotate(Node* root, Node* x) {
    Node* y = x->left;
    x->left = y->right;
    if (y->right != nil_) y->right->parent = x;
    y->parent = x->parent;
    if (x->parent == nil_) {
        root = y;
    } else if (x == x->parent->left) {
        x->parent->left = y;
    } else {
        x->parent->right = y;
    }
    y->right = x;
    x->parent = y;
    return root;
}

JitBlockIndex::Node* JitBlockIndex::TreeInsertBst(Node* root, Node* z) {
    Node* y = nil_;
    Node* x = root;
    z->left  = nil_;
    z->right = nil_;
    while (x != nil_) {
        y = x;
        if (z->ep.guest_start < x->ep.guest_start) {
            x = x->left;
        } else {
            x = x->right;
        }
    }
    z->parent = y;
    if (y == nil_) {
        root = z;
    } else if (z->ep.guest_start < y->ep.guest_start) {
        y->left = z;
    } else {
        y->right = z;
    }
    return root;
}

JitBlockIndex::Node* JitBlockIndex::RbInsert(Node* root, Node* x) {
    root = TreeInsertBst(root, x);
    x->color = NodeColor::kRed;

    while (x != root && x->parent->color == NodeColor::kRed) {
        if (x->parent == x->parent->parent->left) {
            Node* y = x->parent->parent->right;
            if (y->color == NodeColor::kRed) {
                x->parent->color           = NodeColor::kBlack;
                y->color                   = NodeColor::kBlack;
                x->parent->parent->color   = NodeColor::kRed;
                x = x->parent->parent;
            } else if (x == x->parent->right) {
                x = x->parent;
                root = LeftRotate(root, x);
            } else {
                x->parent->color           = NodeColor::kBlack;
                x->parent->parent->color   = NodeColor::kRed;
                root = RightRotate(root, x->parent->parent);
            }
        } else {
            Node* y = x->parent->parent->left;
            if (y->color == NodeColor::kRed) {
                x->parent->color           = NodeColor::kBlack;
                y->color                   = NodeColor::kBlack;
                x->parent->parent->color   = NodeColor::kRed;
                x = x->parent->parent;
            } else if (x == x->parent->left) {
                x = x->parent;
                root = RightRotate(root, x);
            } else {
                x->parent->color           = NodeColor::kBlack;
                x->parent->parent->color   = NodeColor::kRed;
                root = LeftRotate(root, x->parent->parent);
            }
        }
    }
    root->color = NodeColor::kBlack;
    return root;
}

JitBlockIndex::Node* JitBlockIndex::RbFind(Node* root, uint32_t addr) const {
    while (root != nil_) {
        if (addr < root->ep.guest_start) {
            root = root->left;
        } else if (addr > root->ep.guest_end) {
            root = root->right;
        } else {
            return root;
        }
    }
    return nullptr;
}

JitBlockIndex::Node* JitBlockIndex::RbFindNext(Node* root, uint32_t addr) const {
    if (root == nil_) return nullptr;
    Node* candidate = nullptr;
    while (root != nil_) {
        candidate = root;
        if (addr < root->ep.guest_start) {
            root = root->left;
        } else {
            root = root->right;
        }
    }
    while (candidate && addr > candidate->ep.guest_start) {
        if (candidate->parent == nil_) return nullptr;
        candidate = candidate->parent;
    }
    return candidate;
}

bool JitBlockIndex::RbContainsRange(Node* root, uint32_t start_addr, uint32_t end_addr) const {
    while (root != nil_) {
        const uint32_t vs = root->ep.guest_start;
        const uint32_t ve = root->ep.guest_end;
        if (start_addr <= vs && vs <= end_addr) return true;
        if (start_addr <= ve && ve <= end_addr) return true;
        if (vs <= start_addr && end_addr <= ve) return true;

        if (start_addr < vs) {
            root = root->left;
        } else {
            root = root->right;
        }
    }
    return false;
}

JitBlockIndex::Node* JitBlockIndex::Transplant(Node* root, Node* u, Node* v) {
    if (u->parent == nil_) {
        root = v;
    } else if (u == u->parent->left) {
        u->parent->left = v;
    } else {
        u->parent->right = v;
    }
    v->parent = u->parent;
    return root;
}

JitBlockIndex::Node* JitBlockIndex::TreeMinimum(Node* x) {
    while (x->left != nil_) x = x->left;
    return x;
}

JitBlockIndex::Node* JitBlockIndex::RbDelete(Node* root, Node* z) {
    Node*     y               = z;
    NodeColor y_original_color = y->color;
    Node*     x;

    if (z->left == nil_) {
        x    = z->right;
        root = Transplant(root, z, z->right);
    } else if (z->right == nil_) {
        x    = z->left;
        root = Transplant(root, z, z->left);
    } else {
        y                = TreeMinimum(z->right);
        y_original_color = y->color;
        x                = y->right;
        if (y->parent == z) {
            x->parent = y;   /* sentinel-safe: fixup needs x->parent */
        } else {
            root        = Transplant(root, y, y->right);
            y->right    = z->right;
            y->right->parent = y;
        }
        root     = Transplant(root, z, y);
        y->left  = z->left;
        y->left->parent = y;
        y->color = z->color;
    }

    if (y_original_color == NodeColor::kBlack) {
        root = RbDeleteFixup(root, x);
    }
    return root;
}

JitBlockIndex::Node* JitBlockIndex::RbDeleteFixup(Node* root, Node* x) {
    while (x != root && x->color == NodeColor::kBlack) {
        if (x == x->parent->left) {
            Node* w = x->parent->right;
            if (w->color == NodeColor::kRed) {
                w->color         = NodeColor::kBlack;
                x->parent->color = NodeColor::kRed;
                root             = LeftRotate(root, x->parent);
                w                = x->parent->right;
            }
            if (w->left->color == NodeColor::kBlack &&
                w->right->color == NodeColor::kBlack) {
                w->color = NodeColor::kRed;
                x        = x->parent;
            } else {
                if (w->right->color == NodeColor::kBlack) {
                    w->left->color = NodeColor::kBlack;
                    w->color       = NodeColor::kRed;
                    root           = RightRotate(root, w);
                    w              = x->parent->right;
                }
                w->color          = x->parent->color;
                x->parent->color  = NodeColor::kBlack;
                w->right->color   = NodeColor::kBlack;
                root              = LeftRotate(root, x->parent);
                x                 = root;
            }
        } else {
            Node* w = x->parent->left;
            if (w->color == NodeColor::kRed) {
                w->color         = NodeColor::kBlack;
                x->parent->color = NodeColor::kRed;
                root             = RightRotate(root, x->parent);
                w                = x->parent->left;
            }
            if (w->right->color == NodeColor::kBlack &&
                w->left->color == NodeColor::kBlack) {
                w->color = NodeColor::kRed;
                x        = x->parent;
            } else {
                if (w->left->color == NodeColor::kBlack) {
                    w->right->color = NodeColor::kBlack;
                    w->color        = NodeColor::kRed;
                    root            = LeftRotate(root, w);
                    w               = x->parent->left;
                }
                w->color          = x->parent->color;
                x->parent->color  = NodeColor::kBlack;
                w->left->color    = NodeColor::kBlack;
                root              = RightRotate(root, x->parent);
                x                 = root;
            }
        }
    }
    x->color = NodeColor::kBlack;
    return root;
}
