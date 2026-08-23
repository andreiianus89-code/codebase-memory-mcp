#include "scope.h"
#include <stdlib.h>
#include <string.h>

_Atomic int cbm_lsp_walk_depth_effective = -1;

int cbm_lsp_configure_max_walk_depth(void) {
    const char* e = getenv("CBM_LSP_MAX_WALK_DEPTH");
    int v = (e && *e) ? atoi(e) : 0;
    int effective = v > 0 ? v : CBM_LSP_MAX_WALK_DEPTH;
    atomic_store_explicit(&cbm_lsp_walk_depth_effective, effective,
                          memory_order_relaxed);
    return effective;
}

CBMScope* cbm_scope_push(CBMArena* a, CBMScope* current) {
    CBMScope* scope = (CBMScope*)cbm_arena_alloc(a, sizeof(CBMScope));
    if (!scope) {
        return current;
    }
    memset(scope, 0, sizeof(CBMScope));
    scope->parent = current;
    scope->arena = a;
    return scope;
}

CBMScope* cbm_scope_pop(CBMScope* scope) {
    if (!scope) {
        return NULL;
    }
    return scope->parent;
}

static CBMScopeChunk* alloc_chunk(CBMScope* scope) {
    if (!scope->arena) {
        return NULL;
    }
    CBMScopeChunk* c = (CBMScopeChunk*)cbm_arena_alloc(scope->arena, sizeof(CBMScopeChunk));
    if (!c) {
        return NULL;
    }
    memset(c, 0, sizeof(CBMScopeChunk));
    c->next = scope->chunks;
    scope->chunks = c;
    return c;
}

void cbm_scope_bind(CBMScope* scope, const char* name, const CBMType* type) {
    if (!scope || !name) {
        return;
    }
    for (CBMScopeChunk* c = scope->chunks; c != NULL; c = c->next) {
        for (int i = 0; i < c->used; i++) {
            if (c->bindings[i].name && strcmp(c->bindings[i].name, name) == 0) {
                c->bindings[i].type = type;
                return;
            }
        }
    }
    CBMScopeChunk* head = scope->chunks;
    if (!head || head->used >= CBM_SCOPE_CHUNK_BINDINGS) {
        head = alloc_chunk(scope);
        if (!head) {
            return;
        }
    }
    head->bindings[head->used].name = name;
    head->bindings[head->used].type = type;
    head->used++;
}

const CBMType* cbm_scope_lookup(const CBMScope* scope, const char* name) {
    if (!name) {
        return cbm_type_unknown();
    }
    for (const CBMScope* s = scope; s != NULL; s = s->parent) {
        for (CBMScopeChunk* c = s->chunks; c != NULL; c = c->next) {
            for (int i = 0; i < c->used; i++) {
                if (c->bindings[i].name && strcmp(c->bindings[i].name, name) == 0) {
                    return c->bindings[i].type;
                }
            }
        }
    }
    return cbm_type_unknown();
}
