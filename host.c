/* PINAKA M06 "Bhargava's Challenge: The Bow Beyond the Bow"
 * ---------------------------------------------------------------------------
 * Native execution HOST for the two-generation bytecode system.  This is the
 * binary players reverse.  It implements, byte-for-byte with the Python model
 * in src/pinaka_vm.py:
 *     - the gen1 "PNK1" (Pinaka) and gen2 "SRNG" (Sharnga) module formats,
 *     - both static type checkers / verifiers,
 *     - the cross-generation linker (with the shipped type-validation gap),
 *     - a typed-slot executor over one shared 64-bit memory arena,
 *     - the restricted ASTRA opcode that releases PINAKA_FLAG from the
 *       environment iff the host capability word has been armed.
 *
 * Input (two equivalent modes):
 *     host <gen1.pnk1> <gen2.srng>        read the two modules from files, OR
 *     host                                read one combined blob from stdin:
 *         u32 len1 | gen1 bytes | u32 len2 | gen2 bytes      (all little-endian)
 *
 * Output: a single status line on stdout, one of
 *     PINAKA-ASTRA-RELEASED <flag>        (exit 0)  astra fired
 *     astra-sealed                        (exit 2)  ran clean, capability never armed
 *     reject: <reason>                    (exit 3)  verify/link rejected the module set
 *     fault: <reason>                     (exit 4)  runtime VM fault
 *
 * Build:  cc -O2 -std=c11 -Wall -o host host.c
 * ---------------------------------------------------------------------------
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

/* ---- type tags ---- */
enum { TVOID = 0, TINT = 1, TPTR = 2 };

/* ---- opcodes (shared by both generations) ---- */
enum { OP_HALT = 0, OP_LDC = 1, OP_MOV = 2, OP_ADD = 3,
       OP_ALLOC = 4, OP_LOAD = 5, OP_STORE = 6, OP_ASTRA = 8 };

/* ---- arena geometry (the constants a player recovers by reversing this host) ---- */
#define ARENA_N          65536
#define HEAP_BASE        64
#define CTRL_BASE        65408
#define ASTRA_LOCK_CELL  CTRL_BASE
#define ASTRA_KEY        0x5348415247410001LL   /* "SHARGA\0\1"; cell==KEY arms the astra  */

/* An in-binary DECOY flag (never the real one). The real flag is read from the
 * environment at ASTRA time; this string is here only to mislead static scanners. */
static const char DECOY_FLAG[] = "PINAKA{the_bow_is_not_strung_by_looking_at_it}";

/* ------------------------------------------------------------------ module structs */
typedef struct { uint8_t op, a, b, c; int32_t imm; } Insn;

typedef struct {
    int n_slots, n_consts, n_code, n_exports;
    uint8_t *slot_types;          /* [n_slots]  */
    int64_t *consts;              /* [n_consts] */
    Insn    *code;                /* [n_code]   */
    char   (*exp_name)[9];        /* [n_exports] */
    uint16_t *exp_slot;           /* [n_exports] */
} Gen1;

typedef struct {
    int n_types, n_slots, n_consts, n_imports, n_code;
    uint8_t *type_section;        /* [n_types]  */
    uint8_t *slot_types;          /* [n_slots]  resolved through type_section */
    int64_t *consts;              /* [n_consts] */
    Insn    *code;                /* [n_code]   */
    char   (*imp_name)[9];        /* [n_imports] */
    uint16_t *imp_slot;           /* [n_imports] */
} Gen2;

/* ------------------------------------------------------------------ host state */
typedef struct {
    int64_t mem[ARENA_N];
    int     heap_ptr;
} Host;

static char g_reason[256];
#define REJECT(...) do { snprintf(g_reason, sizeof g_reason, __VA_ARGS__); return -1; } while (0)

/* ------------------------------------------------------------------ LE readers */
static uint16_t rd_u16(const uint8_t *p) { return (uint16_t)(p[0] | (p[1] << 8)); }
static int32_t  rd_i32(const uint8_t *p) {
    return (int32_t)((uint32_t)p[0] | ((uint32_t)p[1] << 8) |
                     ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24));
}
static int64_t rd_i64(const uint8_t *p) {
    uint64_t v = 0; for (int i = 7; i >= 0; i--) v = (v << 8) | p[i]; return (int64_t)v;
}

/* ------------------------------------------------------------------ parse gen1 */
static int parse_gen1(const uint8_t *b, size_t len, Gen1 *m) {
    memset(m, 0, sizeof *m);
    if (len < 16 || memcmp(b, "PNK1", 4) != 0) REJECT("gen1: bad magic");
    if (rd_u16(b + 4) != 1) REJECT("gen1: bad version");
    m->n_slots   = rd_u16(b + 6);
    m->n_consts  = rd_u16(b + 8);
    m->n_code    = rd_u16(b + 10);
    m->n_exports = rd_u16(b + 12);
    size_t off = 16;
    size_t need = off + (size_t)m->n_slots + 8u * m->n_consts + 8u * m->n_code
                  + 10u * m->n_exports;
    if (len < need) REJECT("gen1: truncated");
    m->slot_types = malloc(m->n_slots ? m->n_slots : 1);
    memcpy(m->slot_types, b + off, m->n_slots); off += m->n_slots;
    m->consts = malloc(sizeof(int64_t) * (m->n_consts ? m->n_consts : 1));
    for (int i = 0; i < m->n_consts; i++) { m->consts[i] = rd_i64(b + off); off += 8; }
    m->code = malloc(sizeof(Insn) * (m->n_code ? m->n_code : 1));
    for (int i = 0; i < m->n_code; i++) {
        m->code[i].op = b[off]; m->code[i].a = b[off+1];
        m->code[i].b = b[off+2]; m->code[i].c = b[off+3];
        m->code[i].imm = rd_i32(b + off + 4); off += 8;
    }
    m->exp_name = malloc(sizeof(char[9]) * (m->n_exports ? m->n_exports : 1));
    m->exp_slot = malloc(sizeof(uint16_t) * (m->n_exports ? m->n_exports : 1));
    for (int i = 0; i < m->n_exports; i++) {
        memcpy(m->exp_name[i], b + off, 8); m->exp_name[i][8] = 0;
        for (int k = 0; k < 8; k++) if (m->exp_name[i][k] == 0) { m->exp_name[i][k] = 0; }
        off += 8;
        m->exp_slot[i] = rd_u16(b + off); off += 2;
    }
    return 0;
}

/* ------------------------------------------------------------------ parse gen2 */
static int parse_gen2(const uint8_t *b, size_t len, Gen2 *m) {
    memset(m, 0, sizeof *m);
    if (len < 16 || memcmp(b, "SRNG", 4) != 0) REJECT("gen2: bad magic");
    if (rd_u16(b + 4) != 2) REJECT("gen2: bad version");
    m->n_types   = rd_u16(b + 6);
    m->n_slots   = rd_u16(b + 8);
    m->n_consts  = rd_u16(b + 10);
    m->n_imports = rd_u16(b + 12);
    m->n_code    = rd_u16(b + 14);
    size_t off = 16;
    size_t need = off + (size_t)m->n_types + 2u * m->n_slots + 8u * m->n_consts
                  + 10u * m->n_imports + 8u * m->n_code;
    if (len < need) REJECT("gen2: truncated");
    m->type_section = malloc(m->n_types ? m->n_types : 1);
    memcpy(m->type_section, b + off, m->n_types); off += m->n_types;
    m->slot_types = malloc(m->n_slots ? m->n_slots : 1);
    for (int i = 0; i < m->n_slots; i++) {
        uint16_t ti = rd_u16(b + off); off += 2;
        if (ti >= m->n_types) REJECT("gen2: slot type index out of range");
        m->slot_types[i] = m->type_section[ti];
    }
    m->consts = malloc(sizeof(int64_t) * (m->n_consts ? m->n_consts : 1));
    for (int i = 0; i < m->n_consts; i++) { m->consts[i] = rd_i64(b + off); off += 8; }
    m->imp_name = malloc(sizeof(char[9]) * (m->n_imports ? m->n_imports : 1));
    m->imp_slot = malloc(sizeof(uint16_t) * (m->n_imports ? m->n_imports : 1));
    for (int i = 0; i < m->n_imports; i++) {
        memcpy(m->imp_name[i], b + off, 8); m->imp_name[i][8] = 0; off += 8;
        m->imp_slot[i] = rd_u16(b + off); off += 2;
    }
    m->code = malloc(sizeof(Insn) * (m->n_code ? m->n_code : 1));
    for (int i = 0; i < m->n_code; i++) {
        m->code[i].op = b[off]; m->code[i].a = b[off+1];
        m->code[i].b = b[off+2]; m->code[i].c = b[off+3];
        m->code[i].imm = rd_i32(b + off + 4); off += 8;
    }
    return 0;
}

/* ------------------------------------------------------------------ verifier */
static const char *tyname(int t) {
    return t == TINT ? "INT" : t == TPTR ? "PTR" : t == TVOID ? "VOID" : "?";
}

static int verify_code(const uint8_t *slot_types, int n_slots, int n_consts,
                       const Insn *code, int n_code, const char *gen) {
#define TY(s)  ((s) < n_slots ? slot_types[(s)] : (REJECTV(s), 0))
#define REJECTV(s) (snprintf(g_reason, sizeof g_reason, "%s: slot %d out of range", gen, (s)))
    for (int pc = 0; pc < n_code; pc++) {
        const Insn *in = &code[pc];
        int a = in->a, b = in->b, c = in->c, imm = in->imm;
        if (a >= n_slots || b >= n_slots || c >= n_slots) {
            /* only slots actually used matter, but bound-checking all three is safe:
             * unused operands are 0 which is always a valid slot index when n_slots>0. */
        }
        switch (in->op) {
        case OP_HALT: break;
        case OP_LDC:
            if (imm < 0 || imm >= n_consts) REJECT("%s@%d: LDC const out of range", gen, pc);
            if (a >= n_slots) REJECT("%s@%d: slot out of range", gen, pc);
            if (slot_types[a] != TINT) REJECT("%s@%d: LDC expects INT dst", gen, pc);
            break;
        case OP_MOV:
            if (a >= n_slots || b >= n_slots) REJECT("%s@%d: slot out of range", gen, pc);
            if (slot_types[a] != slot_types[b])
                REJECT("%s@%d: MOV type mismatch (%s <- %s)", gen, pc,
                       tyname(slot_types[a]), tyname(slot_types[b]));
            break;
        case OP_ADD:
            if (a >= n_slots || b >= n_slots || c >= n_slots)
                REJECT("%s@%d: slot out of range", gen, pc);
            if (slot_types[a] != TINT || slot_types[b] != TINT || slot_types[c] != TINT)
                REJECT("%s@%d: ADD expects INT operands", gen, pc);
            break;
        case OP_ALLOC:
            if (imm < 0 || imm >= n_consts) REJECT("%s@%d: ALLOC const out of range", gen, pc);
            if (a >= n_slots) REJECT("%s@%d: slot out of range", gen, pc);
            if (slot_types[a] != TPTR) REJECT("%s@%d: ALLOC expects PTR dst", gen, pc);
            break;
        case OP_LOAD:
            if (a >= n_slots || b >= n_slots || c >= n_slots)
                REJECT("%s@%d: slot out of range", gen, pc);
            if (slot_types[a] != TINT) REJECT("%s@%d: LOAD expects INT dst", gen, pc);
            if (slot_types[b] != TPTR) REJECT("%s@%d: LOAD expects PTR base", gen, pc);
            if (slot_types[c] != TINT) REJECT("%s@%d: LOAD expects INT index", gen, pc);
            break;
        case OP_STORE:
            if (a >= n_slots || b >= n_slots || c >= n_slots)
                REJECT("%s@%d: slot out of range", gen, pc);
            if (slot_types[a] != TPTR)
                REJECT("%s@%d: STORE expects slot %d to be PTR, declared %s",
                       gen, pc, a, tyname(slot_types[a]));
            if (slot_types[b] != TINT) REJECT("%s@%d: STORE expects INT index", gen, pc);
            if (slot_types[c] != TINT) REJECT("%s@%d: STORE expects INT value", gen, pc);
            break;
        case OP_ASTRA: break;
        default: REJECT("%s@%d: unknown opcode %d", gen, pc, in->op);
        }
    }
    return 0;
#undef TY
#undef REJECTV
}

/* ------------------------------------------------------------------ executor */
/* returns: 1 = ASTRA released (flag), 0 = ran to HALT clean, -1 = fault (g_reason set) */
static int run_code(Host *h, const uint8_t *slot_types, int n_slots,
                    const int64_t *consts, int n_consts,
                    const Insn *code, int n_code,
                    const int64_t *preset_val, const int *preset_set,
                    int64_t *out_vals) {
    (void)slot_types; (void)n_consts;
    int64_t *v = calloc(n_slots ? n_slots : 1, sizeof(int64_t));
    for (int i = 0; i < n_slots; i++) if (preset_set && preset_set[i]) v[i] = preset_val[i];

    int rc = 0;
    for (int pc = 0; pc < n_code; pc++) {
        const Insn *in = &code[pc];
        int a = in->a, b = in->b, c = in->c, imm = in->imm;
        if (in->op == OP_HALT) break;
        else if (in->op == OP_LDC) v[a] = consts[imm];
        else if (in->op == OP_MOV) v[a] = v[b];
        else if (in->op == OP_ADD) v[a] = v[b] + v[c];
        else if (in->op == OP_ALLOC) {
            int64_t length = consts[imm];
            if (length < 0 || h->heap_ptr + 1 + length > CTRL_BASE) {
                snprintf(g_reason, sizeof g_reason, "heap exhausted (len=%lld)",
                         (long long)length); rc = -1; break;
            }
            int handle = h->heap_ptr;
            h->mem[handle] = length;
            h->heap_ptr += 1 + (int)length;
            v[a] = handle;
        }
        else if (in->op == OP_LOAD || in->op == OP_STORE) {
            /* Trusted-tag access: the verifier "guarantees" the base slot is a genuine PTR,
             * so we do NOT re-check that the handle lands in the heap region -- only the
             * element index against the header length and the final address against the
             * arena.  This is the optimisation the cross-gen confusion abuses. */
            int64_t handle = (in->op == OP_LOAD) ? v[b] : v[a];
            int64_t idx    = (in->op == OP_LOAD) ? v[c] : v[b];
            if (handle < 0 || handle >= ARENA_N) {
                snprintf(g_reason, sizeof g_reason, "handle %lld outside arena",
                         (long long)handle); rc = -1; break;
            }
            int64_t length = h->mem[handle];
            if (idx < 0 || idx >= length) {
                snprintf(g_reason, sizeof g_reason,
                         "index %lld out of object bounds (len=%lld)",
                         (long long)idx, (long long)length); rc = -1; break;
            }
            int64_t addr = handle + 1 + idx;
            if (addr < 0 || addr >= ARENA_N) {
                snprintf(g_reason, sizeof g_reason, "address %lld outside arena",
                         (long long)addr); rc = -1; break;
            }
            if (in->op == OP_LOAD) v[a] = h->mem[addr];
            else                   h->mem[addr] = v[c];
        }
        else if (in->op == OP_ASTRA) {
            if (h->mem[ASTRA_LOCK_CELL] == ASTRA_KEY) { rc = 1; break; }
            /* sealed: say nothing here; the DECOY exists only to mislead scanners */
        }
        else { snprintf(g_reason, sizeof g_reason, "bad opcode %d", in->op); rc = -1; break; }
    }
    if (out_vals) for (int i = 0; i < n_slots; i++) out_vals[i] = v[i];
    free(v);
    return rc;
}

/* ------------------------------------------------------------------ link + drive */
/* prints the status line; returns process exit code */
static int drive(const uint8_t *b1, size_t l1, const uint8_t *b2, size_t l2) {
    Gen1 m1; Gen2 m2;
    if (parse_gen1(b1, l1, &m1) < 0) { printf("reject: %s\n", g_reason); return 3; }
    if (parse_gen2(b2, l2, &m2) < 0) { printf("reject: %s\n", g_reason); return 3; }
    if (verify_code(m1.slot_types, m1.n_slots, m1.n_consts, m1.code, m1.n_code, "gen1") < 0) {
        printf("reject: %s\n", g_reason); return 3;
    }
    for (int i = 0; i < m1.n_exports; i++)
        if (m1.exp_slot[i] >= m1.n_slots) { printf("reject: gen1 export slot out of range\n"); return 3; }
    if (verify_code(m2.slot_types, m2.n_slots, m2.n_consts, m2.code, m2.n_code, "gen2") < 0) {
        printf("reject: %s\n", g_reason); return 3;
    }
    for (int i = 0; i < m2.n_imports; i++)
        if (m2.imp_slot[i] >= m2.n_slots) { printf("reject: gen2 import slot out of range\n"); return 3; }

    Host *h = calloc(1, sizeof(Host));
    h->heap_ptr = HEAP_BASE;

    /* phase 1: run gen1 over the shared arena, collect exports (value + gen1 type) */
    int64_t *g1_vals = calloc(m1.n_slots ? m1.n_slots : 1, sizeof(int64_t));
    int r1 = run_code(h, m1.slot_types, m1.n_slots, m1.consts, m1.n_consts,
                      m1.code, m1.n_code, NULL, NULL, g1_vals);
    if (r1 < 0) { printf("fault: %s\n", g_reason); return 4; }
    if (r1 == 1) { /* gen1 shouldn't normally reach astra, but honour it */
        const char *f = getenv("PINAKA_FLAG");
        printf("PINAKA-ASTRA-RELEASED %s\n", f ? f : DECOY_FLAG); return 0;
    }

    /* phase 2: link gen2 imports from gen1 exports.  SHIPPED linker: assign the value and
     * TRUST the gen2 importer's declared slot type -- it never checks gen1's export type.
     * (The fixed linker would compare the two types and reject on mismatch.) */
    int64_t *preset_val = calloc(m2.n_slots ? m2.n_slots : 1, sizeof(int64_t));
    int     *preset_set = calloc(m2.n_slots ? m2.n_slots : 1, sizeof(int));
    for (int i = 0; i < m2.n_imports; i++) {
        int found = -1;
        for (int j = 0; j < m1.n_exports; j++)
            if (strcmp(m2.imp_name[i], m1.exp_name[j]) == 0) { found = j; break; }
        if (found < 0) { printf("reject: unresolved import '%s'\n", m2.imp_name[i]); return 3; }
        int slot = m2.imp_slot[i];
        preset_val[slot] = g1_vals[m1.exp_slot[found]];
        preset_set[slot] = 1;
        /* NOTE: no `if (m1.slot_types[exp_slot] != m2.slot_types[slot]) reject;`  <-- the gap */
    }

    int r2 = run_code(h, m2.slot_types, m2.n_slots, m2.consts, m2.n_consts,
                      m2.code, m2.n_code, preset_val, preset_set, NULL);
    if (r2 < 0) { printf("fault: %s\n", g_reason); return 4; }
    if (r2 == 1) {
        const char *f = getenv("PINAKA_FLAG");
        printf("PINAKA-ASTRA-RELEASED %s\n", f ? f : DECOY_FLAG);
        return 0;
    }
    printf("astra-sealed\n");
    return 2;
}

/* ------------------------------------------------------------------ input */
static uint8_t *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END); long n = ftell(f); fseek(f, 0, SEEK_SET);
    if (n < 0) { fclose(f); return NULL; }
    uint8_t *buf = malloc((size_t)n ? (size_t)n : 1);
    size_t got = fread(buf, 1, (size_t)n, f); fclose(f);
    *out_len = got; return buf;
}

static uint8_t *read_all_stdin(size_t *out_len) {
    size_t cap = 1 << 16, len = 0;
    uint8_t *buf = malloc(cap);
    size_t r;
    while ((r = fread(buf + len, 1, cap - len, stdin)) > 0) {
        len += r;
        if (len == cap) { cap <<= 1; buf = realloc(buf, cap); }
    }
    *out_len = len; return buf;
}

int main(int argc, char **argv) {
    uint8_t *b1, *b2; size_t l1 = 0, l2 = 0;
    if (argc == 3) {
        b1 = read_file(argv[1], &l1);
        b2 = read_file(argv[2], &l2);
        if (!b1 || !b2) { printf("reject: cannot read module files\n"); return 3; }
    } else {
        size_t tot = 0;
        uint8_t *blob = read_all_stdin(&tot);
        if (tot < 8) { printf("reject: short stdin blob\n"); return 3; }
        size_t off = 0;
        uint32_t len1 = (uint32_t)rd_i32(blob + off); off += 4;
        if (off + len1 + 4 > tot) { printf("reject: bad combined blob (len1)\n"); return 3; }
        b1 = blob + off; off += len1; l1 = len1;
        uint32_t len2 = (uint32_t)rd_i32(blob + off); off += 4;
        if (off + len2 > tot) { printf("reject: bad combined blob (len2)\n"); return 3; }
        b2 = blob + off; l2 = len2;
    }
    return drive(b1, l1, b2, l2);
}
