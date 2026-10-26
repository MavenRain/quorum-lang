/* The canonical printer. Each tree has one printed form: the output parses
   back to the same tree, and a second print gives the same bytes. */
#include <stdio.h>
#include <string.h>

#include "front/print.h"

typedef enum {
  PREC_PAIR,  /* a , b */
  PREC_TERM,  /* λ, a system and → */
  PREC_EQUIV, /* a ≡ b */
  PREC_OPER,  /* a ∷ b, a ++ b, f ∘ g and p ∙ q (D5) */
  PREC_TIMES, /* A × B */
  PREC_MAX,   /* r ∨ s */
  PREC_MIN,   /* r ∧ s */
  PREC_NEG,   /* ~ r */
  PREC_APP,   /* f a, Σ A (λ x → B) and Type ℓ */
  PREC_ATOM
} Prec;

/* An arena-backed text buffer. OK is 0 after the arena limit. */
typedef struct {
  Arena *arena;
  char *text;
  size_t len;
  size_t cap;
  int ok;
} Buf;

static void put_bytes(Buf *b, const char *text, size_t len) {
  if (!b->ok) return;
  if (b->len + len + 1 > b->cap) {
    size_t next = b->cap == 0 ? 256 : b->cap;
    while (next < b->len + len + 1) next *= 2;
    char *fresh = arena_alloc(b->arena, next);
    if (fresh == NULL) {
      b->ok = 0;
      return;
    }
    if (b->len > 0) memcpy(fresh, b->text, b->len);
    b->text = fresh;
    b->cap = next;
  }
  if (len > 0) memcpy(b->text + b->len, text, len);
  b->len += len;
  b->text[b->len] = '\0';
}

static void put(Buf *b, const char *text) {
  put_bytes(b, text, strlen(text));
}

static void put_nat(Buf *b, uint64_t value) {
  char digits[24];
  snprintf(digits, sizeof digits, "%llu", (unsigned long long)value);
  put(b, digits);
}

/* `Type`, `Type₁`, `Type₂`, ...: the level in subscript digits. */
static void put_universe(Buf *b, uint64_t level) {
  char digits[24];
  int n = level == 0 ? 0 : snprintf(digits, sizeof digits, "%llu", (unsigned long long)level);
  put(b, "Type");
  for (int i = 0; i < n; i++) {
    char sub[4] = {(char)0xe2, (char)0x82, (char)(0x80 + (digits[i] - '0')), '\0'};
    put(b, sub);
  }
}

/* The infix operators: the AST name, the printed symbol, the precedence of
   the whole and the context of each operand (parser.c parse_term_body,
   parse_equiv, parse_oper and infix_right). */
static const struct {
  const char *name;
  const char *symbol;
  Prec prec;
  Prec left;
  Prec right;
} INFIX[] = {
  {AST_PAIR_NAME, " , ", PREC_PAIR, PREC_EQUIV, PREC_PAIR},
  {AST_PATH_NAME, " ≡ ", PREC_EQUIV, PREC_OPER, PREC_OPER},
  {AST_TIMES_NAME, " × ", PREC_TIMES, PREC_MAX, PREC_TIMES},
  {AST_MAX_NAME, " ∨ ", PREC_MAX, PREC_MIN, PREC_MAX},
  {AST_MIN_NAME, " ∧ ", PREC_MIN, PREC_NEG, PREC_MIN},
  {AST_CONS_NAME, " ∷ ", PREC_OPER, PREC_TIMES, PREC_OPER},
  {AST_APPEND_NAME, " ++ ", PREC_OPER, PREC_TIMES, PREC_OPER},
  {AST_COMPOSE_NAME, " ∘ ", PREC_OPER, PREC_TIMES, PREC_OPER},
  {AST_CONCAT_NAME, " ∙ ", PREC_OPER, PREC_TIMES, PREC_OPER},
};

#define INFIX_COUNT (sizeof INFIX / sizeof INFIX[0])

/* The names of the rows from INFIX_NAMED on lex as names (D5). Applied to
   more than two arguments, they print in prefix form. */
#define INFIX_NAMED 5u

/* `NAME a b` prints infix, for example `_×_ A B` as `A × B`. */
static int is_binary(const Term *t, const char *name) {
  return t->kind == TERM_APP && t->left->kind == TERM_APP && t->left->left->kind == TERM_VAR
      && strcmp(t->left->left->name, name) == 0;
}

/* `~_ r` prints as `~ r`. */
static int is_neg(const Term *t) {
  return t->kind == TERM_APP && t->left->kind == TERM_VAR && strcmp(t->left->name, AST_NEG_NAME) == 0;
}

/* `∥_∥₁ A` prints as `∥ A ∥₁`. */
static int is_trunc(const Term *t) {
  return t->kind == TERM_APP && t->left->kind == TERM_VAR && strcmp(t->left->name, AST_TRUNC_NAME) == 0;
}

static int same_name(const char *a, const char *b) {
  return a == NULL || b == NULL ? a == b : strcmp(a, b) == 0;
}

/* Returns 1 when A and B are the same term. A system compares unequal.
   Spines and binder bodies are walked without recursion. */
static int same_term(const Term *a, const Term *b) {
  while (a != NULL && b != NULL && a != b) {
    if (a->kind != b->kind) return 0;
    switch (a->kind) {
      case TERM_VAR: return strcmp(a->name, b->name) == 0;
      case TERM_NAT: return a->nat == b->nat;
      case TERM_SYSTEM: return 0;
      case TERM_UNIV:
        if (a->nat != b->nat) return 0;
        break;
      case TERM_APP:
        if (!same_term(a->right, b->right)) return 0;
        a = a->left;
        b = b->left;
        continue;
      case TERM_SIGMA:
      case TERM_LAM:
      case TERM_PI:
      case TERM_LET:
        if (!same_name(a->name, b->name) || !same_term(a->left, b->left)) return 0;
        break;
    }
    a = a->right;
    b = b->right;
  }
  return a == b;
}

/* `∃ A (λ (x : A) → B)` prints as `∃[ x ꞉ A ] B` when the binder type is the
   same term as A. */
static int is_exists(const Term *t) {
  return is_binary(t, AST_EXISTS_NAME) && t->right->kind == TERM_LAM && t->right->left != NULL
      && same_term(t->right->left, t->left->right);
}

/* Returns the INFIX row of T, or INFIX_COUNT. */
static size_t infix_row(const Term *t) {
  size_t k = 0;
  while (k < INFIX_COUNT && !is_binary(t, INFIX[k].name)) k++;
  return k;
}

static Prec app_prec(const Term *t) {
  size_t k = infix_row(t);
  return k < INFIX_COUNT ? INFIX[k].prec
       : is_neg(t)        ? PREC_NEG
       : is_trunc(t)      ? PREC_ATOM
       : is_exists(t)     ? PREC_TERM
                          : PREC_APP;
}

/* A D5 name in operator or notation shape is part of a longer spine:
   `_∷_ a b c` prints in prefix form. */
static int named_head(const Term *t) {
  size_t k = infix_row(t);
  return (k >= INFIX_NAMED && k < INFIX_COUNT) || is_trunc(t) || is_exists(t);
}

static Prec term_prec(const Term *t) {
  switch (t->kind) {
    case TERM_VAR:
    case TERM_NAT:
      return PREC_ATOM;
    case TERM_UNIV: return t->right == NULL ? PREC_ATOM : PREC_APP;
    case TERM_APP: return app_prec(t);
    case TERM_SIGMA: return PREC_APP;
    case TERM_LAM:
    case TERM_PI:
    case TERM_SYSTEM:
    case TERM_LET:
      return PREC_TERM;
  }
  return PREC_TERM;
}

static void print_term(Buf *b, const Term *t, Prec ctx);

static void print_app(Buf *b, const Term *t) {
  size_t k = infix_row(t);
  if (k < INFIX_COUNT) {
    print_term(b, t->left->right, INFIX[k].left);
    put(b, INFIX[k].symbol);
    print_term(b, t->right, INFIX[k].right);
    return;
  }
  if (is_neg(t)) {
    put(b, "~ ");
    print_term(b, t->right, PREC_NEG);
    return;
  }
  if (is_trunc(t)) {
    put(b, "∥ ");
    print_term(b, t->right, PREC_TERM);
    put(b, " ∥₁");
    return;
  }
  if (is_exists(t)) {
    put(b, "∃[ ");
    put(b, t->right->name);
    put(b, " ꞉ ");
    print_term(b, t->left->right, PREC_TERM);
    put(b, " ] ");
    print_term(b, t->right->right, PREC_TERM);
    return;
  }
  /* The spine `h a1 ... an` nests to the left. An operator ends it, unless
     its name lexes (D5). */
  size_t n = 0;
  const Term *head = t;
  while (head->kind == TERM_APP && (app_prec(head) == PREC_APP || (head != t && named_head(head)))) {
    n++;
    head = head->left;
  }
  const Term **args = arena_alloc(b->arena, n * sizeof *args);
  if (args == NULL) {
    b->ok = 0;
    return;
  }
  size_t i = n;
  for (const Term *s = t; s != head; s = s->left) {
    i--;
    args[i] = s->right;
  }
  /* `(Type) 2` keeps its parentheses: `Type 2` is the universe at level 2,
     and `Type x` is the universe at the level x. */
  int bare_type = head->kind == TERM_UNIV && head->nat == 0 && head->right == NULL;
  if (bare_type) put(b, "(");
  print_term(b, head, PREC_ATOM);
  if (bare_type) put(b, ")");
  for (i = 0; i < n; i++) {
    put(b, " ");
    print_term(b, args[i], PREC_ATOM);
  }
}

/* Nested lambdas merge: `λ x (y : A) → t`. */
static void print_lambda(Buf *b, const Term *t) {
  const Term *body = t;
  put(b, "λ");
  while (body->kind == TERM_LAM) {
    put(b, " ");
    if (body->left == NULL) {
      put(b, body->name);
    } else {
      put(b, "(");
      put(b, body->name);
      put(b, " : ");
      print_term(b, body->left, PREC_TERM);
      put(b, ")");
    }
    body = body->right;
  }
  put(b, " → ");
  print_term(b, body, PREC_PAIR);
}

/* One binder group for each arrow: `(x : A) → (y : B) → C`. */
static void print_pi(Buf *b, const Term *t) {
  if (t->name != NULL) {
    put(b, "(");
    put(b, t->name);
    put(b, " : ");
    print_term(b, t->left, PREC_TERM);
    put(b, ")");
  } else {
    print_term(b, t->left, PREC_EQUIV);
  }
  put(b, " → ");
  print_term(b, t->right, PREC_TERM);
}

static void print_sigma(Buf *b, const Term *t) {
  put(b, "Σ ");
  print_term(b, t->left, PREC_ATOM);
  put(b, " (λ ");
  put(b, t->name);
  put(b, " → ");
  print_term(b, t->right, PREC_TERM);
  put(b, ")");
}

/* `λ { (i = i0) → a ; (i = i1) (j = i0) → b }` on one line. */
static void print_system(Buf *b, const Term *t) {
  put(b, "λ {");
  for (size_t i = 0; i < t->cell_count; i++) {
    const Cell *cell = &t->cells[i];
    put(b, i == 0 ? " " : " ; ");
    for (size_t j = 0; j < cell->atom_count; j++) {
      put(b, "(");
      put(b, cell->atoms[j].name);
      put(b, cell->atoms[j].end ? " = i1) " : " = i0) ");
    }
    put(b, "→ ");
    print_term(b, cell->body, PREC_PAIR);
  }
  put(b, " }");
}

/* `Type ℓ`: the level is an atom. */
static void print_univ(Buf *b, const Term *t) {
  if (t->right == NULL) {
    put_universe(b, t->nat);
    return;
  }
  put(b, "Type ");
  print_term(b, t->right, PREC_ATOM);
}

/* `let x = t in u` (A1). A let in the body prints as a nested let. */
static void print_let(Buf *b, const Term *t) {
  put(b, "let ");
  put(b, t->name);
  put(b, " = ");
  print_term(b, t->left, PREC_PAIR);
  put(b, " in ");
  print_term(b, t->right, PREC_PAIR);
}

static void print_body(Buf *b, const Term *t) {
  switch (t->kind) {
    case TERM_VAR: put(b, t->name); return;
    case TERM_NAT: put_nat(b, t->nat); return;
    case TERM_UNIV: print_univ(b, t); return;
    case TERM_APP: print_app(b, t); return;
    case TERM_LAM: print_lambda(b, t); return;
    case TERM_PI: print_pi(b, t); return;
    case TERM_SIGMA: print_sigma(b, t); return;
    case TERM_SYSTEM: print_system(b, t); return;
    case TERM_LET: print_let(b, t); return;
  }
}

static void print_term(Buf *b, const Term *t, Prec ctx) {
  int paren = term_prec(t) < ctx;
  if (paren) put(b, "(");
  print_body(b, t);
  if (paren) put(b, ")");
}

/* The bare lambdas at the front of the body print as clause patterns. A
   definition of a section is indented by 2 spaces (D3). */
static void print_def(Buf *b, const Decl *d) {
  const Term *body = d->body;
  const char *indent = d->section != 0u ? "  " : "";
  put(b, indent);
  put(b, d->name);
  put(b, " : ");
  print_term(b, d->type, PREC_TERM);
  put(b, "\n");
  put(b, indent);
  put(b, d->name);
  while (body->kind == TERM_LAM && body->left == NULL) {
    put(b, " ");
    put(b, body->name);
    body = body->right;
  }
  put(b, " = ");
  print_term(b, body, PREC_PAIR);
  put(b, "\n");
}

static void print_postulate(Buf *b, const Decl *d) {
  put(b, "postulate ");
  put(b, d->name);
  put(b, " : ");
  print_term(b, d->type, PREC_TERM);
  put(b, "\n");
}

static void print_field(Buf *b, const Field *f) {
  put(b, "(");
  put(b, f->name);
  put(b, " : ");
  print_term(b, f->type, PREC_TERM);
  put(b, ")");
}

static void print_data(Buf *b, const Decl *d) {
  put(b, "data ");
  put(b, d->name);
  for (size_t i = 0; i < d->param_count; i++) {
    put(b, " ");
    print_field(b, &d->params[i]);
  }
  put(b, " : ");
  for (size_t i = 0; i < d->index_count; i++) {
    print_term(b, d->indices[i], PREC_ATOM);
    put(b, " → ");
  }
  put_universe(b, d->level);
  put(b, " where\n");
  for (size_t i = 0; i < d->ctor_count; i++) {
    const Ctor *ctor = &d->ctors[i];
    put(b, "  ");
    put(b, ctor->name);
    put(b, " : ");
    for (size_t j = 0; j < ctor->field_count; j++) {
      print_field(b, &ctor->fields[j]);
      put(b, " → ");
    }
    if (ctor->result != NULL) {
      print_term(b, ctor->result, PREC_TERM);
      put(b, "\n");
      continue;
    }
    put(b, d->name);
    for (size_t j = 0; j < d->param_count; j++) {
      put(b, " ");
      put(b, d->params[j].name);
    }
    for (size_t j = 0; j < d->index_count; j++) {
      put(b, " ");
      print_term(b, ctor->indices[j], PREC_ATOM);
    }
    put(b, "\n");
  }
}

static void print_record(Buf *b, const Decl *d) {
  put(b, "record ");
  put(b, d->name);
  for (size_t i = 0; i < d->param_count; i++) {
    put(b, " ");
    print_field(b, &d->params[i]);
  }
  put(b, " : ");
  put_universe(b, d->level);
  put(b, " where\n");
  if (d->coinductive) put(b, "  coinductive\n");
  for (size_t i = 0; i < d->field_count; i++) {
    put(b, "  ");
    put(b, d->fields[i].name);
    put(b, " : ");
    print_term(b, d->fields[i].type, PREC_TERM);
    put(b, "\n");
  }
}

static void print_module(Buf *b, const Decl *d) {
  put(b, "module ");
  put(b, d->name);
  for (size_t i = 0; i < d->param_count; i++) {
    put(b, " ");
    print_field(b, &d->params[i]);
  }
  put(b, " where\n");
}

static void print_decl(Buf *b, const Decl *d) {
  switch (d->kind) {
    case DECL_DEF: print_def(b, d); return;
    case DECL_AXIOM: print_postulate(b, d); return;
    case DECL_FAMILY: print_data(b, d); return;
    case DECL_RECORD: print_record(b, d); return;
    case DECL_MODULE: print_module(b, d); return;
  }
}

/* One blank line where the source has one or more between two items. */
static void put_gap(Buf *b, int prev_end, int line) {
  if (prev_end > 0 && line > prev_end + 1) put(b, "\n");
}

static void put_comment(Buf *b, const Comment *note) {
  put_bytes(b, note->text, note->len);
  put(b, "\n");
}

int print_source(Arena *arena, const TokenList *toks, const DeclList *decls, Printed *out, Diag *diag) {
  Buf b = {.arena = arena, .text = NULL, .len = 0, .cap = 0, .ok = 1};
  size_t next = 0;
  int prev_end = 0;
  put_bytes(&b, "", 0);
  for (size_t i = 0; i < decls->count; i++) {
    const Decl *d = &decls->items[i];
    for (; next < toks->comment_count && toks->comments[next].line < d->line; next++) {
      put_gap(&b, prev_end, toks->comments[next].line);
      put_comment(&b, &toks->comments[next]);
      prev_end = toks->comments[next].line;
    }
    put_gap(&b, prev_end, d->line);
    print_decl(&b, d);
    prev_end = d->end_line;
    /* A comment inside a declaration moves to the lines after it. */
    for (; next < toks->comment_count && toks->comments[next].line <= d->end_line; next++) {
      put_comment(&b, &toks->comments[next]);
    }
  }
  for (; next < toks->comment_count; next++) {
    put_gap(&b, prev_end, toks->comments[next].line);
    put_comment(&b, &toks->comments[next]);
    prev_end = toks->comments[next].line;
  }
  if (!b.ok) return diag_fail(diag, "OOM", NULL, "the arena limit is reached while printing");
  out->text = b.text;
  out->len = b.len;
  return 1;
}
