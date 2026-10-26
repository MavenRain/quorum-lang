/* The canonical printer. Each tree has one printed form: the output parses
   back to the same tree, and a second print gives the same bytes. */
#include <stdio.h>
#include <string.h>

#include "front/print.h"

typedef enum {
  PREC_TERM,  /* λ and → */
  PREC_TIMES, /* A × B */
  PREC_APP,   /* f a, and Σ A (λ x → B) */
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

/* `_×_ A B` prints infix as `A × B`. */
static int is_times(const Term *t) {
  return t->kind == TERM_APP && t->left->kind == TERM_APP && t->left->left->kind == TERM_VAR
      && strcmp(t->left->left->name, AST_TIMES_NAME) == 0;
}

static Prec term_prec(const Term *t) {
  switch (t->kind) {
    case TERM_VAR:
    case TERM_NAT:
    case TERM_UNIV:
      return PREC_ATOM;
    case TERM_APP: return is_times(t) ? PREC_TIMES : PREC_APP;
    case TERM_SIGMA: return PREC_APP;
    case TERM_LAM:
    case TERM_PI:
      return PREC_TERM;
  }
  return PREC_TERM;
}

static void print_term(Buf *b, const Term *t, Prec ctx);

static void print_app(Buf *b, const Term *t) {
  if (is_times(t)) {
    print_term(b, t->left->right, PREC_APP);
    put(b, " × ");
    print_term(b, t->right, PREC_TIMES);
    return;
  }
  /* The spine `h a1 ... an` nests to the left. A product ends it. */
  size_t n = 0;
  const Term *head = t;
  while (head->kind == TERM_APP && !is_times(head)) {
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
  /* `(Type) 2` keeps its parentheses: `Type 2` is the universe at level 2. */
  int bare_type = head->kind == TERM_UNIV && head->nat == 0;
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
  print_term(b, body, PREC_TERM);
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
    print_term(b, t->left, PREC_TIMES);
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

static void print_body(Buf *b, const Term *t) {
  switch (t->kind) {
    case TERM_VAR: put(b, t->name); return;
    case TERM_NAT: put_nat(b, t->nat); return;
    case TERM_UNIV: put_universe(b, t->nat); return;
    case TERM_APP: print_app(b, t); return;
    case TERM_LAM: print_lambda(b, t); return;
    case TERM_PI: print_pi(b, t); return;
    case TERM_SIGMA: print_sigma(b, t); return;
  }
}

static void print_term(Buf *b, const Term *t, Prec ctx) {
  int paren = term_prec(t) < ctx;
  if (paren) put(b, "(");
  print_body(b, t);
  if (paren) put(b, ")");
}

/* The bare lambdas at the front of the body print as clause patterns. */
static void print_def(Buf *b, const Decl *d) {
  const Term *body = d->body;
  put(b, d->name);
  put(b, " : ");
  print_term(b, d->type, PREC_TERM);
  put(b, "\n");
  put(b, d->name);
  while (body->kind == TERM_LAM && body->left == NULL) {
    put(b, " ");
    put(b, body->name);
    body = body->right;
  }
  put(b, " = ");
  print_term(b, body, PREC_TERM);
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
    put(b, d->name);
    for (size_t j = 0; j < d->param_count; j++) {
      put(b, " ");
      put(b, d->params[j].name);
    }
    put(b, "\n");
  }
}

static void print_decl(Buf *b, const Decl *d) {
  switch (d->kind) {
    case DECL_DEF: print_def(b, d); return;
    case DECL_AXIOM: print_postulate(b, d); return;
    case DECL_FAMILY: print_data(b, d); return;
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
