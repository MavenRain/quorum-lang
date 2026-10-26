/* Grammar (docs/GRAMMAR.md gives the canonical form):
     file    := decl*
     decl    := NAME ':' term NL NAME NAME* '=' term
              | 'postulate' NAME ':' term
              | 'data' NAME group* ':' TYPE 'where' (NL ctor)+
     ctor    := NAME ':' (group '→')* NAME NAME*
     group   := '(' NAME+ ':' term ')'
     term    := 'λ' (NAME | group)+ '→' term
              | 'λ' '{' cell (';' cell)* '}'
              | group '→' term
              | equiv '→' term
              | equiv (',' term)?
     cell    := ('(' NAME '=' ('i0' | 'i1') ')')+ '→' term
     equiv   := times ('≡' times)?
     times   := max ('×' times)?
     max     := min ('∨' max)?
     min     := neg ('∧' min)?
     neg     := '~' neg | app
     app     := atom atom* | 'Type' atom atom*
     atom    := NAME | NAT | TYPE | '(' term ')' | 'Σ' atom atom
     TYPE    := 'Type' | 'Type₁' | ... | 'Type' NAT
   Layout: a token in column 1 starts a declaration and ends the one before
   it. A constructor line is indented. A token at or left of the column of
   a constructor name ends that constructor. */
#include <stdio.h>
#include <string.h>

#include "front/parser.h"

#define PARSE_MAX_DEPTH 1000

typedef struct {
  const Token *toks;
  size_t count;
  size_t pos;
  Arena *arena;
  Diag *diag;
  const char *source;
  const char *def;
  Origin origin;
  int depth;
  int layout; /* a token at or left of this column ends the current item */
  int base;   /* the indent of the current section: 0, or 2 inside a module (D3) */
} Parser;

/* One binder group: `(x y : A)` gives two names that share one type. */
typedef struct {
  const char **names;
  size_t count;
  const Term *type;
  const Token *tok;
} Binders;

static const Term *parse_term(Parser *p);
static const Term *parse_atom(Parser *p);

static const Token *peek_at(const Parser *p, size_t ahead) {
  size_t i = p->pos + ahead;
  return &p->toks[i < p->count ? i : p->count - 1];
}

static const Token *cur(const Parser *p) {
  return peek_at(p, 0);
}

/* A token at or left of the layout column belongs to the next item. */
static int at_boundary(const Parser *p) {
  return cur(p)->kind == TOK_EOF || cur(p)->col <= p->layout;
}

static int at(const Parser *p, TokKind kind) {
  return cur(p)->kind == kind && (kind == TOK_EOF || !at_boundary(p));
}

static void bump(Parser *p) {
  p->pos += p->pos + 1 < p->count ? 1u : 0u;
}

static int eat(Parser *p, TokKind kind) {
  if (!at(p, kind)) return 0;
  bump(p);
  return 1;
}

static int oom(Parser *p) {
  return diag_fail(p->diag, "OOM", p->def, "%s: the arena limit is reached", p->source);
}

static int fail_at(Parser *p, const Token *tok, const char *what) {
  char found[128];
  text_copy(found, sizeof found, tok->text, tok->len);
  Span span = {p->source, tok->line, tok->col, tok->line, tok->col + utf8_width(tok->text, tok->len)};
  return diag_fail_at(p->diag, "PARSE_EXPECT", p->def, span, what, tok->len > 0 ? found : tok_kind_name(tok->kind),
                      "%s:%d:%d: expected %s, found %s",
                      p->source, tok->line, tok->col, what, tok_kind_name(tok->kind));
}

static int expect(Parser *p, TokKind kind, const char *what) {
  return eat(p, kind) ? 1 : fail_at(p, cur(p), what);
}

/* Consumes the name NAME. WHAT says which name the grammar wants there. */
static int expect_name(Parser *p, const char *name, const char *what) {
  const Token *tok = cur(p);
  if (at(p, TOK_IDENT) && tok->len == strlen(name) && memcmp(tok->text, name, tok->len) == 0) {
    bump(p);
    return 1;
  }
  char want[256];
  snprintf(want, sizeof want, "%s '%s'", what, name);
  return fail_at(p, tok, want);
}

static int enter(Parser *p) {
  p->depth++;
  if (p->depth <= PARSE_MAX_DEPTH) return 1;
  const Token *tok = cur(p);
  Span span = {p->source, tok->line, tok->col, tok->line, tok->col};
  return diag_fail_at(p->diag, "PARSE_DEPTH", p->def, span, NULL, NULL, "%s:%d:%d: terms nest deeper than %d levels",
                      p->source, tok->line, tok->col, PARSE_MAX_DEPTH);
}

static const char *token_text(Parser *p, const Token *tok) {
  char *text = arena_strndup(p->arena, tok->text, tok->len);
  if (text == NULL) oom(p);
  return text;
}

static const char *take_name(Parser *p, const char *what) {
  if (!at(p, TOK_IDENT)) {
    fail_at(p, cur(p), what);
    return NULL;
  }
  const Token *tok = cur(p);
  bump(p);
  return token_text(p, tok);
}

static Term *make_term(Parser *p, TermKind kind, int line, int col) {
  Term *term = arena_alloc(p->arena, sizeof *term);
  if (term == NULL) {
    oom(p);
    return NULL;
  }
  term->kind = kind;
  term->line = line;
  term->col = col;
  return term;
}

/* Grows an arena array by doubling. The old block stays in the arena. */
static void *grow(Parser *p, void *items, size_t count, size_t *cap, size_t size) {
  if (count < *cap) return items;
  size_t next = *cap == 0 ? 4 : *cap * 2;
  void *fresh = arena_alloc(p->arena, next * size);
  if (fresh == NULL) {
    oom(p);
    return NULL;
  }
  if (count > 0) memcpy(fresh, items, count * size);
  *cap = next;
  return fresh;
}

static int starts_atom(const Parser *p) {
  if (at_boundary(p)) return 0;
  switch (cur(p)->kind) {
    case TOK_IDENT:
    case TOK_NAT:
    case TOK_LPAREN:
    case TOK_KW_TYPE:
    case TOK_SIGMA:
      return 1;
    case TOK_EOF:
    case TOK_RPAREN:
    case TOK_COLON:
    case TOK_EQUALS:
    case TOK_ARROW:
    case TOK_LAMBDA:
    case TOK_TIMES:
    case TOK_EQUIV:
    case TOK_TILDE:
    case TOK_AND:
    case TOK_OR:
    case TOK_COMMA:
    case TOK_LBRACE:
    case TOK_RBRACE:
    case TOK_SEMI:
    case TOK_KW_DATA:
    case TOK_KW_WHERE:
    case TOK_KW_POSTULATE:
    case TOK_KW_LET:
    case TOK_KW_IN:
    case TOK_KW_RECORD:
    case TOK_KW_COINDUCTIVE:
    case TOK_KW_MODULE:
      return 0;
  }
  return 0;
}

/* `(` NAME+ `:` starts a binder group. `(f x)` does not. */
static int at_binder_group(const Parser *p) {
  if (!at(p, TOK_LPAREN) || peek_at(p, 1)->kind != TOK_IDENT) return 0;
  size_t ahead = 2;
  while (peek_at(p, ahead)->kind == TOK_IDENT) ahead++;
  return peek_at(p, ahead)->kind == TOK_COLON;
}

static int parse_group(Parser *p, Binders *out) {
  out->tok = cur(p);
  if (!expect(p, TOK_LPAREN, "'('")) return 0;
  size_t start = p->pos;
  while (at(p, TOK_IDENT)) bump(p);
  out->count = p->pos - start;
  if (out->count == 0) return fail_at(p, cur(p), "a binder name");
  out->names = arena_alloc(p->arena, out->count * sizeof *out->names);
  if (out->names == NULL) return oom(p);
  for (size_t i = 0; i < out->count; i++) {
    out->names[i] = token_text(p, &p->toks[start + i]);
    if (out->names[i] == NULL) return 0;
  }
  if (!expect(p, TOK_COLON, "':'")) return 0;
  out->type = parse_term(p);
  return out->type != NULL && expect(p, TOK_RPAREN, "')'");
}

/* A bare lambda binder `x` has no type. The checker infers it. */
static int parse_bare(Parser *p, Binders *out) {
  out->tok = cur(p);
  out->names = arena_alloc(p->arena, sizeof *out->names);
  if (out->names == NULL) return oom(p);
  out->names[0] = take_name(p, "a binder");
  out->count = 1;
  out->type = NULL;
  return out->names[0] != NULL;
}

/* Builds the nested binders of B around BODY, the last name innermost. */
static const Term *wrap(Parser *p, TermKind kind, const Binders *b, const Term *body) {
  const Term *acc = body;
  for (size_t i = b->count; i > 0 && acc != NULL; i--) {
    Term *node = make_term(p, kind, b->tok->line, b->tok->col);
    if (node == NULL) return NULL;
    node->name = b->names[i - 1];
    node->left = b->type;
    node->right = acc;
    acc = node;
  }
  return acc;
}

static const Term *parse_lambda_tail(Parser *p) {
  if (eat(p, TOK_ARROW)) return parse_term(p);
  Binders b;
  int ok = at(p, TOK_IDENT) ? parse_bare(p, &b) : parse_group(p, &b);
  if (!ok || !enter(p)) return NULL;
  const Term *body = parse_lambda_tail(p);
  p->depth--;
  return body == NULL ? NULL : wrap(p, TERM_LAM, &b, body);
}

static const Term *parse_lambda(Parser *p) {
  bump(p);
  if (at(p, TOK_ARROW)) {
    fail_at(p, cur(p), "a binder after 'λ'");
    return NULL;
  }
  return parse_lambda_tail(p);
}

static const Term *parse_binder_type(Parser *p) {
  Binders b;
  if (!parse_group(p, &b) || !expect(p, TOK_ARROW, "'→' after a binder")) return NULL;
  const Term *body = parse_term(p);
  return body == NULL ? NULL : wrap(p, TERM_PI, &b, body);
}

/* `Type` and `Type₁` carry the level. `Type 1` is the ASCII spelling (not
   canonical). */
static const Term *parse_universe(Parser *p) {
  const Token *tok = cur(p);
  bump(p);
  Term *term = make_term(p, TERM_UNIV, tok->line, tok->col);
  if (term == NULL) return NULL;
  term->nat = tok->nat;
  if (tok->len == 4 && at(p, TOK_NAT)) {
    term->nat = cur(p)->nat;
    bump(p);
  }
  return term;
}

/* `Σ A (λ x → B)`: the second atom is a lambda with one bare binder. Its
   name and body become the binder and body of the Sigma. */
static const Term *parse_sigma_tail(Parser *p, const Token *tok) {
  const Term *domain = parse_atom(p);
  if (domain == NULL) return NULL;
  const Token *family_tok = cur(p);
  const Term *family = parse_atom(p);
  if (family == NULL) return NULL;
  if (family->kind != TERM_LAM || family->left != NULL) {
    fail_at(p, family_tok, "a lambda with a bare binder after 'Σ A'");
    return NULL;
  }
  Term *sigma = make_term(p, TERM_SIGMA, tok->line, tok->col);
  if (sigma == NULL) return NULL;
  sigma->name = family->name;
  sigma->left = domain;
  sigma->right = family->right;
  return sigma;
}

/* `Σ Σ A F G` nests without parentheses, so it counts toward the depth
   limit. */
static const Term *parse_sigma(Parser *p) {
  const Token *tok = cur(p);
  bump(p);
  const Term *term = enter(p) ? parse_sigma_tail(p, tok) : NULL;
  p->depth--;
  return term;
}

static const Term *parse_paren(Parser *p) {
  bump(p);
  const Term *inner = parse_term(p);
  return inner != NULL && expect(p, TOK_RPAREN, "')'") ? inner : NULL;
}

static const Term *parse_leaf(Parser *p, TermKind kind) {
  const Token *tok = cur(p);
  Term *term = make_term(p, kind, tok->line, tok->col);
  if (term == NULL) return NULL;
  term->nat = tok->nat;
  term->name = kind == TERM_VAR ? token_text(p, tok) : NULL;
  bump(p);
  return kind == TERM_VAR && term->name == NULL ? NULL : term;
}

static const Term *parse_atom(Parser *p) {
  const Token *tok = cur(p);
  if (!starts_atom(p)) {
    fail_at(p, tok, "a term");
    return NULL;
  }
  switch (tok->kind) {
    case TOK_IDENT: return parse_leaf(p, TERM_VAR);
    case TOK_NAT: return parse_leaf(p, TERM_NAT);
    case TOK_LPAREN: return parse_paren(p);
    case TOK_KW_TYPE: return parse_universe(p);
    case TOK_SIGMA: return parse_sigma(p);
    case TOK_EOF:
    case TOK_RPAREN:
    case TOK_COLON:
    case TOK_EQUALS:
    case TOK_ARROW:
    case TOK_LAMBDA:
    case TOK_TIMES:
    case TOK_EQUIV:
    case TOK_TILDE:
    case TOK_AND:
    case TOK_OR:
    case TOK_COMMA:
    case TOK_LBRACE:
    case TOK_RBRACE:
    case TOK_SEMI:
    case TOK_KW_DATA:
    case TOK_KW_WHERE:
    case TOK_KW_POSTULATE:
    case TOK_KW_LET:
    case TOK_KW_IN:
    case TOK_KW_RECORD:
    case TOK_KW_COINDUCTIVE:
    case TOK_KW_MODULE:
      break;
  }
  fail_at(p, tok, "a term");
  return NULL;
}

/* `Type ℓ`: a bare `Type` at the head of an application takes one level
   atom. `f Type x` and `Σ Type F` do not. */
static const Term *parse_level_univ(Parser *p, const Token *tok) {
  Term *univ = make_term(p, TERM_UNIV, tok->line, tok->col);
  if (univ == NULL) return NULL;
  univ->nat = 0;
  univ->right = parse_atom(p);
  return univ->right == NULL ? NULL : univ;
}

static const Term *parse_app(Parser *p) {
  const Token *first = cur(p);
  const Term *head = parse_atom(p);
  int bare_type = head != NULL && first->kind == TOK_KW_TYPE && first->len == 4 && cur(p) == first + 1;
  if (bare_type && starts_atom(p)) head = parse_level_univ(p, first);
  while (head != NULL && starts_atom(p)) {
    const Term *arg = parse_atom(p);
    Term *app = arg == NULL ? NULL : make_term(p, TERM_APP, head->line, head->col);
    if (app == NULL) return NULL;
    app->left = head;
    app->right = arg;
    head = app;
  }
  return head;
}

/* The named application `NAME left right` of the infix operator at OP. */
static const Term *binary(Parser *p, const Token *op, const char *name, const Term *left, const Term *right) {
  Term *former = right == NULL ? NULL : make_term(p, TERM_VAR, op->line, op->col);
  Term *partial = former == NULL ? NULL : make_term(p, TERM_APP, left->line, left->col);
  Term *whole = partial == NULL ? NULL : make_term(p, TERM_APP, left->line, left->col);
  if (whole == NULL) return NULL;
  former->name = name;
  partial->left = former;
  partial->right = left;
  whole->left = partial;
  whole->right = right;
  return whole;
}

/* A right-associative operator: `a × b × c` is `a × (b × c)`. NEXT parses
   each operand. The right side nests without parentheses, so it counts
   toward the depth limit. */
static const Term *infix_right(Parser *p, TokKind kind, const char *name, const Term *(*next)(Parser *)) {
  const Term *left = next(p);
  if (left == NULL || !at(p, kind)) return left;
  const Token *op = cur(p);
  bump(p);
  const Term *right = enter(p) ? infix_right(p, kind, name, next) : NULL;
  p->depth--;
  return binary(p, op, name, left, right);
}

/* `~ r` is `~_ r`, and `~ p i` is `~ (p i)`. */
static const Term *parse_neg(Parser *p) {
  if (!at(p, TOK_TILDE)) return parse_app(p);
  const Token *op = cur(p);
  bump(p);
  const Term *arg = enter(p) ? parse_neg(p) : NULL;
  p->depth--;
  Term *former = arg == NULL ? NULL : make_term(p, TERM_VAR, op->line, op->col);
  Term *app = former == NULL ? NULL : make_term(p, TERM_APP, op->line, op->col);
  if (app == NULL) return NULL;
  former->name = AST_NEG_NAME;
  app->left = former;
  app->right = arg;
  return app;
}

static const Term *parse_min(Parser *p) {
  return infix_right(p, TOK_AND, AST_MIN_NAME, parse_neg);
}

static const Term *parse_max(Parser *p) {
  return infix_right(p, TOK_OR, AST_MAX_NAME, parse_min);
}

static const Term *parse_times(Parser *p) {
  return infix_right(p, TOK_TIMES, AST_TIMES_NAME, parse_max);
}

/* `a ≡ b` is `_≡_ a b`. It does not chain. */
static const Term *parse_equiv(Parser *p) {
  const Term *left = parse_times(p);
  if (left == NULL || !at(p, TOK_EQUIV)) return left;
  const Token *op = cur(p);
  bump(p);
  return binary(p, op, AST_PATH_NAME, left, parse_times(p));
}

/* `(i = i0)`: one atom of a face. */
static int parse_face_atom(Parser *p, FaceAtom *atom) {
  atom->line = cur(p)->line;
  atom->col = cur(p)->col;
  if (!expect(p, TOK_LPAREN, "'(' of a face")) return 0;
  atom->name = take_name(p, "an interval variable");
  if (atom->name == NULL || !expect(p, TOK_EQUALS, "'='")) return 0;
  const Token *end = cur(p);
  int ident = at(p, TOK_IDENT) && end->len == 2;
  int zero = ident && memcmp(end->text, "i0", 2) == 0;
  int one = ident && memcmp(end->text, "i1", 2) == 0;
  if (!zero && !one) return fail_at(p, end, "'i0' or 'i1'");
  bump(p);
  atom->end = one;
  return expect(p, TOK_RPAREN, "')'");
}

/* One cell: one or more face atoms, '→', then the body. */
static int parse_cell(Parser *p, Cell *cell) {
  FaceAtom *atoms = NULL;
  size_t count = 0;
  size_t cap = 0;
  cell->line = cur(p)->line;
  cell->col = cur(p)->col;
  do {
    atoms = grow(p, atoms, count, &cap, sizeof *atoms);
    if (atoms == NULL || !parse_face_atom(p, &atoms[count])) return 0;
    count++;
  } while (at(p, TOK_LPAREN));
  cell->atoms = atoms;
  cell->atom_count = count;
  if (!expect(p, TOK_ARROW, "'→' after a face")) return 0;
  cell->body = parse_term(p);
  return cell->body != NULL;
}

/* `λ { (i = i0) → a ; (i = i1) → b }`: a system. */
static const Term *parse_system(Parser *p) {
  const Token *tok = cur(p);
  bump(p);
  if (!expect(p, TOK_LBRACE, "'{'")) return NULL;
  Cell *cells = NULL;
  size_t count = 0;
  size_t cap = 0;
  do {
    cells = grow(p, cells, count, &cap, sizeof *cells);
    if (cells == NULL || !parse_cell(p, &cells[count])) return NULL;
    count++;
  } while (eat(p, TOK_SEMI));
  Term *system = expect(p, TOK_RBRACE, "';' or '}'") ? make_term(p, TERM_SYSTEM, tok->line, tok->col) : NULL;
  if (system == NULL) return NULL;
  system->cells = cells;
  system->cell_count = count;
  return system;
}

/* `let x = t in u` (A1). The body extends as far right as it can. */
static const Term *parse_let(Parser *p) {
  const Token *tok = cur(p);
  bump(p);
  const char *name = take_name(p, "a name after 'let'");
  if (name == NULL || !expect(p, TOK_EQUALS, "'=' after the name of a let")) return NULL;
  const Term *bound = parse_term(p);
  if (bound == NULL || !expect(p, TOK_KW_IN, "'in' after the value of a let")) return NULL;
  const Term *body = parse_term(p);
  Term *let = body == NULL ? NULL : make_term(p, TERM_LET, tok->line, tok->col);
  if (let == NULL) return NULL;
  let->name = name;
  let->left = bound;
  let->right = body;
  return let;
}

static const Term *parse_term_body(Parser *p) {
  if (at(p, TOK_KW_LET)) return parse_let(p);
  if (at(p, TOK_LAMBDA)) return peek_at(p, 1)->kind == TOK_LBRACE ? parse_system(p) : parse_lambda(p);
  if (at_binder_group(p)) return parse_binder_type(p);
  const Term *head = parse_equiv(p);
  if (head != NULL && at(p, TOK_COMMA)) {
    const Token *comma = cur(p);
    bump(p);
    return binary(p, comma, AST_PAIR_NAME, head, parse_term(p));
  }
  if (head == NULL || !at(p, TOK_ARROW)) return head;
  const Token *arrow = cur(p);
  bump(p);
  const Term *body = parse_term(p);
  Term *pi = body == NULL ? NULL : make_term(p, TERM_PI, arrow->line, arrow->col);
  if (pi == NULL) return NULL;
  pi->name = NULL;
  pi->left = head;
  pi->right = body;
  return pi;
}

static const Term *parse_term(Parser *p) {
  const Term *term = enter(p) ? parse_term_body(p) : NULL;
  p->depth--;
  return term;
}

static int occurs_free(const Term *t, const char *name);

/* A face atom names a variable too. */
static int occurs_in_system(const Term *t, const char *name) {
  for (size_t i = 0; i < t->cell_count; i++) {
    const Cell *cell = &t->cells[i];
    for (size_t j = 0; j < cell->atom_count; j++) {
      if (strcmp(cell->atoms[j].name, name) == 0) return 1;
    }
    if (occurs_free(cell->body, name)) return 1;
  }
  return 0;
}

/* Returns 1 when NAME occurs free in T. A binder with the same name hides
   it. Spines and binder bodies are walked without recursion. */
static int occurs_free(const Term *t, const char *name) {
  while (t != NULL) {
    switch (t->kind) {
      case TERM_VAR: return strcmp(t->name, name) == 0;
      case TERM_NAT: return 0;
      case TERM_SYSTEM: return occurs_in_system(t, name);
      case TERM_UNIV:
        t = t->right;
        break;
      case TERM_APP:
        if (occurs_free(t->right, name)) return 1;
        t = t->left;
        break;
      case TERM_LAM:
      case TERM_PI:
      case TERM_SIGMA:
      case TERM_LET:
        if (occurs_free(t->left, name)) return 1;
        if (t->name != NULL && strcmp(t->name, name) == 0) return 0;
        t = t->right;
        break;
    }
  }
  return 0;
}

/* Reads binder groups. With ARROWS, a '→' follows each group (the fields
   of a constructor). */
static int parse_fields(Parser *p, int arrows, const Field **out, size_t *out_count) {
  Field *items = NULL;
  size_t count = 0;
  size_t cap = 0;
  while (at_binder_group(p)) {
    Binders b;
    if (!parse_group(p, &b)) return 0;
    if (arrows && !expect(p, TOK_ARROW, "'→' after a field")) return 0;
    for (size_t i = 0; i < b.count; i++) {
      items = grow(p, items, count, &cap, sizeof *items);
      if (items == NULL) return 0;
      items[count].name = b.names[i];
      items[count].type = b.type;
      items[count].line = b.tok->line;
      items[count].col = b.tok->col;
      count++;
    }
  }
  *out = items;
  *out_count = count;
  return 1;
}

/* `f : A` then the clause `f x y = t` in column 1. The patterns become bare
   lambdas around t. */
static int parse_def(Parser *p, Decl *d, const Token *name_tok) {
  d->kind = DECL_DEF;
  d->name = token_text(p, name_tok);
  if (d->name == NULL) return 0;
  p->def = d->name;
  if (!expect(p, TOK_COLON, "':'")) return 0;
  d->type = parse_term(p);
  if (d->type == NULL) return 0;
  p->layout = p->base;
  if (!expect_name(p, d->name, "the clause of")) return 0;
  p->layout = p->base + 1;
  size_t first = p->pos;
  while (at(p, TOK_IDENT)) bump(p);
  size_t last = p->pos;
  if (!expect(p, TOK_EQUALS, "'='")) return 0;
  const Term *acc = parse_term(p);
  for (size_t i = last; i > first && acc != NULL; i--) {
    const Token *tok = &p->toks[i - 1];
    Term *lam = make_term(p, TERM_LAM, tok->line, tok->col);
    const char *name = lam == NULL ? NULL : token_text(p, tok);
    if (name == NULL) return 0;
    lam->name = name;
    lam->left = NULL;
    lam->right = acc;
    acc = lam;
  }
  d->body = acc;
  d->is_rec = acc != NULL && occurs_free(acc, d->name);
  return acc != NULL;
}

static int parse_postulate(Parser *p, Decl *d) {
  d->kind = DECL_AXIOM;
  d->name = take_name(p, "a postulate name");
  if (d->name == NULL) return 0;
  p->def = d->name;
  if (!expect(p, TOK_COLON, "':'")) return 0;
  d->type = parse_term(p);
  return d->type != NULL;
}

/* `c : (f : A) → ... → D p1 ... pn i1 ... im`: the result is the data type
   applied to its parameters, in order, then one atom for each index. */
static int parse_ctor_type(Parser *p, const Decl *d, Ctor *ctor) {
  if (!expect(p, TOK_COLON, "':'") || !parse_fields(p, 1, &ctor->fields, &ctor->field_count)) return 0;
  const Token *head = cur(p);
  ctor->result = NULL;
  ctor->indices = NULL;
  if (!at(p, TOK_IDENT) || head->len != strlen(d->name) || memcmp(head->text, d->name, head->len) != 0) {
    ctor->result = parse_term(p);
    if (ctor->result == NULL) return 0;
    return at_boundary(p) ? 1 : fail_at(p, cur(p), "the end of the constructor");
  }
  if (!expect_name(p, d->name, "the result type")) return 0;
  for (size_t i = 0; i < d->param_count; i++) {
    if (!expect_name(p, d->params[i].name, "the parameter")) return 0;
  }
  const Term **items = NULL;
  size_t cap = 0;
  for (size_t i = 0; i < d->index_count; i++) {
    items = grow(p, items, i, &cap, sizeof *items);
    if (items == NULL) return 0;
    items[i] = parse_atom(p);
    if (items[i] == NULL) return 0;
  }
  ctor->indices = items;
  return at_boundary(p) ? 1 : fail_at(p, cur(p), "the end of the constructor");
}

/* `A1 → ... → Am → Type`: each Ai is an index type. */
static int parse_head(Parser *p, Decl *d) {
  const Token *tok = cur(p);
  const Term *t = parse_term(p);
  const Term **items = NULL;
  size_t count = 0;
  size_t cap = 0;
  while (t != NULL && t->kind == TERM_PI && t->name == NULL) {
    items = grow(p, items, count, &cap, sizeof *items);
    if (items == NULL) return 0;
    items[count] = t->left;
    count++;
    t = t->right;
  }
  if (t == NULL) return 0;
  if (t->kind != TERM_UNIV || t->right != NULL) return fail_at(p, tok, "'Type'");
  d->indices = items;
  d->index_count = count;
  d->level = t->nat;
  return 1;
}

static int parse_data(Parser *p, Decl *d) {
  d->kind = DECL_FAMILY;
  d->name = take_name(p, "a data type name");
  if (d->name == NULL) return 0;
  p->def = d->name;
  if (!parse_fields(p, 0, &d->params, &d->param_count) || !expect(p, TOK_COLON, "':'")) return 0;
  if (!parse_head(p, d) || !expect(p, TOK_KW_WHERE, "'where'")) return 0;
  Ctor *ctors = NULL;
  size_t count = 0;
  size_t cap = 0;
  do {
    if (!at(p, TOK_IDENT)) return fail_at(p, cur(p), "a constructor on an indented line");
    ctors = grow(p, ctors, count, &cap, sizeof *ctors);
    if (ctors == NULL) return 0;
    Ctor *ctor = &ctors[count];
    count++;
    ctor->line = cur(p)->line;
    ctor->col = cur(p)->col;
    ctor->name = take_name(p, "a constructor name");
    if (ctor->name == NULL) return 0;
    p->layout = ctor->col;
    int ok = parse_ctor_type(p, d, ctor);
    p->layout = 1;
    if (!ok) return 0;
  } while (at(p, TOK_IDENT));
  d->ctors = ctors;
  d->ctor_count = count;
  return 1;
}

/* `record NAME params : Type where`, an optional `coinductive` line, then
   one `NAME : type` line for each field (D2). */
static int parse_record(Parser *p, Decl *d) {
  d->kind = DECL_RECORD;
  d->name = take_name(p, "a record name");
  if (d->name == NULL) return 0;
  p->def = d->name;
  if (!parse_fields(p, 0, &d->params, &d->param_count) || !expect(p, TOK_COLON, "':'")) return 0;
  const Token *head = cur(p);
  if (!parse_head(p, d)) return 0;
  if (d->index_count > 0) return fail_at(p, head, "'Type'");
  if (!expect(p, TOK_KW_WHERE, "'where'")) return 0;
  d->coinductive = eat(p, TOK_KW_COINDUCTIVE);
  d->is_rec = 0;
  Field *fields = NULL;
  size_t count = 0;
  size_t cap = 0;
  do {
    if (!at(p, TOK_IDENT)) return fail_at(p, cur(p), "a field on an indented line");
    fields = grow(p, fields, count, &cap, sizeof *fields);
    if (fields == NULL) return 0;
    Field *field = &fields[count];
    count++;
    field->line = cur(p)->line;
    field->col = cur(p)->col;
    field->name = take_name(p, "a field name");
    if (field->name == NULL) return 0;
    p->layout = field->col;
    field->type = expect(p, TOK_COLON, "':'") ? parse_term(p) : NULL;
    int ok = field->type != NULL && (at_boundary(p) || fail_at(p, cur(p), "the end of the field"));
    p->layout = 1;
    if (!ok) return 0;
    d->is_rec = d->is_rec || occurs_free(field->type, d->name);
  } while (at(p, TOK_IDENT));
  d->fields = fields;
  d->field_count = count;
  return 1;
}

/* `module NAME params where`; parse_section reads the definitions (D3). */
static int parse_module(Parser *p, Decl *d) {
  d->kind = DECL_MODULE;
  d->name = take_name(p, "a module name");
  if (d->name == NULL) return 0;
  p->def = d->name;
  return parse_fields(p, 0, &d->params, &d->param_count) && expect(p, TOK_KW_WHERE, "'where'");
}

static int parse_decl(Parser *p, Decl *d) {
  const Token *tok = cur(p);
  p->def = NULL;
  p->layout = p->base;
  d->origin = p->origin;
  d->source = p->source;
  d->line = tok->line;
  d->col = tok->col;
  switch (tok->kind) {
    case TOK_IDENT:
    case TOK_KW_POSTULATE:
    case TOK_KW_DATA:
    case TOK_KW_RECORD:
    case TOK_KW_MODULE:
      break;
    case TOK_EOF:
    case TOK_NAT:
    case TOK_LPAREN:
    case TOK_RPAREN:
    case TOK_COLON:
    case TOK_EQUALS:
    case TOK_ARROW:
    case TOK_LAMBDA:
    case TOK_TIMES:
    case TOK_SIGMA:
    case TOK_EQUIV:
    case TOK_TILDE:
    case TOK_AND:
    case TOK_OR:
    case TOK_COMMA:
    case TOK_LBRACE:
    case TOK_RBRACE:
    case TOK_SEMI:
    case TOK_KW_WHERE:
    case TOK_KW_TYPE:
    case TOK_KW_LET:
    case TOK_KW_IN:
    case TOK_KW_COINDUCTIVE:
      return fail_at(p, tok, "a name, 'postulate', 'data', 'record' or 'module'");
  }
  if (p->base > 0 && (tok->kind != TOK_IDENT || tok->col != p->base + 1))
    return fail_at(p, tok, "a definition indented by 2 spaces (a module holds definitions only)");
  bump(p);
  p->layout = p->base + 1;
  int ok = tok->kind == TOK_KW_DATA ? parse_data(p, d)
         : tok->kind == TOK_KW_RECORD ? parse_record(p, d)
         : tok->kind == TOK_KW_POSTULATE ? parse_postulate(p, d)
         : tok->kind == TOK_KW_MODULE ? parse_module(p, d)
         : parse_def(p, d, tok);
  d->end_line = p->toks[p->pos - 1].line;
  return ok && (d->kind == DECL_MODULE || at_boundary(p) || fail_at(p, cur(p), "the end of the declaration"));
}

/* The definitions of the module at INDEX, each indented by 2 spaces, until
   a line at column 1 (D3). */
static int parse_section(Parser *p, DeclList *list, size_t index) {
  if (cur(p)->kind == TOK_EOF || cur(p)->col == 1)
    return fail_at(p, cur(p), "a definition indented by 2 spaces");
  p->base = 2;
  while (cur(p)->kind != TOK_EOF && cur(p)->col > 1) {
    Decl *items = grow(p, list->items, list->count, &list->cap, sizeof *list->items);
    if (items == NULL) return 0;
    list->items = items;
    items[list->count].section = index + 1;
    if (!parse_decl(p, &items[list->count])) return 0;
    list->count++;
  }
  p->base = 0;
  return 1;
}

/* LIST keeps the declarations parsed before a failure, so a caller can
   count them. */
int parse_source(Arena *arena, const char *source, Origin origin, const TokenList *toks, DeclList *list, Diag *diag) {
  Parser p = {
    .toks = toks->items, .count = toks->count, .pos = 0, .arena = arena, .diag = diag,
    .source = source, .def = NULL, .origin = origin, .depth = 0, .layout = 0, .base = 0,
  };
  while (!at(&p, TOK_EOF)) {
    Decl *items = grow(&p, list->items, list->count, &list->cap, sizeof *list->items);
    if (items == NULL) return 0;
    list->items = items;
    if (!parse_decl(&p, &items[list->count])) return 0;
    list->count++;
    if (items[list->count - 1].kind == DECL_MODULE && !parse_section(&p, list, list->count - 1)) return 0;
  }
  return 1;
}
