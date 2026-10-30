/* The type checker (see front/check.h). SHARED by the tcc kits.

   Checking is bidirectional. A term is checked against an expected type (the
   hint) or its type is inferred. Two types are equal when their normal forms
   are equal (front/eval.c). The checker writes core terms (front/core.h). */
#include "front/check.h"

#include <string.h>

#define CHECK_DEPTH_LIMIT 2000u
#define SPINE_MAX 64u
#define SHOW_MAX 512u
#define NAMES_MAX 64u
#define UNIVERSE_MAX 2u
#define PRINT_MAX 65536u
#define NO_FAMILY UINT32_MAX
#define NO_DEF UINT32_MAX

#define FAIL(c, code, ...) diag_fail_at((c)->m->diag, (code), (c)->m->def, span_of(c), NULL, NULL, __VA_ARGS__)
#define FAIL_NAME(c, name, code, ...) diag_fail_at((c)->m->diag, (code), (c)->m->def, span_named((c), (name)), NULL, NULL, __VA_ARGS__)

typedef struct Scope Scope;
struct Scope {
  const char *name; /* NULL for the binder of `A -> B` */
  const Value *type;
  uint32_t level;
  const Scope *next;
};

typedef struct {
  Machine *m;
  const DeclList *decls;
  size_t decl_index;
  const Scope *scope; /* the innermost binder first */
  const Env *env;     /* a variable for each binder */
  const Value *face;  /* the faces of the enclosing system cells, or NULL */
  uint32_t level;     /* the number of binders */
  unsigned depth;
  uint32_t eta_count;
  uint32_t self;      /* the family whose fields are checked, or NO_FAMILY */
  uint32_t self_uses; /* the uses of that family in the current field */
  const Term *at;     /* the term being checked, for the span of a failure */
  int opens;          /* O72: the body opens a sealed family */
} Checker;

/* The span of a failure: the term being checked, else the declaration.
   A name gets its width; other terms get a point span. */
static Span span_of(const Checker *c) {
  const Decl *d = &c->decls->items[c->decl_index];
  int line = c->at != NULL ? c->at->line : d->line;
  int col = c->at != NULL ? c->at->col : d->col;
  int width = c->at != NULL && c->at->kind == TERM_VAR ? utf8_width(c->at->name, strlen(c->at->name)) : 0;
  return (Span){d->source, line, col, line, col + width};
}

/* The span of a use of NAME: the current term with the width of NAME. A
   name at the head of an application is checked with the application as
   the current term, and there span_of gives one point. */
static Span span_named(const Checker *c, const char *name) {
  Span s = span_of(c);
  s.end_col = s.col + utf8_width(name, strlen(name));
  return s;
}

typedef enum {
  RULE_TYPE0,
  RULE_TYPE1,
  RULE_TYPE2,
  RULE_VALUE0,
  RULE_PAIR,
  RULE_INJ,
  RULE_EMPTY,
  RULE_SOME,
  RULE_CONS,
  RULE_REFL,
  RULE_SIGMA_PART,
  RULE_TIMES,
  RULE_LEVEL,
  RULE_EITHER,
  RULE_OPTION,
  RULE_PURE,
  RULE_MAP,
  RULE_BIND,
  RULE_FILTER,
  RULE_FOLD,
  RULE_ELIM,
  RULE_FOLDB,
  RULE_FOLDI,
  RULE_UNFOLD,
  RULE_NAT2,
  RULE_SUC,
  RULE_FLAG_IF,
  RULE_INTERVAL,
  RULE_IOP,
  RULE_PATHP,
  RULE_PATH_EQ,
  RULE_TRANSP,
  RULE_HCOMP,
  RULE_HOST
} Rule;

typedef struct {
  const char *name;
  uint32_t arity; /* fold: the least number of arguments */
  Rule rule;
  Op op;
  Op result;     /* VALUE0, NAT2: the result type. EMPTY, INJ: the type former. */
  uint32_t part; /* INJ, SIGMA_PART: 0 or 1. HOST: the import number (O105). */
} Builtin;

static const Builtin BUILTINS[] = {
  {"ℕ", 0, RULE_TYPE0, OP_NAT, OP_NAT, 0},
  {"Bool", 0, RULE_TYPE0, OP_FLAG, OP_NAT, 0},
  {"Unit", 0, RULE_TYPE0, OP_UNIT, OP_NAT, 0},
  {"_×_", 2, RULE_TIMES, OP_NAT, OP_NAT, 0},
  {"Maybe", 1, RULE_TYPE1, OP_OPTION, OP_NAT, 0},
  {"unit", 0, RULE_VALUE0, OP_UNIT_VAL, OP_UNIT, 0},
  {"true", 0, RULE_VALUE0, OP_FLAG_YES, OP_FLAG, 0},
  {"false", 0, RULE_VALUE0, OP_FLAG_NO, OP_FLAG, 0},
  {"_,_", 2, RULE_PAIR, OP_PACK, OP_NAT, 0},
  {"nothing", 0, RULE_EMPTY, OP_NONE, OP_OPTION, 0},
  {"just", 1, RULE_SOME, OP_SOME, OP_OPTION, 0},
  {"refl", 0, RULE_REFL, OP_PLAM, OP_PATHP, 0},
  {"fst", 1, RULE_SIGMA_PART, OP_WITNESS, OP_NAT, 0},
  {"snd", 1, RULE_SIGMA_PART, OP_PAYLOAD, OP_NAT, 1},
  {"option", 3, RULE_OPTION, OP_OPTION_ELIM, OP_OPTION, 0},
  {"pure", 1, RULE_PURE, OP_PURE, OP_NAT, 0},
  {"map", 2, RULE_MAP, OP_MAP, OP_NAT, 0},
  {"bind", 2, RULE_BIND, OP_BIND, OP_NAT, 0},
  {"fold", 2, RULE_FOLD, OP_FOLD_NAT, OP_NAT, 0},
  {"elim", 4, RULE_ELIM, OP_ELIM_NAT, OP_NAT, 0},
  {"foldᴮ", 5, RULE_FOLDB, OP_FOLD_BAG, OP_NAT, 0},
  {"foldᴵ", 2, RULE_FOLDI, OP_FOLD_FAMILY, OP_NAT, 0},
  {"natAdd", 2, RULE_NAT2, OP_NAT_ADD, OP_NAT, 0},
  {"suc", 1, RULE_SUC, OP_NAT_ADD, OP_NAT, 0},
  {"natSub", 2, RULE_NAT2, OP_NAT_SUB, OP_NAT, 0},
  {"natMul", 2, RULE_NAT2, OP_NAT_MUL, OP_NAT, 0},
  {"natEq", 2, RULE_NAT2, OP_NAT_EQ, OP_FLAG, 0},
  {"natLe", 2, RULE_NAT2, OP_NAT_LE, OP_FLAG, 0},
  {"flagIf", 3, RULE_FLAG_IF, OP_FLAG_IF, OP_FLAG, 0},
  {"I", 0, RULE_INTERVAL, OP_I, OP_NAT, 0},
  {"i0", 0, RULE_VALUE0, OP_I0, OP_I, 0},
  {"i1", 0, RULE_VALUE0, OP_I1, OP_I, 0},
  {"~_", 1, RULE_IOP, OP_INEG, OP_I, 0},
  {"_∧_", 2, RULE_IOP, OP_IMIN, OP_I, 0},
  {"_∨_", 2, RULE_IOP, OP_IMAX, OP_I, 0},
  {"PathP", 3, RULE_PATHP, OP_PATHP, OP_NAT, 0},
  {"_≡_", 2, RULE_PATH_EQ, OP_PATHP, OP_NAT, 0},
  {"primTransp", 3, RULE_TRANSP, OP_TRANSP, OP_NAT, 0},
  {"primHComp", 2, RULE_HCOMP, OP_HCOMP, OP_NAT, 0},
  {"Level", 0, RULE_TYPE0, OP_LEVEL, OP_NAT, 0},
  {"lzero", 0, RULE_LEVEL, OP_NAT_ADD, OP_LEVEL, 0},
  {"lsuc", 1, RULE_LEVEL, OP_NAT_ADD, OP_LEVEL, 0},
  {"ℓ-max", 2, RULE_LEVEL, OP_NAT_LE, OP_LEVEL, 0},
  {"q_hash2", 2, RULE_HOST, OP_HOST, OP_NAT, 0},
  {"q_frost_verify", 3, RULE_HOST, OP_HOST, OP_NAT, 1},
  {"q_ballot_verify", 5, RULE_HOST, OP_HOST, OP_NAT, 2},
  {"q_tally_add", 3, RULE_HOST, OP_HOST, OP_NAT, 3},
  {"q_partial_verify", 3, RULE_HOST, OP_HOST, OP_NAT, 4},
  {"q_combine", 7, RULE_HOST, OP_HOST, OP_NAT, 5},
  {"q_mpc_check", 3, RULE_HOST, OP_HOST, OP_NAT, 6},
  {"q_mpc_add", 2, RULE_HOST, OP_HOST, OP_NAT, 7},
  {"q_mpc_affine", 3, RULE_HOST, OP_HOST, OP_NAT, 8},
  {"q_mpc_mul", 6, RULE_HOST, OP_HOST, OP_NAT, 9},
  {"q_mpc_mulc", 4, RULE_HOST, OP_HOST, OP_NAT, 10},
  {"q_mpc_open", 3, RULE_HOST, OP_HOST, OP_NAT, 11}
};

#define BUILTIN_COUNT ((uint32_t)(sizeof BUILTINS / sizeof BUILTINS[0]))

/* Names that no declaration can take (rule R4). */
static const char *const RESERVED[] = {"Text"};

/* Core names that S1 took out. A use gives CODE: REFUSE_CELL for the
   cons form (rule R1), REFUSE_BASE for a name outside the design (rule R2). */
typedef struct {
  const char *name;
  const char *code;
  const char *why;
} Refused;

static const Refused REFUSED[] = {
  {"List", "REFUSE_CELL", "List is a cons-form type, and only cell monads are type constructors (rule R1)"},
  {"cons", "REFUSE_CELL", "cons builds a cons-form List, and only cell monads are type constructors (rule R1)"},
  {"nil", "REFUSE_CELL", "nil is the empty cons-form List, and only cell monads are type constructors (rule R1)"},
  {"unfold", "REFUSE_CELL", "unfold builds a cons-form List, and only cell monads are type constructors (rule R1)"},
  {"Sum", "REFUSE_BASE", "Sum is not a base type of the design (rule R2)"},
  {"inl", "REFUSE_BASE", "inl builds a Sum, and Sum is not a base type of the design (rule R2)"},
  {"inr", "REFUSE_BASE", "inr builds a Sum, and Sum is not a base type of the design (rule R2)"},
  {"either", "REFUSE_BASE", "either takes a Sum apart, and Sum is not a base type of the design (rule R2)"},
  {"filter", "REFUSE_BASE", "filter is derived, not a base operation: bind m (λ x → flagIf (p x) (just x) nothing) (rule R2)"}
};

/* The refused row for NAME, or NULL. */
static const Refused *refused(const char *name) {
  size_t i;
  for (i = 0; i < sizeof REFUSED / sizeof REFUSED[0]; i++) {
    if (strcmp(REFUSED[i].name, name) == 0)
      return &REFUSED[i];
  }
  return NULL;
}

typedef enum {
  HEAD_TERM, /* a local, a definition or another term: plain application */
  HEAD_FAMILY,
  HEAD_CTOR,
  HEAD_PROJ,
  HEAD_BUILTIN
} HeadKind;

typedef struct {
  HeadKind kind;
  uint32_t index; /* FAMILY: the family. CTOR, PROJ: the constructor. */
  uint32_t field; /* PROJ: the field number */
  const Builtin *builtin;
} Head;

/* One application of a core name to the arguments of a spine. */
typedef struct {
  Checker *c;
  const Builtin *b;
  const Term *const *args;
  uint32_t argc;      /* the arguments in the spine */
  const Value *hint;  /* the expected type of the result, or NULL */
  const Value *outer; /* the expected type of the whole spine, or NULL */
  uint32_t used;      /* the arguments that the core name takes */
  const Value *type;  /* the type of the result */
} Call;

static const Core *nul(int failed) {
  (void)failed;
  return NULL;
}

static Core *new_core(Checker *c, CoreKind kind) {
  Core *k = arena_alloc(c->m->arena, sizeof *k);
  if (k == NULL) {
    FAIL(c, "OOM", "out of memory");
    return NULL;
  }
  k->kind = kind;
  return k;
}

static const Core *core_index(Checker *c, CoreKind kind, uint32_t index) {
  Core *k = new_core(c, kind);
  if (k != NULL)
    k->index = index;
  return k;
}

static const Core *core_leaf(Checker *c, CoreKind kind, uint64_t nat) {
  Core *k = new_core(c, kind);
  if (k != NULL)
    k->nat = nat;
  return k;
}

static const Core *core_bind(Checker *c, CoreKind kind, const char *name, const Core *a, const Core *b) {
  Core *k;
  if (b == NULL || (a == NULL && kind != CORE_LAM))
    return NULL;
  k = new_core(c, kind);
  if (k == NULL)
    return NULL;
  k->name = name;
  k->a = a;
  k->b = b;
  return k;
}

static const Core *core_app(Checker *c, const Core *f, const Core *x) {
  Core *k;
  if (f == NULL || x == NULL)
    return NULL;
  k = new_core(c, CORE_APP);
  if (k == NULL)
    return NULL;
  k->a = f;
  k->b = x;
  return k;
}

static const Core *core_op(Checker *c, Op op, uint32_t inst, uint32_t field, const Core *const *args, uint32_t n) {
  const Core **copy = arena_alloc(c->m->arena, ((size_t)n + 1u) * sizeof *copy);
  Core *k;
  uint32_t i;
  if (copy == NULL)
    return nul(FAIL(c, "OOM", "out of memory"));
  for (i = 0; i < n; i++) {
    if (args[i] == NULL)
      return NULL;
    copy[i] = args[i];
  }
  k = new_core(c, CORE_OP);
  if (k == NULL)
    return NULL;
  k->op = op;
  k->inst = inst;
  k->field = field;
  k->args = copy;
  k->argc = n;
  return k;
}

static const Core *op3(Checker *c, Op op, uint32_t inst, uint32_t n, const Core *a, const Core *b, const Core *x) {
  const Core *args[3];
  args[0] = a;
  args[1] = b;
  args[2] = x;
  return core_op(c, op, inst, 0, args, n);
}

static const Value *tyop(Checker *c, Op op, uint32_t n, const Value *a, const Value *b, const Value *x) {
  return val_make(c->m, op, 0, n, a, b, x);
}

static const Value *nat_type(Checker *c) {
  return tyop(c, OP_NAT, 0, NULL, NULL, NULL);
}

static const Value *flag_type(Checker *c) {
  return tyop(c, OP_FLAG, 0, NULL, NULL, NULL);
}

static const Value *interval_type(Checker *c) {
  return tyop(c, OP_I, 0, NULL, NULL, NULL);
}

/* The value of the core term K in the current context. */
static const Value *here(Checker *c, const Core *k) {
  return k == NULL ? NULL : eval_core(c->m, c->env, k);
}

/* V in the surface syntax, for a diagnostic. */
static const char *show(Checker *c, const Value *v) {
  const char *names[NAMES_MAX];
  const Scope *s;
  char *buf = arena_alloc(c->m->arena, SHOW_MAX);
  uint32_t count = c->level < NAMES_MAX ? c->level : NAMES_MAX;
  for (s = c->scope; s != NULL; s = s->next) {
    if (s->level < NAMES_MAX)
      names[s->level] = s->name != NULL ? s->name : "_";
  }
  if (buf == NULL || v == NULL)
    return "?";
  value_print(c->m, names, count, v, buf, SHOW_MAX);
  return buf;
}

/* Binds NAME : TYPE to VALUE. A binder passes its own variable. A defined
   local (`let x = t in u`, A1) passes the value of t, so the body checks
   with x unfolded. */
static int push_value(Checker *c, const char *name, const Value *type, const Value *value) {
  Scope *s = arena_alloc(c->m->arena, sizeof *s);
  const Env *e = value == NULL ? NULL : env_push(c->m, c->env, value);
  if (type == NULL || s == NULL || e == NULL)
    return c->m->diag->set ? 0 : FAIL(c, "OOM", "out of memory");
  s->name = name;
  s->type = type;
  s->level = c->level;
  s->next = c->scope;
  c->scope = s;
  c->env = e;
  c->level++;
  return 1;
}

static int push(Checker *c, const char *name, const Value *type) {
  return push_value(c, name, type, val_var(c->m, c->level));
}

static void pop(Checker *c) {
  c->scope = c->scope->next;
  c->env = c->env->next;
  c->level--;
}

/* The checker environment at DEPTH binders, with the variable of each
   literal set to i1 (level * 2) or i0 (level * 2 + 1). */
static const Env *face_env_at(Checker *c, uint32_t depth, const uint32_t *lits, uint32_t n) {
  const Env *env = NULL;
  const Value *v;
  uint32_t level;
  uint32_t i;
  for (level = 0; level < depth; level++) {
    v = val_var(c->m, level);
    for (i = 0; i < n; i++) {
      if (lits[i] / 2u == level)
        v = tyop(c, lits[i] % 2u == 0 ? OP_I1 : OP_I0, 0, NULL, NULL, NULL);
    }
    env = env_push(c->m, env, v);
    if (env == NULL)
      return NULL;
  }
  return env;
}

/* Conversion under the faces of the enclosing system cells (former C1): A
   and B agree on each meet of c->face. The core of each side is evaluated
   again with the variables of the meet set to their ends. */
static int conv_on(Checker *c, uint32_t level, const Value *a, const Value *b) {
  FaceMeets fm;
  const Core *ka;
  const Core *kb;
  const Env *env;
  uint32_t q;
  if (a == NULL || b == NULL)
    return 0;
  if (conv_values(c->m, level, a, b))
    return 1;
  if (c->face == NULL || !face_meets(c->m, level, c->face, &fm))
    return 0;
  ka = quote_value(c->m, level, a);
  kb = quote_value(c->m, level, b);
  if (ka == NULL || kb == NULL)
    return 0;
  for (q = 0; q < fm.count; q++) {
    env = face_env_at(c, level, fm.lit[q], fm.len[q]);
    if ((env == NULL && level > 0) || !conv_values(c->m, level, eval_core(c->m, env, ka), eval_core(c->m, env, kb)))
      return 0;
  }
  return 1;
}

/* 1 when a term of type FOUND can stand where WANT is expected.
   Universes are not cumulative (former F14). */
static int expect(Checker *c, const Value *found, const Value *want) {
  if (found == NULL || want == NULL)
    return 0;
  if (conv_on(c, c->level, found, want))
    return 1;
  return FAIL(c, "TYPE_MISMATCH", "expected a term of type %s, found a term of type %s", show(c, want), show(c, found));
}

static const Scope *find_local(const Checker *c, const char *name) {
  const Scope *s;
  for (s = c->scope; s != NULL; s = s->next) {
    if (s->name != NULL && strcmp(s->name, name) == 0)
      return s;
  }
  return NULL;
}

static uint32_t find_def(const Machine *m, const char *name) {
  uint32_t i;
  for (i = 0; i < m->def_count; i++) {
    if (strcmp(m->defs[i].name, name) == 0)
      return i;
  }
  return NO_DEF;
}

/* An environment that binds VALS in order: the last one is index 0. */
static const Env *env_of(Checker *c, const Value *const *vals, uint32_t n) {
  const Env *e = NULL;
  uint32_t i;
  for (i = 0; i < n; i++)
    e = env_push(c->m, e, vals[i]);
  return e;
}

static const Core *elab(Checker *c, const Term *t, const Value *hint, const Value **type);
static const Core *check_lam(Checker *c, const Term *t, const Value *hint, const Value **type);
static int annotation_ok(Checker *c, const Term *ann, const Value *dom);

static const Core *check_inside(Checker *c, const Term *t, const Value *want);
static const Core *infer_inside(Checker *c, const Term *t, const Value **type);

/* check and infer make T the failure point. A failure inside T keeps the
   innermost point. A success gives the outer point back. */
static const Core *check(Checker *c, const Term *t, const Value *want) {
  const Term *outer = c->at;
  c->at = t;
  const Core *r = check_inside(c, t, want);
  c->at = r != NULL ? outer : c->at;
  return r;
}

static const Core *infer(Checker *c, const Term *t, const Value **type) {
  const Term *outer = c->at;
  c->at = t;
  const Core *r = infer_inside(c, t, type);
  c->at = r != NULL ? outer : c->at;
  return r;
}

static const Core *check_inside(Checker *c, const Term *t, const Value *want) {
  const Value *type = NULL;
  return want == NULL ? NULL : elab(c, t, want, &type);
}

static const Core *infer_inside(Checker *c, const Term *t, const Value **type) {
  *type = NULL;
  return elab(c, t, NULL, type);
}

/* infer, but a failure leaves no diagnostic. */
static const Core *try_infer(Checker *c, const Term *t, const Value **type) {
  Diag saved = *c->m->diag;
  const Core *k = infer(c, t, type);
  if (k == NULL)
    *c->m->diag = saved;
  return k;
}

/* T as a type. INTERVAL 1 also takes the interval I, which is in no
   universe (former C1): only a binder can have the type I. */
static const Core *type_term(Checker *c, const Term *t, int interval, uint64_t *level) {
  const Value *type = NULL;
  const Core *k = infer(c, t, &type);
  if (k == NULL)
    return NULL;
  if (interval && val_is(type, OP_SSET) && val_is(here(c, k), OP_I)) {
    *level = 0;
    return k;
  }
  if (type == NULL || type->kind != VAL_UNIV)
    return nul(FAIL(c, "TYPE_MISMATCH", "expected a type, found a term of type %s", show(c, type)));
  *level = type->nat;
  return k;
}

static const Core *check_type(Checker *c, const Term *t, uint64_t *level) {
  return type_term(c, t, 0, level);
}

/* Compares the inferred *TYPE with HINT. */
static const Core *finish(Checker *c, const Core *k, const Value *hint, const Value **type) {
  if (k == NULL || *type == NULL)
    return NULL;
  if (hint != NULL && !expect(c, *type, hint))
    return NULL;
  *type = hint != NULL ? hint : *type;
  return k;
}

/* 1 when T is Option A, List A or Sum E A. *ELEM is A. */
static int carrier_of(const Value *t, Carrier *carrier, const Value **elem) {
  if (val_is(t, OP_OPTION) || val_is(t, OP_LIST)) {
    *carrier = val_is(t, OP_OPTION) ? CARRIER_OPTION : CARRIER_LIST;
    *elem = t->args[0];
    return 1;
  }
  if (!val_is(t, OP_SUM))
    return 0;
  *carrier = CARRIER_SUM;
  *elem = t->args[1];
  return 1;
}

/* SHAPE (Option, List or Sum E) with the element ELEM. */
static const Value *carried(Checker *c, const Value *shape, const Value *elem) {
  if (shape == NULL)
    return NULL;
  return val_is(shape, OP_SUM) ? tyop(c, OP_SUM, 2, shape->args[0], elem, NULL) : tyop(c, shape->op, 1, elem, NULL, NULL);
}

/* Checks T as a function from DOM. *RESULT is WANT, or the result type that
   T infers when WANT is NULL. */
static const Core *fn_into(Checker *c, const Term *t, const Value *dom, const Value *want, const Value **result) {
  const Value *ft = NULL;
  const Core *f;
  if (want != NULL) {
    *result = want;
    return check(c, t, val_arrow(c->m, dom, want));
  }
  f = infer(c, t, &ft);
  if (f == NULL)
    return NULL;
  if (ft == NULL || ft->kind != VAL_PI)
    return nul(FAIL(c, "TYPE_NOT_FUNCTION", "expected a function, found a term of type %s", show(c, ft)));
  *result = closure_apply(c->m, ft, val_var(c->m, c->level));
  /* Compare at two fresh arguments before the result leaves the binder.
     Reusing its level in expect would capture a dependent result. */
  if (!conv_values(c->m, c->level + 2u, *result,
                   closure_apply(c->m, ft, val_var(c->m, c->level + 1u))))
    return nul(FAIL(c, "TYPE_MISMATCH", "this operation needs a function with a non-dependent result type"));
  return expect(c, ft, val_arrow(c->m, dom, *result)) ? f : NULL;
}

/* The argument type of the function T, from its binder or its type. */
static const Value *lam_domain(Checker *c, const Term *t) {
  uint64_t level = 0;
  const Value *ft = NULL;
  if (t->kind == TERM_LAM && t->left != NULL)
    return here(c, check_type(c, t->left, &level));
  return try_infer(c, t, &ft) != NULL && ft != NULL && ft->kind == VAL_PI ? ft->dom : NULL;
}

/* The carried argument ARG of map, bind or filter. When ARG does not infer
   (`inr 3`), its type comes from the expected type and from the binder of
   the function FN. */
static const Core *carried_arg(Call *k, const Term *arg, const Term *fn, const Value **type) {
  Checker *c = k->c;
  Carrier carrier = CARRIER_OPTION;
  const Value *elem = NULL;
  const Value *dom;
  const Core *x = try_infer(c, arg, type);
  if (x != NULL)
    return x;
  if (!carrier_of(k->hint, &carrier, &elem))
    return infer(c, arg, type);
  dom = lam_domain(c, fn);
  if (dom == NULL)
    return infer(c, arg, type);
  *type = carried(c, k->hint, dom);
  return check(c, arg, *type);
}

static const Core *need_type(Call *k, const char *what) {
  return nul(FAIL(k->c, "TYPE_INFER", "%s needs a declared type %s here", k->b->name, what));
}

static const Core *not_carrier(Call *k, const Value *type) {
  return nul(FAIL(k->c, "TYPE_MISMATCH", "%s needs a value of type Maybe A or List A, found a term of type %s", k->b->name, show(k->c, type)));
}

static const Core *rule_type1(Call *k) {
  uint64_t level = 0;
  const Core *a = check_type(k->c, k->args[0], &level);
  k->type = val_univ(k->c->m, level);
  return op3(k->c, k->b->op, 0, 1, a, NULL, NULL);
}

static const Core *rule_type2(Call *k) {
  uint64_t la = 0;
  uint64_t lb = 0;
  const Core *a = check_type(k->c, k->args[0], &la);
  const Core *b = a == NULL ? NULL : check_type(k->c, k->args[1], &lb);
  k->type = val_univ(k->c->m, la > lb ? la : lb);
  return op3(k->c, k->b->op, 0, 2, a, b, NULL);
}

/* The Sigma over A with the constant codomain B: A × B (D9). */
static const Value *sigma_const(Checker *c, const Value *a, const Value *b) {
  return here(c, core_bind(c, CORE_SIGMA, "_", quote_value(c->m, c->level, a), quote_value(c->m, c->level + 1u, b)));
}

/* A × B: Sigma with a constant codomain (D9). */
static const Core *rule_times(Call *k) {
  Checker *c = k->c;
  uint64_t la = 0;
  uint64_t lb = 0;
  const Core *a = check_type(c, k->args[0], &la);
  const Core *b = a == NULL ? NULL : check_type(c, k->args[1], &lb);
  if (b == NULL)
    return NULL;
  k->type = val_univ(c->m, la > lb ? la : lb);
  return core_bind(c, CORE_SIGMA, "_", a, quote_value(c->m, c->level + 1u, here(c, b)));
}

static const Core *rule_pack(Call *k);

/* a , b: OP_PACK against a Sigma hint, else the constant Sigma of the
   inferred types (D9). */
static const Core *rule_pair(Call *k) {
  Checker *c = k->c;
  const Value *ta = NULL;
  const Value *tb = NULL;
  const Core *a;
  const Core *b;
  if (k->hint != NULL && k->hint->kind == VAL_SIGMA)
    return rule_pack(k);
  a = infer(c, k->args[0], &ta);
  b = a == NULL ? NULL : infer(c, k->args[1], &tb);
  if (b == NULL)
    return NULL;
  k->type = sigma_const(c, ta, tb);
  return op3(c, OP_PACK, 0, 2, a, b, NULL);
}

static const Core *rule_inj(Call *k) {
  if (!val_is(k->hint, OP_SUM))
    return need_type(k, "Sum A B");
  k->type = k->hint;
  return op3(k->c, k->b->op, 0, 1, check(k->c, k->args[0], k->hint->args[k->b->part]), NULL, NULL);
}

static const Core *rule_empty(Call *k) {
  if (!val_is(k->hint, k->b->result))
    return need_type(k, k->b->result == OP_OPTION ? "Maybe A" : "List A");
  k->type = k->hint;
  return op3(k->c, k->b->op, 0, 0, NULL, NULL, NULL);
}

static const Core *rule_some(Call *k) {
  Checker *c = k->c;
  const Value *a = val_is(k->hint, OP_OPTION) ? k->hint->args[0] : NULL;
  const Core *x = a != NULL ? check(c, k->args[0], a) : infer(c, k->args[0], &a);
  k->type = tyop(c, OP_OPTION, 1, a, NULL, NULL);
  return op3(c, OP_SOME, 0, 1, x, NULL, NULL);
}

static const Core *rule_cons(Call *k) {
  Checker *c = k->c;
  const Value *a = val_is(k->hint, OP_LIST) ? k->hint->args[0] : NULL;
  const Core *x = a != NULL ? check(c, k->args[0], a) : infer(c, k->args[0], &a);
  const Value *list = tyop(c, OP_LIST, 1, a, NULL, NULL);
  const Core *xs = x == NULL ? NULL : check(c, k->args[1], list);
  k->type = list;
  return op3(c, OP_CONS, 0, 2, x, xs, NULL);
}

static const Core *rule_pack(Call *k) {
  Checker *c = k->c;
  const Value *s = k->hint;
  const Core *w;
  const Core *p;
  if (s == NULL || s->kind != VAL_SIGMA)
    return need_type(k, "Sigma (x : A) B");
  w = check(c, k->args[0], s->dom);
  p = w == NULL ? NULL : check(c, k->args[1], closure_apply(c->m, s, here(c, w)));
  k->type = s;
  return op3(c, OP_PACK, 0, 2, w, p, NULL);
}

/* lzero, lsuc l and ℓ-max l m (D5): a closed level is a ℕ value of type
   Level, so the ℕ ops compute it. The arity picks the builtin. */
static const Core *rule_level(Call *k) {
  Checker *c = k->c;
  const Value *level = tyop(c, OP_LEVEL, 0, NULL, NULL, NULL);
  const Core *a = k->b->arity == 0u ? NULL : check(c, k->args[0], level);
  const Core *b = k->b->arity < 2u || a == NULL ? NULL : check(c, k->args[1], level);
  k->type = level;
  switch (k->b->arity) {
  case 0u:
    return core_leaf(c, CORE_NAT, 0);
  case 1u:
    return a == NULL ? NULL : op3(c, OP_NAT_ADD, 0, 2, a, core_leaf(c, CORE_NAT, 1u), NULL);
  default:
    return b == NULL ? NULL : op3(c, OP_FLAG_IF, 0, 3, op3(c, OP_NAT_LE, 0, 2, a, b, NULL), b, a);
  }
}

/* Type ℓ (D5): ℓ is a Level with a closed normal form below UNIVERSE_MAX. */
static const Core *univ_level(Checker *c, const Term *t, const Value *hint, const Value **type) {
  const Core *l = check(c, t->right, tyop(c, OP_LEVEL, 0, NULL, NULL, NULL));
  const Value *v = here(c, l);
  if (l == NULL)
    return NULL;
  if (v == NULL || v->kind != VAL_NAT)
    return nul(FAIL(c, "TYPE_UNIVERSE", "the level %s is not closed; S2 has no level variables", show(c, v)));
  if (v->nat >= UNIVERSE_MAX)
    return nul(FAIL(c, "TYPE_UNIVERSE", "the universe level %llu is above the largest level %u", (unsigned long long)v->nat, UNIVERSE_MAX - 1u));
  *type = val_univ(c->m, v->nat + 1u);
  return finish(c, core_leaf(c, CORE_UNIV, v->nat), hint, type);
}

/* I : SSet (former C1). */
static const Core *rule_interval(Call *k) {
  k->type = tyop(k->c, OP_SSET, 0, NULL, NULL, NULL);
  return op3(k->c, OP_I, 0, 0, NULL, NULL, NULL);
}

/* ~ r, r ∧ s and r ∨ s: each argument is in I. */
static const Core *rule_iop(Call *k) {
  const Value *i = interval_type(k->c);
  const Core *a = check(k->c, k->args[0], i);
  const Core *b = k->b->arity < 2u || a == NULL ? NULL : check(k->c, k->args[1], i);
  k->type = i;
  return op3(k->c, k->b->op, 0, k->b->arity, a, b, NULL);
}

/* The line L of PathP L a b: a function from I into a universe (former
   C2). *LEVEL is the universe. */
static const Core *path_line(Checker *c, const Term *t, uint64_t *level) {
  const Value *lt = NULL;
  const Value *cod;
  const Core *body;
  const Core *k;
  if (t->kind == TERM_LAM) {
    if (t->left != NULL && !annotation_ok(c, t->left, interval_type(c)))
      return NULL;
    if (!push(c, t->name, interval_type(c)))
      return NULL;
    body = check_type(c, t->right, level);
    pop(c);
    return core_bind(c, CORE_LAM, t->name, NULL, body);
  }
  k = infer(c, t, &lt);
  if (k == NULL)
    return NULL;
  cod = lt != NULL && lt->kind == VAL_PI && val_is(lt->dom, OP_I) ? closure_apply(c->m, lt, val_var(c->m, c->level)) : NULL;
  if (cod == NULL || cod->kind != VAL_UNIV)
    return nul(FAIL(c, "TYPE_MISMATCH", "PathP needs a line of type I → Type, found a term of type %s", show(c, lt)));
  *level = cod->nat;
  return k;
}

static const Value *at_end(Checker *c, const Value *line, Op end) {
  return apply_value(c->m, line, tyop(c, end, 0, NULL, NULL, NULL));
}

/* PathP L a b : Type n, for L : I → Type n, a : L i0 and b : L i1. */
static const Core *rule_pathp(Call *k) {
  Checker *c = k->c;
  uint64_t level = 0;
  const Core *l = path_line(c, k->args[0], &level);
  const Value *lv = here(c, l);
  const Core *a = lv == NULL ? NULL : check(c, k->args[1], at_end(c, lv, OP_I0));
  const Core *b = a == NULL ? NULL : check(c, k->args[2], at_end(c, lv, OP_I1));
  k->type = val_univ(c->m, level);
  return op3(c, OP_PATHP, 0, 3, l, a, b);
}

#define LEVEL_UNKNOWN UINT64_MAX

static uint64_t level_max(uint64_t a, uint64_t b) {
  if (a == LEVEL_UNKNOWN || b == LEVEL_UNKNOWN)
    return LEVEL_UNKNOWN;
  return a > b ? a : b;
}

/* The universe of the type A at LEVEL binders, read off its value. A
   neutral type that is not a local of the context, and a pretype (I,
   Partial), give LEVEL_UNKNOWN. */
static uint64_t type_level(Checker *c, uint32_t level, const Value *a) {
  const Scope *s;
  uint64_t n = 0;
  uint32_t i;
  if (a == NULL)
    return LEVEL_UNKNOWN;
  if (a->kind == VAL_UNIV)
    return a->nat + 1u;
  if (a->kind == VAL_PI || a->kind == VAL_SIGMA)
    return level_max(type_level(c, level, a->dom), type_level(c, level + 1u, closure_apply(c->m, a, val_var(c->m, level))));
  if (a->kind == VAL_VAR) {
    for (s = c->scope; s != NULL; s = s->next) {
      if (s->level == a->nat && s->type != NULL && s->type->kind == VAL_UNIV)
        return s->type->nat;
    }
    return LEVEL_UNKNOWN;
  }
  if (a->kind != VAL_OP || val_is(a, OP_I) || val_is(a, OP_SSET) || val_is(a, OP_PARTIAL))
    return LEVEL_UNKNOWN;
  if (val_is(a, OP_FAMILY))
    return c->m->families[a->inst].universe;
  if (val_is(a, OP_PATHP))
    return type_level(c, level + 1u, apply_value(c->m, a->args[0], val_var(c->m, level)));
  for (i = 0; i < a->argc; i++)
    n = level_max(n, type_level(c, level, a->args[i]));
  return n;
}

/* a ≡ b: PathP over the constant line of the type of a, else of the type
   of b (D7). */
static const Core *rule_path_eq(Call *k) {
  Checker *c = k->c;
  const Value *ta = NULL;
  const Core *a = try_infer(c, k->args[0], &ta);
  const Core *b;
  uint64_t level;
  if (a == NULL && try_infer(c, k->args[1], &ta) == NULL)
    return nul(FAIL(c, "TYPE_INFER", "neither side of a ≡ b infers its type; write PathP (λ _ → A) a b"));
  a = a != NULL ? a : check(c, k->args[0], ta);
  b = a == NULL ? NULL : check(c, k->args[1], ta);
  if (b == NULL)
    return NULL;
  level = type_level(c, c->level, ta);
  if (level == LEVEL_UNKNOWN)
    return nul(FAIL(c, "TYPE_INFER", "the universe of %s is not known here; write PathP (λ _ → %s) a b", show(c, ta), show(c, ta)));
  k->type = val_univ(c->m, level);
  return op3(c, OP_PATHP, 0, 3, core_bind(c, CORE_LAM, "_", NULL, quote_value(c->m, c->level + 1u, ta)), a, b);
}

/* refl against PathP L a b (D6): λ i → a, when L is constant and a and b
   have the same normal form. */
static const Core *refl_path(Call *k) {
  Checker *c = k->c;
  const Value *e = k->hint;
  const Value *line = apply_value(c->m, e->args[0], val_var(c->m, c->level));
  if (!conv_on(c, c->level + 1u, line, at_end(c, e->args[0], OP_I0)))
    return nul(FAIL(c, "TYPE_REFL", "refl needs a constant line, found a path over %s", show(c, e->args[0])));
  if (!conv_on(c, c->level, e->args[1], e->args[2]))
    return nul(FAIL(c, "TYPE_REFL", "refl cannot prove the equality: the left side normalizes to %s, the right side normalizes to %s", show(c, e->args[1]), show(c, e->args[2])));
  k->type = e;
  return op3(c, OP_PLAM, 0, 1, core_bind(c, CORE_LAM, "i", NULL, quote_value(c->m, c->level + 1u, e->args[1])), NULL, NULL);
}

static const Core *var_core(Checker *c, const char *name, const Value **type);

#define CELLS_MAX FACE_MEETS_MAX

/* 1 when LINE is constant: LINE at a fresh point is LINE at i0. */
static int line_const(Checker *c, const Value *line) {
  return conv_on(c, c->level + 1u, apply_value(c->m, line, val_var(c->m, c->level)), at_end(c, line, OP_I0));
}

/* The line LINE is constant on each meet of R, so primTransp A r u = u where
   r holds. A neutral atom in a meet stays, so the test is stricter, and
   sound. */
static int line_const_on(Checker *c, const Core *line, const Value *r) {
  FaceMeets fm;
  const Env *env;
  const Value *lv;
  const Core *closed = quote_value(c->m, c->level, here(c, line));
  uint32_t q;
  if (closed == NULL)
    return 0;
  if (c->face != NULL)
    r = tyop(c, OP_IMIN, 2, r, c->face, NULL);
  if (r == NULL)
    return 0;
  if (!face_meets(c->m, c->level, r, &fm)) {
    lv = here(c, line);
    return lv != NULL && line_const(c, lv) ? 1 : FAIL(c, "TYPE_MISMATCH", "primTransp needs a line that is constant where r holds, found the line %s", show(c, lv));
  }
  for (q = 0; q < fm.count; q++) {
    env = face_env_at(c, c->level, fm.lit[q], fm.len[q]);
    lv = env == NULL && c->level > 0 ? NULL : eval_core(c->m, env, closed);
    if (lv == NULL)
      return c->m->diag->set ? 0 : FAIL(c, "OOM", "out of memory");
    if (!line_const(c, lv))
      return FAIL(c, "TYPE_MISMATCH", "primTransp needs a line that is constant where r holds, found the line %s", show(c, here(c, line)));
  }
  return 1;
}

/* primTransp A r u (former C3): A : I → Type n, r : I and u : A i0, of type
   A i1. A is constant where r holds. */
static const Core *rule_transp(Call *k) {
  Checker *c = k->c;
  uint64_t level = 0;
  const Core *line = path_line(c, k->args[0], &level);
  const Value *lv = here(c, line);
  const Core *r = lv == NULL ? NULL : check(c, k->args[1], interval_type(c));
  const Core *u;
  if (r == NULL || !line_const_on(c, line, here(c, r)))
    return NULL;
  u = check(c, k->args[2], at_end(c, lv, OP_I0));
  k->type = at_end(c, lv, OP_I1);
  return op3(c, OP_TRANSP, 0, 3, line, r, u);
}

/* The face of CELL: the meet of its atoms. `(i = i1)` is i and `(i = i0)`
   is ~ i. Each atom names a local of type I. */
static const Core *face_core(Checker *c, const Cell *cell) {
  const Core *acc = cell->atom_count == 0 ? op3(c, OP_I1, 0, 0, NULL, NULL, NULL) : NULL;
  const Value *type = NULL;
  const Scope *s;
  const Core *v;
  size_t i;
  for (i = 0; i < cell->atom_count; i++) {
    s = find_local(c, cell->atoms[i].name);
    if (s == NULL || !val_is(s->type, OP_I))
      return nul(FAIL(c, "TYPE_SYSTEM", "the face (%s = i%d) needs a variable of type I", cell->atoms[i].name, cell->atoms[i].end));
    v = var_core(c, cell->atoms[i].name, &type);
    if (v == NULL)
      return NULL;
    v = cell->atoms[i].end == 0 ? op3(c, OP_INEG, 0, 1, v, NULL, NULL) : v;
    acc = acc == NULL ? v : op3(c, OP_IMIN, 0, 2, acc, v, NULL);
  }
  return acc;
}

/* T against WANT under the face FACE, in conjunction with the faces of the
   enclosing cells. A face that never holds still gets the ordinary checks. */
static const Core *check_on(Checker *c, const Term *t, const Value *want, const Core *face) {
  FaceMeets fm;
  const Value *saved = c->face;
  const Value *fv = here(c, face);
  const Core *out;
  c->face = saved == NULL ? fv : tyop(c, OP_IMIN, 2, saved, fv, NULL);
  if (c->face == NULL) {
    c->face = saved;
    return NULL;
  }
  if (face_meets(c->m, c->level, c->face, &fm) && fm.count == 0)
    c->face = saved;
  out = check(c, t, want);
  c->face = saved;
  return out;
}

/* The cells UA and UB agree on each meet of the faces FA ∧ FB. A neutral
   atom in a meet stays, so the test is stricter, and sound. */
static int cells_agree(Checker *c, const Core *fa, const Core *ua, const Core *fb, const Core *ub) {
  FaceMeets fm;
  const Value *meet = here(c, op3(c, OP_IMIN, 0, 2, fa, fb, NULL));
  /* Unfold defined locals before substituting interval endpoints. */
  const Core *ka = quote_value(c->m, c->level, here(c, ua));
  const Core *kb = quote_value(c->m, c->level, here(c, ub));
  const Env *env;
  const Value *x;
  const Value *y;
  uint32_t q;
  if (meet == NULL || ka == NULL || kb == NULL)
    return 0;
  if (c->face != NULL)
    meet = tyop(c, OP_IMIN, 2, meet, c->face, NULL);
  if (!face_meets(c->m, c->level, meet, &fm))
    return FAIL(c, "TYPE_SYSTEM", "the overlap %s of two faces is not in the face bounds", show(c, meet));
  for (q = 0; q < fm.count; q++) {
    env = face_env_at(c, c->level, fm.lit[q], fm.len[q]);
    x = env == NULL && c->level > 0 ? NULL : eval_core(c->m, env, ka);
    y = x == NULL ? NULL : eval_core(c->m, env, kb);
    if (x == NULL || y == NULL)
      return c->m->diag->set ? 0 : FAIL(c, "OOM", "out of memory");
    if (!conv_values(c->m, c->level, x, y))
      return FAIL(c, "TYPE_SYSTEM", "two cells disagree where the faces meet at %s: %s against %s", show(c, meet), show(c, x), show(c, y));
  }
  return 1;
}

/* The side `λ j → λ { φ₁ → u₁ ; ... }` of primHComp (former C2), against
   TY with j : I. Pass 1 checks each face in the outer context, so a face
   cannot name j: the faces go to FK and their join to *PHI. Pass 2 checks
   the cells under j (UK) and their overlaps on these same faces. */
static const Core *side_of(Checker *c, const Term *t, const Value *ty, const Core **phi, const Core **fk, const Core **uk, uint32_t *n) {
  const Term *s = t->kind == TERM_LAM ? t->right : NULL;
  const Value *fv[CELLS_MAX];
  const Core *inner[CELLS_MAX];
  const Core *body;
  uint32_t i;
  uint32_t q;
  *n = 0;
  *phi = op3(c, OP_I0, 0, 0, NULL, NULL, NULL);
  if (s == NULL || s->kind != TERM_SYSTEM)
    return nul(FAIL(c, "TYPE_SYSTEM", "primHComp needs the side λ j → λ { (i = i0) → a ; ... }"));
  if (t->left != NULL && !annotation_ok(c, t->left, interval_type(c)))
    return NULL;
  if (s->cell_count > CELLS_MAX)
    return nul(FAIL(c, "TYPE_SYSTEM", "a system needs at most %u cells", (unsigned)CELLS_MAX));
  for (; *n < s->cell_count; (*n)++) {
    fk[*n] = face_core(c, &s->cells[*n]);
    fv[*n] = here(c, fk[*n]);
    if (fv[*n] == NULL)
      return NULL;
    *phi = *n == 0 ? fk[0] : op3(c, OP_IMAX, 0, 2, *phi, fk[*n], NULL);
  }
  if (!push(c, t->name, interval_type(c)))
    return NULL;
  for (i = 0; i < *n; i++) {
    inner[i] = quote_value(c->m, c->level, fv[i]);
    uk[i] = inner[i] == NULL ? NULL : check_on(c, s->cells[i].body, ty, inner[i]);
    if (uk[i] == NULL) {
      pop(c);
      return NULL;
    }
  }
  for (i = 0; i < *n; i++) {
    for (q = i + 1u; q < *n; q++) {
      if (!cells_agree(c, inner[i], uk[i], inner[q], uk[q])) {
        pop(c);
        return NULL;
      }
    }
  }
  body = op3(c, OP_SYSNIL, 0, 0, NULL, NULL, NULL);
  for (i = *n; i > 0; i--)
    body = op3(c, OP_SYSTEM, 0, 3, inner[i - 1u], uk[i - 1u], body);
  pop(c);
  return core_bind(c, CORE_LAM, t->name, NULL, body);
}

/* The base condition of primHComp (former C2): where its face FK holds,
   each cell UK of the side at j = i0 is U0. */
static int side_base(Checker *c, const Core *const *fk, const Core *const *uk, uint32_t n, const Core *u0) {
  const Core *i0 = op3(c, OP_I0, 0, 0, NULL, NULL, NULL);
  const Core *i1 = op3(c, OP_I1, 0, 0, NULL, NULL, NULL);
  uint32_t q;
  for (q = 0; q < n; q++) {
    if (!cells_agree(c, fk[q], core_app(c, core_bind(c, CORE_LAM, "j", NULL, uk[q]), i0), i1, u0))
      return 0;
  }
  return 1;
}

/* primHComp side u0 (former C3): A is the hint, else the type of u0, and A
   is in a universe; phi is the join of the faces of side; where its face
   holds, each cell at j = i0 is u0. The type is A. */
static const Core *rule_hcomp(Call *k) {
  Checker *c = k->c;
  const Value *a = k->hint;
  const Core *fk[CELLS_MAX];
  const Core *uk[CELLS_MAX];
  const Core *args[4];
  const Core *phi = NULL;
  const Core *side;
  const Core *u0 = NULL;
  uint32_t n = 0;
  if (a == NULL) {
    u0 = try_infer(c, k->args[1], &a);
    if (u0 == NULL)
      return need_type(k, "A");
  }
  if (val_is(a, OP_I) || val_is(a, OP_SSET) || val_is(a, OP_PARTIAL))
    return nul(FAIL(c, "TYPE_MISMATCH", "primHComp needs a type in a universe, found the pretype %s", show(c, a)));
  side = side_of(c, k->args[0], a, &phi, fk, uk, &n);
  if (side == NULL)
    return NULL;
  u0 = u0 != NULL ? u0 : check(c, k->args[1], a);
  if (u0 == NULL || !side_base(c, fk, uk, n, u0))
    return NULL;
  k->type = a;
  args[0] = quote_value(c->m, c->level, a);
  args[1] = phi;
  args[2] = side;
  args[3] = u0;
  return core_op(c, OP_HCOMP, 0, 0, args, 4u);
}

/* refl needs a PathP hint (D6). */
static const Core *rule_refl(Call *k) {
  if (!val_is(k->hint, OP_PATHP))
    return need_type(k, "a ≡ b");
  return refl_path(k);
}

static const Core *rule_sigma_part(Call *k) {
  Checker *c = k->c;
  const Value *st = NULL;
  const Core *s = infer(c, k->args[0], &st);
  const Core *w;
  if (s == NULL)
    return NULL;
  if (st == NULL || st->kind != VAL_SIGMA)
    return nul(FAIL(c, "TYPE_MISMATCH", "%s needs a Sigma value, found a term of type %s", k->b->name, show(c, st)));
  w = op3(c, OP_WITNESS, 0, 1, s, NULL, NULL);
  k->type = k->b->part == 0u ? st->dom : closure_apply(c->m, st, here(c, w));
  return k->b->part == 0u ? w : op3(c, OP_PAYLOAD, 0, 1, s, NULL, NULL);
}

/* either f g s */
static const Core *rule_either(Call *k) {
  Checker *c = k->c;
  const Value *st = NULL;
  const Value *res = NULL;
  const Core *s = infer(c, k->args[2], &st);
  const Core *f;
  const Core *g;
  if (s == NULL)
    return NULL;
  if (!val_is(st, OP_SUM))
    return nul(FAIL(c, "TYPE_MISMATCH", "either needs a value of type Sum A B, found a term of type %s", show(c, st)));
  f = fn_into(c, k->args[0], st->args[0], k->hint, &res);
  g = f == NULL ? NULL : check(c, k->args[1], val_arrow(c->m, st->args[1], res));
  k->type = res;
  return op3(c, OP_EITHER, 0, 3, f, g, s);
}

/* option z f o */
static const Core *rule_option(Call *k) {
  Checker *c = k->c;
  const Value *ot = NULL;
  const Value *res = k->hint;
  const Core *o = infer(c, k->args[2], &ot);
  const Core *z;
  const Core *f;
  if (o == NULL)
    return NULL;
  if (!val_is(ot, OP_OPTION))
    return nul(FAIL(c, "TYPE_MISMATCH", "option needs a value of type Maybe A, found a term of type %s", show(c, ot)));
  z = res != NULL ? check(c, k->args[0], res) : infer(c, k->args[0], &res);
  f = z == NULL ? NULL : check(c, k->args[1], val_arrow(c->m, ot->args[0], res));
  k->type = res;
  return op3(c, OP_OPTION_ELIM, 0, 3, z, f, o);
}

static const Core *rule_pure(Call *k) {
  Carrier carrier = CARRIER_OPTION;
  const Value *a = NULL;
  if (!carrier_of(k->hint, &carrier, &a))
    return need_type(k, "Maybe A or List A");
  k->type = k->hint;
  return op3(k->c, OP_PURE, carrier, 1, check(k->c, k->args[0], a), NULL, NULL);
}

/* map f m */
static const Core *rule_map(Call *k) {
  Checker *c = k->c;
  Carrier carrier = CARRIER_OPTION;
  Carrier hint_carrier = CARRIER_OPTION;
  const Value *mt = NULL;
  const Value *a = NULL;
  const Value *b = NULL;
  const Value *hint_elem = NULL;
  const Core *x = carried_arg(k, k->args[1], k->args[0], &mt);
  const Core *f;
  if (x == NULL)
    return NULL;
  if (!carrier_of(mt, &carrier, &a))
    return not_carrier(k, mt);
  f = fn_into(c, k->args[0], a, carrier_of(k->hint, &hint_carrier, &hint_elem) ? hint_elem : NULL, &b);
  k->type = carried(c, mt, b);
  return op3(c, OP_MAP, carrier, 2, f, x, NULL);
}

/* bind m f */
static const Core *rule_bind(Call *k) {
  Checker *c = k->c;
  Carrier carrier = CARRIER_OPTION;
  Carrier result_carrier = CARRIER_OPTION;
  const Value *mt = NULL;
  const Value *a = NULL;
  const Value *b = NULL;
  const Value *res = NULL;
  const Core *x = carried_arg(k, k->args[0], k->args[1], &mt);
  const Core *f;
  if (x == NULL)
    return NULL;
  if (!carrier_of(mt, &carrier, &a))
    return not_carrier(k, mt);
  f = fn_into(c, k->args[1], a, k->hint, &res);
  if (f == NULL)
    return NULL;
  if (!carrier_of(res, &result_carrier, &b) || result_carrier != carrier)
    return nul(FAIL(c, "TYPE_MISMATCH", "bind needs a function into the carrier of %s, found one into %s", show(c, mt), show(c, res)));
  if (carrier == CARRIER_SUM && !conv_values(c->m, c->level, res->args[0], mt->args[0]))
    return nul(FAIL(c, "TYPE_MISMATCH", "bind must preserve the Sum error type %s, found %s", show(c, mt->args[0]), show(c, res->args[0])));
  k->type = res;
  return op3(c, OP_BIND, carrier, 2, x, f, NULL);
}

/* filter p m */
static const Core *rule_filter(Call *k) {
  Checker *c = k->c;
  Carrier carrier = CARRIER_OPTION;
  const Value *mt = NULL;
  const Value *a = NULL;
  const Core *x = carried_arg(k, k->args[1], k->args[0], &mt);
  const Core *p;
  if (x == NULL)
    return NULL;
  if (!carrier_of(mt, &carrier, &a) || carrier == CARRIER_SUM)
    return nul(FAIL(c, "TYPE_MISMATCH", "filter needs a value of type Option A or List A, found a term of type %s", show(c, mt)));
  p = check(c, k->args[0], val_arrow(c->m, a, flag_type(c)));
  k->type = mt;
  return op3(c, OP_FILTER, carrier, 2, p, x, NULL);
}

/* fold step z n (Nat) or fold f z xs (List A). */
static const Core *fold_simple(Call *k, const Core *s, const Value *st) {
  Checker *c = k->c;
  const Value *res = k->hint;
  const Core *z = res != NULL ? check(c, k->args[1], res) : infer(c, k->args[1], &res);
  int list = val_is(st, OP_LIST);
  const Value *step = list ? val_arrow(c->m, st->args[0], val_arrow(c->m, res, res)) : val_arrow(c->m, res, res);
  const Core *f = z == NULL ? NULL : check(c, k->args[0], step);
  k->used = 3u;
  k->type = res;
  return op3(c, list ? OP_FOLD_LIST : OP_FOLD_NAT, 0, 3, f, z, s);
}

/* The type of the fold case of CTOR: one argument for each field (a
   recursive field arrives folded, so its type is RES), then RES. */
static const Value *case_type(Checker *c, const CtorInfo *ctor, const Env *env, const Value *res) {
  const Value *t = res;
  uint32_t i = ctor->field_count;
  while (i > 0u && t != NULL) {
    const FieldInfo *field = &ctor->fields[--i];
    t = val_arrow(c->m, field->recursive ? res : eval_core(c->m, env, field->type), t);
  }
  return t;
}

/* The Core of PathP (λ _ → LINE) X Y at level LVL (LINE is at LVL + 1). */
static const Core *path_core(Checker *c, uint32_t lvl, const Core *line, const Value *x, const Value *y) {
  const Core *cx = x == NULL ? NULL : quote_value(c->m, lvl, x);
  const Core *cy = y == NULL ? NULL : quote_value(c->m, lvl, y);
  return line == NULL || cx == NULL || cy == NULL ? NULL : op3(c, OP_PATHP, 0, 3, core_bind(c, CORE_LAM, "_", NULL, line), cx, cy);
}

/* T is the family FAM (at any arguments). */
static int is_family_core(const Core *t, uint32_t fam) {
  return t != NULL && t->kind == CORE_OP && t->op == OP_FAMILY && t->inst == fam;
}

/* The point term K through the fold cases (S3 D2, the zkpolicy-lang star):
   a field variable is itself (from ENV), and a point constructor of FAM
   applies its case in CASES to its fields (the parameters drop). */
static const Value *star(Checker *c, uint32_t fam, const Value *const *cases, const Env *env, const Core *k) {
  Machine *m = c->m;
  const FamilyInfo *f = &m->families[fam];
  const Value *acc;
  const Value *arg;
  uint32_t j;
  if (k->kind != CORE_OP || k->op != OP_CTOR || k->inst < f->first_ctor || k->inst >= f->first_ctor + f->ctor_count || m->ctors[k->inst].depth != 0u)
    return eval_core(m, env, k);
  acc = cases[k->inst - f->first_ctor];
  for (j = 0; j < m->ctors[k->inst].field_count && acc != NULL; j++) {
    arg = star(c, fam, cases, env, k->args[f->param_count + j]);
    acc = arg == NULL ? NULL : apply_value(m, acc, arg);
  }
  return acc;
}

static int family_has_path(const Machine *m, uint32_t fam);
static const Core *path_body(const Core *t);

/* The type of the fold case of CTOR over FAM, a family with a path
   constructor (S3 D2): a Pi over the fields into RES at depth 0, else
   Path RES a* b* (depth 1) or Path (Path RES x* y*) p* q* (depth 2), with
   the ends through the earlier CASES. A recursive field has the type RES;
   a path field u ≡ v in FAM has the type Path RES u* v*. A field type sees
   the earlier fields, so each field is a fresh variable in ENV. */
static const Value *hit_case_type(Checker *c, uint32_t fam, const CtorInfo *ctor, const Value *const *cases, const Env *env, const Value *res) {
  Machine *m = c->m;
  const Core **doms = arena_alloc(m->arena, ((size_t)ctor->field_count + 1u) * sizeof *doms);
  uint32_t n = ctor->field_count;
  uint32_t lvl = c->level + n;
  const Value *dom;
  const Core *line;
  const Core *k;
  uint32_t i;
  if (doms == NULL) {
    FAIL(c, "OOM", "out of memory");
    return NULL;
  }
  for (i = 0; i < n; i++) {
    const Core *t = ctor->fields[i].type;
    int path = !ctor->fields[i].recursive && is_family_core(path_body(t), fam);
    dom = ctor->fields[i].recursive ? res : path ? NULL : eval_core(m, env, t);
    doms[i] = path ? path_core(c, c->level + i, quote_value(m, c->level + i + 1u, res), star(c, fam, cases, env, t->args[1]), star(c, fam, cases, env, t->args[2]))
              : dom == NULL ? NULL : quote_value(m, c->level + i, dom);
    env = env_push(m, env, val_var(m, c->level + i));
    if (doms[i] == NULL || env == NULL)
      return NULL;
  }
  line = ctor->depth == 2u ? path_core(c, lvl + 1u, quote_value(m, lvl + 2u, res), star(c, fam, cases, env, ctor->ends[2]), star(c, fam, cases, env, ctor->ends[3])) : quote_value(m, lvl + 1u, res);
  k = ctor->depth == 0u ? quote_value(m, lvl, res) : path_core(c, lvl, line, star(c, fam, cases, env, ctor->ends[0]), star(c, fam, cases, env, ctor->ends[1]));
  for (i = n; i > 0u && k != NULL; i--)
    k = core_bind(c, CORE_PI, ctor->fields[i - 1u].name, doms[i - 1u], k);
  return here(c, k);
}

/* fold case... x over a domain family: one case for each constructor. */
static const Core *fold_family(Call *k, const Core *s, const Value *st) {
  Checker *c = k->c;
  Machine *m = c->m;
  const FamilyInfo *f = &m->families[st->inst];
  const Env *env = env_of(c, st->args, st->argc);
  const Value *res = k->hint;
  const Core **cores = arena_alloc(m->arena, ((size_t)f->ctor_count + 2u) * sizeof *cores);
  const Value **vals = arena_alloc(m->arena, ((size_t)f->ctor_count + 1u) * sizeof *vals);
  const Value *want;
  int hit = family_has_path(m, st->inst);
  uint32_t j;
  if (cores == NULL || vals == NULL)
    return nul(FAIL(c, "OOM", "out of memory"));
  if (res == NULL && m->ctors[f->first_ctor].field_count == 0u)
    cores[0] = infer(c, k->args[0], &res);
  if (res == NULL)
    return nul(FAIL(c, "TYPE_INFER", "fold over %s needs a declared result type here", f->name));
  /* S3 D2: a family with a path constructor gets the case types of
     hit_case_type, whose ends go through the earlier cases (VALS) */
  for (j = 0; j < f->ctor_count; j++) {
    want = hit ? hit_case_type(c, st->inst, &m->ctors[f->first_ctor + j], vals, env, res) : case_type(c, &m->ctors[f->first_ctor + j], env, res);
    cores[j] = cores[j] != NULL ? cores[j] : want == NULL ? NULL : check(c, k->args[j], want);
    vals[j] = cores[j] == NULL || !hit ? NULL : here(c, cores[j]);
    if (cores[j] == NULL || (hit && vals[j] == NULL))
      return NULL;
  }
  cores[f->ctor_count] = s;
  k->used = f->ctor_count + 1u;
  k->type = res;
  return core_op(c, OP_FOLD_FAMILY, st->inst, 0, cores, f->ctor_count + 1u);
}

static int simple_scrutinee(const Value *t) {
  return val_is(t, OP_NAT) || val_is(t, OP_LIST);
}

/* fold takes its scrutinee last, so the scrutinee type sets the arity. */
/* A family with a path constructor is a higher inductive family (D10). */
static int family_has_path(const Machine *m, uint32_t fam) {
  const FamilyInfo *f = &m->families[fam];
  uint32_t j;
  for (j = 0; j < f->ctor_count; j++)
    if (m->ctors[f->first_ctor + j].depth > 0u)
      return 1;
  return 0;
}

/* O72: a fold or a projection R of the sealed family FAM into a type
   that is not a sealed family opens the seal. */
static const Core *seal_open(Call *k, uint32_t fam, const Core *r) {
  const FamilyInfo *fs = k->c->m->families;
  Core *sealed;
  if (r == NULL || !fs[fam].sealed)
    return r;
  if (!(val_is(k->type, OP_FAMILY) && fs[k->type->inst].sealed)) {
    k->c->opens = 1;
    return r;
  }
  sealed = new_core(k->c, r->kind);
  if (sealed != NULL) {
    *sealed = *r;
    sealed->sealed_result = 1;
  }
  return sealed;
}

static const Core *rule_fold(Call *k) {
  Checker *c = k->c;
  const Value *st = NULL;
  const Core *s = try_infer(c, k->args[k->argc - 1u], &st);
  uint32_t fam = val_is(st, OP_FAMILY) ? st->inst : NO_FAMILY;
  if (s != NULL && fam != NO_FAMILY && c->m->families[fam].index_count > 0u)
    return nul(FAIL(c, "DOMAIN_FAMILY", "fold over %s is not in S2: a fold over an indexed family needs a dependent eliminator (S3)", c->m->families[fam].name));
  if (s != NULL && fam != NO_FAMILY && c->m->families[fam].ctor_count + 1u == k->argc) {
    k->hint = k->outer;
    return seal_open(k, fam, fold_family(k, s, st));
  }
  if (s != NULL && k->argc == 3u && simple_scrutinee(st)) {
    k->hint = k->outer;
    return fold_simple(k, s, st);
  }
  s = k->argc > 3u ? try_infer(c, k->args[2], &st) : NULL;
  if (s != NULL && simple_scrutinee(st)) {
    k->hint = NULL;
    return fold_simple(k, s, st);
  }
  s = infer(c, k->args[k->argc - 1u], &st);
  return s == NULL ? NULL : nul(FAIL(c, "TYPE_MISMATCH", "fold needs a last argument of type ℕ, List A or a domain family, and one case for each constructor; found %u arguments and a last argument of type %s", k->argc, show(c, st)));
}

/* The motive of elim over D: P : D → Type₁ (large elimination), else
   P : D → Type. A failed first try leaves no diagnostic. */
static const Core *motive_check(Checker *c, const Term *t, const Value *big, const Value *small) {
  Diag saved = *c->m->diag;
  const Term *at = c->at;
  const Env *env = c->env;
  const Core *p = check(c, t, big);
  if (p != NULL)
    return p;
  *c->m->diag = saved;
  c->at = at;
  c->env = env;
  return check(c, t, small);
}

static const Core *elim_motive(Checker *c, const Term *t, const Value *d) {
  return motive_check(c, t, val_arrow(c->m, d, val_univ(c->m, 1u)), val_arrow(c->m, d, val_univ(c->m, 0u)));
}

/* I₁ → … → Iₖ → Type at LVL over the index types of F (O70). F has no
   parameters, so the index types see no variable. */
static const Value *index_arrows(Checker *c, const FamilyInfo *f, uint32_t lvl) {
  const Value *t = val_univ(c->m, lvl);
  uint32_t j = f->index_count;
  while (j > 0u && t != NULL) {
    j--;
    t = val_arrow(c->m, eval_core(c->m, NULL, f->index_types[j]), t);
  }
  return t;
}

/* PV applied to the N index cores IX, each evaluated in ENV. */
static const Value *motive_at(Checker *c, const Value *pv, const Env *env, const Core *const *ix, uint32_t n) {
  uint32_t j;
  for (j = 0; j < n && pv != NULL; j++)
    pv = apply_value(c->m, pv, eval_core(c->m, env, ix[j]));
  return pv;
}

/* Whether T refers to the free variable INDEX, under any local binders. */
static int core_uses_var(const Core *t, uint32_t index) {
  uint32_t j;
  if (t == NULL)
    return 0;
  switch (t->kind) {
  case CORE_VAR:
    return t->index == index;
  case CORE_GLOBAL:
  case CORE_NAT:
  case CORE_TRAP:
  case CORE_UNIV:
    return 0;
  case CORE_LAM:
  case CORE_PI:
  case CORE_SIGMA:
    return core_uses_var(t->a, index) || core_uses_var(t->b, index + 1u);
  case CORE_APP:
    return core_uses_var(t->a, index) || core_uses_var(t->b, index);
  case CORE_OP:
    break;
  }
  for (j = 0; j < t->argc; j++)
    if (core_uses_var(t->args[j], index))
      return 1;
  return 0;
}

/* A fold replaces recursive fields with their results. Later types and
   result indices must not refer to the original recursive values. */
static int index_case_ok(Checker *c, const FamilyInfo *f, const CtorInfo *ctor) {
  const Env *env = NULL;
  const Core *t;
  uint32_t j;
  uint32_t i;
  for (i = 0; i < ctor->field_count; i++) {
    t = quote_value(c->m, c->level + i, eval_core(c->m, env, ctor->fields[i].type));
    if (t == NULL)
      return 0;
    for (j = 0; j < i; j++)
      if (ctor->fields[j].recursive && core_uses_var(t, i - j - 1u))
        return FAIL(c, "DOMAIN_FAMILY", "foldᴵ over %s cannot replace the recursive field %s of %s: the later field %s depends on its original value", f->name, ctor->fields[j].name, ctor->name, ctor->fields[i].name);
    env = env_push(c->m, env, val_var(c->m, c->level + i));
    if (env == NULL)
      return 0;
  }
  for (i = 0; i < f->index_count; i++) {
    t = quote_value(c->m, c->level + ctor->field_count, eval_core(c->m, env, ctor->indices[i]));
    if (t == NULL)
      return 0;
    for (j = 0; j < ctor->field_count; j++)
      if (ctor->fields[j].recursive && core_uses_var(t, ctor->field_count - j - 1u))
        return FAIL(c, "DOMAIN_FAMILY", "foldᴵ over %s cannot replace the recursive field %s of %s: a result index depends on its original value", f->name, ctor->fields[j].name, ctor->name);
  }
  return 1;
}

/* The type of the foldᴵ case of CTOR (O70): a Pi over the fields into PV
   at the result indices. A recursive field at the indices u has the type
   PV u. A field type sees the earlier fields, so each field is a fresh
   variable in ENV. */
static const Value *index_case_type(Checker *c, const FamilyInfo *f, const CtorInfo *ctor, const Value *pv) {
  Machine *m = c->m;
  const Core **doms = arena_alloc(m->arena, ((size_t)ctor->field_count + 1u) * sizeof *doms);
  const Env *env = NULL;
  uint32_t n = ctor->field_count;
  const Value *dom;
  const Core *k;
  uint32_t i;
  if (doms == NULL) {
    FAIL(c, "OOM", "out of memory");
    return NULL;
  }
  for (i = 0; i < n; i++) {
    const Core *t = ctor->fields[i].type;
    dom = ctor->fields[i].recursive ? motive_at(c, pv, env, t->args + f->param_count, f->index_count) : eval_core(m, env, t);
    doms[i] = dom == NULL ? NULL : quote_value(m, c->level + i, dom);
    env = env_push(m, env, val_var(m, c->level + i));
    if (doms[i] == NULL || env == NULL)
      return NULL;
  }
  dom = motive_at(c, pv, env, ctor->indices, f->index_count);
  k = dom == NULL ? NULL : quote_value(m, c->level + n, dom);
  for (i = n; i > 0u && k != NULL; i--)
    k = core_bind(c, CORE_PI, ctor->fields[i - 1u].name, doms[i - 1u], k);
  return here(c, k);
}

/* foldᴵ P c₁ … cₙ x over an indexed family with no parameters (O70). P
   is a motive over the indices only (not over x): P : I₁ → … → Iₖ → Type₁,
   else into Type. The result is P at the indices of x. The core drops P
   and is the family fold, so eval and lower are the ones of fold. */
static const Core *rule_foldi(Call *k) {
  Checker *c = k->c;
  Machine *m = c->m;
  const Value *st = NULL;
  const Core *s = infer(c, k->args[k->argc - 1u], &st);
  const FamilyInfo *f = s != NULL && val_is(st, OP_FAMILY) ? &m->families[st->inst] : NULL;
  const Core **cores;
  const Core *p;
  const Value *pv;
  uint32_t j;
  if (s == NULL)
    return NULL;
  if (f == NULL || f->index_count == 0u || f->param_count != 0u || f->ctor_count + 2u != k->argc)
    return nul(FAIL(c, "TYPE_MISMATCH", "foldᴵ needs a motive, one case for each constructor and a last argument in an indexed family with no parameters; found %u arguments and a last argument of type %s", k->argc, show(c, st)));
  cores = arena_alloc(m->arena, ((size_t)f->ctor_count + 2u) * sizeof *cores);
  if (cores == NULL)
    return nul(FAIL(c, "OOM", "out of memory"));
  p = motive_check(c, k->args[0], index_arrows(c, f, 1u), index_arrows(c, f, 0u));
  pv = p == NULL ? NULL : eval_core(m, c->env, p);
  if (pv == NULL)
    return NULL;
  for (j = 0; j < f->ctor_count; j++) {
    const CtorInfo *ctor = &m->ctors[f->first_ctor + j];
    const Value *want;
    if (!index_case_ok(c, f, ctor))
      return NULL;
    want = index_case_type(c, f, ctor, pv);
    cores[j] = want == NULL ? NULL : check(c, k->args[j + 1u], want);
    if (cores[j] == NULL)
      return NULL;
  }
  for (j = 0; j < f->index_count && pv != NULL; j++)
    pv = apply_value(m, pv, st->args[j]);
  cores[f->ctor_count] = s;
  k->used = f->ctor_count + 2u;
  k->type = pv;
  return pv == NULL ? NULL : core_op(c, OP_FOLD_FAMILY, st->inst, 0, cores, f->ctor_count + 1u);
}

/* (n : ℕ) → P n → P (suc n), with PV the value of the motive P. */
static const Value *elim_step(Checker *c, const Value *pv) {
  const Core *succ = op3(c, OP_NAT_ADD, 0, 2, core_index(c, CORE_VAR, 1u), core_leaf(c, CORE_NAT, 1u), NULL);
  const Core *ih = core_app(c, core_index(c, CORE_VAR, 1u), core_index(c, CORE_VAR, 0u));
  const Core *res = succ == NULL ? NULL : core_app(c, core_index(c, CORE_VAR, 2u), succ);
  const Core *body = ih == NULL || res == NULL ? NULL : core_bind(c, CORE_PI, "ih", ih, res);
  const Env *env = body == NULL ? NULL : env_push(c->m, NULL, pv);
  return env == NULL ? NULL : val_closure(c->m, VAL_PI, "n", nat_type(c), env, body);
}

/* elim P z s n (ℕ) or elim P yes no b (Bool): the dependent eliminator
   of closed data (S3 D1). The core drops P: an elim over ℕ is
   OP_ELIM_NAT z s n, an elim over Bool is flagIf b yes no. More
   arguments apply to the result. */
static const Core *rule_elim(Call *k) {
  Checker *c = k->c;
  Machine *m = c->m;
  const Value *d = NULL;
  const Core *x = infer(c, k->args[3], &d);
  const Core *p;
  const Value *pv;
  const Core *yes;
  const Core *no;
  int nat;
  if (x == NULL)
    return NULL;
  if (val_is(d, OP_FAMILY))
    return nul(FAIL(c, "DOMAIN_FAMILY", "elim over %s is not in S3: elim takes a ℕ or a Bool, and fold takes a domain family", m->families[d->inst].name));
  if (!val_is(d, OP_NAT) && !val_is(d, OP_FLAG))
    return nul(FAIL(c, "TYPE_MISMATCH", "elim needs a last argument of type ℕ or Bool, found a term of type %s", show(c, d)));
  nat = val_is(d, OP_NAT);
  p = elim_motive(c, k->args[0], d);
  pv = p == NULL ? NULL : eval_core(m, c->env, p);
  yes = pv == NULL ? NULL : check(c, k->args[1], apply_value(m, pv, nat ? val_nat(m, 0u) : tyop(c, OP_FLAG_YES, 0, NULL, NULL, NULL)));
  no = yes == NULL ? NULL : check(c, k->args[2], nat ? elim_step(c, pv) : apply_value(m, pv, tyop(c, OP_FLAG_NO, 0, NULL, NULL, NULL)));
  if (no == NULL)
    return NULL;
  k->used = 4u;
  k->type = apply_value(m, pv, eval_core(m, c->env, x));
  return nat ? op3(c, OP_ELIM_NAT, 0, 3, yes, no, x) : op3(c, OP_FLAG_IF, 0, 3, x, yes, no);
}

/* A Pi over DOM into BODY; NULL when one of them is NULL. */
static const Core *bag_pi(Checker *c, const char *name, const Core *dom, const Core *body) {
  return dom == NULL || body == NULL ? NULL : core_bind(c, CORE_PI, name, dom, body);
}

/* F X Y, or NULL. */
static const Value *bag_apply2(Machine *m, const Value *f, const Value *x, const Value *y) {
  const Value *fx = f == NULL || x == NULL || y == NULL ? NULL : apply_value(m, f, x);
  return fx == NULL ? NULL : apply_value(m, fx, y);
}

/* The swap obligation of foldᴮ, with FV the value of f:
   (x : A) → (y : A) → (b : B) → f x (f y b) ≡ f y (f x b). */
static const Value *bag_swap_type(Checker *c, const Value *a, const Value *res, const Value *fv) {
  Machine *m = c->m;
  uint32_t l = c->level;
  const Value *x = val_var(m, l);
  const Value *y = val_var(m, l + 1u);
  const Value *b = val_var(m, l + 2u);
  const Core *k = path_core(c, l + 3u, quote_value(m, l + 4u, res), bag_apply2(m, fv, x, bag_apply2(m, fv, y, b)), bag_apply2(m, fv, y, bag_apply2(m, fv, x, b)));
  k = bag_pi(c, "b", quote_value(m, l + 2u, res), k);
  k = bag_pi(c, "y", quote_value(m, l + 1u, a), k);
  return here(c, bag_pi(c, "x", quote_value(m, l, a), k));
}

/* isSet B, unfolded: (x : B) → (y : B) → (p : x ≡ y) → (q : x ≡ y) → p ≡ q. */
static const Value *bag_set_type(Checker *c, const Value *res) {
  Machine *m = c->m;
  uint32_t l = c->level;
  const Value *x = val_var(m, l);
  const Value *y = val_var(m, l + 1u);
  const Core *line = path_core(c, l + 5u, quote_value(m, l + 6u, res), x, y);
  const Core *k = path_core(c, l + 4u, line, val_var(m, l + 2u), val_var(m, l + 3u));
  k = bag_pi(c, "q", path_core(c, l + 3u, quote_value(m, l + 4u, res), x, y), k);
  k = bag_pi(c, "p", path_core(c, l + 2u, quote_value(m, l + 3u, res), x, y), k);
  k = bag_pi(c, "y", quote_value(m, l + 1u, res), k);
  return here(c, bag_pi(c, "x", quote_value(m, l, res), k));
}

/* The constructors of a bag (S3 D4), in order: the depth, the number of
   fields, and the ends as prefix patterns. In a pattern, a digit is a
   field, e is the empty bag and m is the union of the next two patterns. */
typedef struct {
  uint32_t depth;
  uint32_t fields;
  const char *ends[4];
} BagCtor;

static const BagCtor BAG_CTORS[] = {
  {0u, 1u, {NULL, NULL, NULL, NULL}},
  {0u, 0u, {NULL, NULL, NULL, NULL}},
  {0u, 2u, {NULL, NULL, NULL, NULL}},
  {1u, 1u, {"me0", "0", NULL, NULL}},
  {1u, 3u, {"mm012", "m0m12", NULL, NULL}},
  {1u, 2u, {"m01", "m10", NULL, NULL}},
  {2u, 4u, {"2", "3", "0", "1"}}
};

#define BAG_CTOR_COUNT ((uint32_t)(sizeof BAG_CTORS / sizeof BAG_CTORS[0]))

/* K matches the pattern at *S over the bag constructors from FIRST, with
   P params and then N fields in the context. *S moves past the pattern. */
static int bag_end(const Core *k, const char **s, uint32_t first, uint32_t p, uint32_t n) {
  char t = **s;
  uint32_t fields = t == 'm' ? 2u : 0u;
  (*s)++;
  if (t >= '0' && t <= '9')
    return k != NULL && k->kind == CORE_VAR && (uint32_t)(t - '0') < n && k->index == n - 1u - (uint32_t)(t - '0');
  if (k == NULL || k->kind != CORE_OP || k->op != OP_CTOR || k->inst != first + (t == 'm' ? 2u : 1u) || k->argc != p + fields)
    return 0;
  return t == 'e' || (bag_end(k->args[p], s, first, p, n) && bag_end(k->args[p + 1u], s, first, p, n));
}

/* K matches all of the pattern PAT. */
static int bag_match(const Core *k, const char *pat, uint32_t first, uint32_t p, uint32_t n) {
  const char *s = pat;
  return pat != NULL && bag_end(k, &s, first, p, n) && *s == '\0';
}

/* FAM is a bag (S3 D4): a cell monad with one type parameter A and the
   FMSet generator constructors in this order: η (one field of type A),
   e, m (two recursive fields), the 1-cells unit, assoc and comm over
   recursive fields, and the 2-cell set truncation. The ends are the
   ends of BAG_CTORS. */
static int bag_shaped(const Machine *m, uint32_t fam) {
  const FamilyInfo *f = &m->families[fam];
  const CtorInfo *ci;
  const Core *t;
  uint32_t j;
  uint32_t i;
  int ok = f->r1 == FAMILY_CM && f->param_count == 1u && f->index_count == 0u && f->ctor_count == BAG_CTOR_COUNT;
  for (j = 0; j < BAG_CTOR_COUNT && ok; j++) {
    ci = &m->ctors[f->first_ctor + j];
    ok = ci->depth == BAG_CTORS[j].depth && ci->field_count == BAG_CTORS[j].fields;
    for (i = 0; i < 2u * ci->depth && ok; i++)
      ok = ci->ends != NULL && bag_match(ci->ends[i], BAG_CTORS[j].ends[i], f->first_ctor, 1u, ci->field_count);
    for (i = 0; i < ci->field_count && ok; i++) {
      t = ci->fields[i].type;
      ok = j == 0u ? !ci->fields[i].recursive && t != NULL && t->kind == CORE_VAR && t->index == 0u
         : j == 6u && i >= 2u ? !ci->fields[i].recursive && t != NULL && t->kind == CORE_OP && t->op == OP_PATHP && t->argc == 3u && is_family_core(path_body(t), fam) && bag_match(t->args[1], "0", f->first_ctor, 1u, i) && bag_match(t->args[2], "1", f->first_ctor, 1u, i)
         : ci->fields[i].recursive;
    }
  }
  return ok;
}

/* foldᴮ f swap st b xs over a bag F A (S3 D4, O40), into B from the
   expected type, else from b: f : A → B → B, swap the swap obligation,
   st : isSet B, b : B. The core drops swap and st: OP_FOLD_BAG f b xs.
   More arguments apply to the result. */
static const Core *rule_foldb(Call *k) {
  Checker *c = k->c;
  Machine *m = c->m;
  const Value *st = NULL;
  const Core *xs = infer(c, k->args[4], &st);
  const Value *res = k->argc == 5u ? k->outer : NULL;
  const Core *b = NULL;
  const Core *f;
  const Core *sw;
  const Core *set;
  const Value *want;
  const Value *a;
  if (xs == NULL)
    return NULL;
  if (!val_is(st, OP_FAMILY) || !bag_shaped(m, st->inst))
    return nul(FAIL(c, "TYPE_BAG", "foldᴮ needs a bag: a cell monad with one type parameter and the constructors η, e, m, unit, assoc, comm and trunc in this order; found a last argument of type %s", show(c, st)));
  a = st->args[0];
  if (res == NULL)
    b = infer(c, k->args[3], &res);
  if (res == NULL)
    return NULL;
  f = check(c, k->args[0], val_arrow(m, a, val_arrow(m, res, res)));
  want = f == NULL ? NULL : bag_swap_type(c, a, res, here(c, f));
  sw = want == NULL ? NULL : check(c, k->args[1], want);
  want = sw == NULL ? NULL : bag_set_type(c, res);
  set = want == NULL ? NULL : check(c, k->args[2], want);
  b = set == NULL ? NULL : b != NULL ? b : check(c, k->args[3], res);
  if (b == NULL)
    return NULL;
  k->used = 5u;
  k->type = res;
  return op3(c, OP_FOLD_BAG, 0, 3, f, b, xs);
}

/* unfold g limit seed, with g : S → Maybe (A × S). S1 refuses unfold
   (REFUSE_CELL), so no BUILTINS row reaches this rule. */
static const Core *rule_unfold(Call *k) {
  Checker *c = k->c;
  const Value *st = NULL;
  const Value *a;
  const Core *seed;
  const Core *limit;
  const Core *g;
  if (!val_is(k->hint, OP_LIST))
    return need_type(k, "List A");
  a = k->hint->args[0];
  seed = infer(c, k->args[2], &st);
  limit = seed == NULL ? NULL : check(c, k->args[1], nat_type(c));
  g = limit == NULL ? NULL : check(c, k->args[0], val_arrow(c->m, st, tyop(c, OP_OPTION, 1, sigma_const(c, a, st), NULL, NULL)));
  k->type = k->hint;
  return op3(c, OP_UNFOLD, 0, 3, g, limit, seed);
}

static const Core *rule_nat2(Call *k) {
  Checker *c = k->c;
  const Core *x = check(c, k->args[0], nat_type(c));
  const Core *y = x == NULL ? NULL : check(c, k->args[1], nat_type(c));
  k->type = tyop(c, k->b->result, 0, NULL, NULL, NULL);
  return op3(c, k->b->op, 0, 2, x, y, NULL);
}

/* Family I is the word record NAME of domain/domain.lang (W4, W8, W12):
   one constructor of WORDS fields. */
static int is_word_record(const Machine *m, uint32_t i, const char *name, uint32_t words) {
  const FamilyInfo *f = &m->families[i];
  return strcmp(f->name, name) == 0 && f->param_count == 0u && f->index_count == 0u && f->ctor_count == 1u &&
         m->ctors[f->first_ctor].field_count == words;
}

/* The type NAME. A domain without it refuses a host call. */
static const Value *word_record(Checker *c, const char *name, uint32_t words) {
  uint32_t i;
  for (i = 0; i < c->m->family_count; i++) {
    if (is_word_record(c->m, i, name, words))
      return val_make(c->m, OP_FAMILY, i, 0, NULL, NULL, NULL);
  }
  FAIL(c, "DOMAIN_FAMILY",
       "a host call needs its word records (`data W4`, `data W8`, `data W12`, `data W16`, `data DecPart`, `data BitProof`: one constructor of ℕ fields) in "
       "domain/domain.lang");
  return NULL;
}

/* The list NAME (R-E4): CTORS constructors, no parameter or index. A
   domain without it refuses a host call. */
static const Value *list_family(Checker *c, const char *name, uint32_t ctors) {
  uint32_t i;
  for (i = 0; i < c->m->family_count; i++) {
    const FamilyInfo *f = &c->m->families[i];
    if (strcmp(f->name, name) == 0 && f->param_count == 0u && f->index_count == 0u && f->ctor_count == ctors)
      return val_make(c->m, OP_FAMILY, i, 0, NULL, NULL, NULL);
  }
  FAIL(c, "DOMAIN_FAMILY", "a host call needs its lists (`data Parts`, `data KeyList`, `data Prods`) in domain/domain.lang");
  return NULL;
}

/* The argument types of the host import PART in T, then the result type
   at T[*N] (R-E2). 0 when the domain has no record or list for it. */
static int host_types(Checker *c, uint32_t part, const Value **t, uint32_t *n) {
  const Value *nat = nat_type(c);
  const Value *w4 = word_record(c, "W4", 4u);
  const Value *w16 = w4 == NULL || part < 2u ? NULL : word_record(c, "W16", 16u);
  if (w4 == NULL || (part >= 2u && w16 == NULL))
    return 0;
  if (part == 0u) {
    t[0] = w4;
    t[1] = w4;
    t[2] = w4;
    *n = 2u;
    return 1;
  }
  if (part == 1u) {
    t[0] = word_record(c, "W8", 8u);
    t[1] = t[0] == NULL ? NULL : word_record(c, "W12", 12u);
    t[2] = w4;
    t[3] = nat;
    *n = 3u;
    return t[1] != NULL;
  }
  if (part == 3u) {
    t[0] = w16;
    t[1] = w16;
    t[2] = nat;
    t[3] = w16;
    *n = 3u;
    return 1;
  }
  if (part == 5u) {
    t[0] = list_family(c, "Parts", 2u);
    t[2] = t[0] == NULL ? NULL : list_family(c, "KeyList", 2u);
    t[1] = nat;
    t[3] = nat;
    t[4] = nat;
    t[5] = w16;
    t[6] = nat;
    t[7] = w4;
    *n = 7u;
    return t[2] != NULL;
  }
  if (part == 6u || part == 11u) {
    t[0] = w16;
    t[1] = w16;
    t[2] = nat;
    t[3] = part == 6u ? nat : word_record(c, "W8", 8u);
    *n = 3u;
    return t[3] != NULL;
  }
  if (part == 7u) {
    t[0] = w16;
    t[1] = w16;
    t[2] = w16;
    *n = 2u;
    return 1;
  }
  if (part == 8u) {
    t[0] = w16;
    t[1] = w4;
    t[2] = w4;
    t[3] = w16;
    *n = 3u;
    return 1;
  }
  if (part == 9u || part == 10u) {
    t[0] = list_family(c, "Prods", 2u);
    t[1] = t[0];
    t[2] = t[0];
    t[3] = nat;
    t[4] = w16;
    t[5] = w16;
    t[6] = w16;
    *n = part == 9u ? 6u : 4u;
    return t[0] != NULL;
  }
  t[0] = part == 2u ? word_record(c, "BitProof", 48u) : word_record(c, "DecPart", 29u);
  t[1] = t[0] == NULL ? NULL : word_record(c, "W8", 8u);
  t[2] = w16;
  t[3] = part == 2u ? w4 : nat;
  t[4] = nat;
  t[5] = nat;
  *n = part == 2u ? 5u : 3u;
  return t[1] != NULL;
}

/* A host import (O105). q_hash2 (import 0) : W4 → W4 → W4.
   q_frost_verify (import 1) : W8 → W12 → W4 → ℕ, the FrostResult code
   (R-C1). H5a (R-E2): q_ballot_verify (2) : BitProof → W8 → W16 → W4 → ℕ
   → ℕ, the SigResult code; q_tally_add (3) : W16 → W16 → ℕ → W16;
   q_partial_verify (4) : DecPart → W8 → W16 → ℕ (0 when the part
   verifies, else 1); q_combine (5) : Parts → ℕ → KeyList → ℕ → ℕ → W16 →
   ℕ → W4 (m, the ThrResult code, 0, 0). S10 H3 (the BGW route, bgw.h):
   q_mpc_check (6) : W16 → W16 → ℕ → ℕ, the BgwResult code; q_mpc_add (7)
   : W16 → W16 → W16; q_mpc_affine (8) : W16 → W4 → W4 → W16; q_mpc_mul
   (9) : Prods → Prods → Prods → ℕ → W16 → W16 → W16 (the new shares, the
   code in word 12); q_mpc_mulc (10) : Prods → Prods → Prods → ℕ → W16;
   q_mpc_open (11) : W16 → W16 → ℕ → W8 (the value, then the code). The
   node has one child for each argument (core_op, R-E23). The checker
   treats the call as opaque. langc eval and the Wasm host call the same C
   function. */
static const Core *rule_host(Call *k) {
  Checker *c = k->c;
  const Value *t[8];
  const Core *x[7];
  uint32_t n = 0;
  uint32_t i;
  if (!host_types(c, k->b->part, t, &n))
    return NULL;
  for (i = 0; i < n; i++) {
    x[i] = check(c, k->args[i], t[i]);
    if (x[i] == NULL)
      return NULL;
  }
  k->type = t[n];
  return core_op(c, k->b->op, k->b->part, 0, x, n);

}

/* suc n: natAdd n 1 */
static const Core *rule_suc(Call *k) {
  Checker *c = k->c;
  const Core *x = check(c, k->args[0], nat_type(c));
  const Core *one = x == NULL ? NULL : core_leaf(c, CORE_NAT, 1u);
  k->type = tyop(c, k->b->result, 0, NULL, NULL, NULL);
  return op3(c, k->b->op, 0, 2, x, one, NULL);
}

/* flagIf b yes no */
static const Core *rule_flag_if(Call *k) {
  Checker *c = k->c;
  const Value *res = k->hint;
  const Core *b = check(c, k->args[0], flag_type(c));
  const Core *yes = b == NULL ? NULL : (res != NULL ? check(c, k->args[1], res) : infer(c, k->args[1], &res));
  const Core *no = yes == NULL ? NULL : check(c, k->args[2], res);
  k->type = res;
  return op3(c, OP_FLAG_IF, 0, 3, b, yes, no);
}

static const Core *rule(Call *k) {
  switch (k->b->rule) {
  case RULE_TYPE0:
    k->type = val_univ(k->c->m, 0);
    return op3(k->c, k->b->op, 0, 0, NULL, NULL, NULL);
  case RULE_VALUE0:
    k->type = tyop(k->c, k->b->result, 0, NULL, NULL, NULL);
    return op3(k->c, k->b->op, 0, 0, NULL, NULL, NULL);
  case RULE_TYPE1:
    return rule_type1(k);
  case RULE_TYPE2:
    return rule_type2(k);
  case RULE_PAIR:
    return rule_pair(k);
  case RULE_INJ:
    return rule_inj(k);
  case RULE_EMPTY:
    return rule_empty(k);
  case RULE_SOME:
    return rule_some(k);
  case RULE_CONS:
    return rule_cons(k);
  case RULE_REFL:
    return rule_refl(k);
  case RULE_SIGMA_PART:
    return rule_sigma_part(k);
  case RULE_TIMES:
    return rule_times(k);
  case RULE_LEVEL:
    return rule_level(k);
  case RULE_EITHER:
    return rule_either(k);
  case RULE_OPTION:
    return rule_option(k);
  case RULE_PURE:
    return rule_pure(k);
  case RULE_MAP:
    return rule_map(k);
  case RULE_BIND:
    return rule_bind(k);
  case RULE_FILTER:
    return rule_filter(k);
  case RULE_FOLD:
    return rule_fold(k);
  case RULE_ELIM:
    return rule_elim(k);
  case RULE_FOLDB:
    return rule_foldb(k);
  case RULE_FOLDI:
    return rule_foldi(k);
  case RULE_UNFOLD:
    return rule_unfold(k);
  case RULE_NAT2:
    return rule_nat2(k);
  case RULE_SUC:
    return rule_suc(k);
  case RULE_FLAG_IF:
    return rule_flag_if(k);
  case RULE_INTERVAL:
    return rule_interval(k);
  case RULE_IOP:
    return rule_iop(k);
  case RULE_PATHP:
    return rule_pathp(k);
  case RULE_PATH_EQ:
    return rule_path_eq(k);
  case RULE_TRANSP:
    return rule_transp(k);
  case RULE_HCOMP:
    return rule_hcomp(k);
  case RULE_HOST:
    return rule_host(k);
  }
  return NULL;
}

/* Checks the family parameters ARGS. VALS gets their values. */
/* The fields of an indexed family are a telescope: a field type sees the
   earlier fields, and the result indices see all of them. A cell monad
   keeps fields in the context of its parameters only. */
static int telescope(const FamilyInfo *f) {
  return f->index_count > 0u && f->r1 != FAMILY_CM;
}

static int check_params(Checker *c, const FamilyInfo *f, const Term *const *args, const Core **cores, const Value **vals) {
  uint32_t i;
  for (i = 0; i < f->param_count; i++) {
    cores[i] = check(c, args[i], eval_core(c->m, env_of(c, vals, i), f->param_types[i]));
    vals[i] = here(c, cores[i]);
    if (vals[i] == NULL)
      return 0;
  }
  return 1;
}

static const Core *family_app(Call *k, uint32_t fam) {
  Checker *c = k->c;
  const FamilyInfo *f = &c->m->families[fam];
  uint32_t p = f->param_count;
  const Core **cores = arena_alloc(c->m->arena, ((size_t)p + f->index_count + 1u) * sizeof *cores);
  const Value **vals = arena_alloc(c->m->arena, ((size_t)p + 1u) * sizeof *vals);
  uint32_t j;
  if (cores == NULL || vals == NULL)
    return nul(FAIL(c, "OOM", "out of memory"));
  if (!check_params(c, f, k->args, cores, vals))
    return NULL;
  for (j = 0; j < f->index_count; j++) {
    cores[p + j] = check(c, k->args[p + j], eval_core(c->m, env_of(c, vals, p), f->index_types[j]));
    if (cores[p + j] == NULL)
      return NULL;
  }
  k->type = val_univ(c->m, f->universe);
  return core_op(c, OP_FAMILY, fam, 0, cores, p + f->index_count);
}

/* A constructor takes the family parameters, then its fields. Its type is
   the family at the parameters and at its result indices. */
/* A path constructor applied to its params and fields is a path
   abstraction over OP_PCTOR: one OP_PLAM for each dimension (D10). */
static const Core *pctor_app(Call *k, uint32_t ctor, const Value *const *vals, uint32_t n) {
  Checker *c = k->c;
  const CtorInfo *ci = &c->m->ctors[ctor];
  uint32_t d = ci->depth;
  const Core **args = arena_alloc(c->m->arena, ((size_t)n + d + 1u) * sizeof *args);
  const Core *body;
  uint32_t i;
  if (args == NULL)
    return nul(FAIL(c, "OOM", "out of memory"));
  for (i = 0; i < n; i++)
    args[i] = quote_value(c->m, c->level + d, vals[i]);
  for (i = 0; i < d; i++)
    args[n + i] = core_index(c, CORE_VAR, d - 1u - i);
  k->type = eval_core(c->m, env_of(c, vals, n), ci->type);
  body = core_op(c, OP_PCTOR, ctor, 0, args, n + d);
  for (i = 0; i < d; i++)
    body = op3(c, OP_PLAM, 0, 1, core_bind(c, CORE_LAM, i == 0u && d == 2u ? "j" : "i", NULL, body), NULL, NULL);
  return body;
}

static const Core *ctor_app(Call *k, uint32_t ctor) {
  Checker *c = k->c;
  const CtorInfo *ci = &c->m->ctors[ctor];
  const FamilyInfo *f = &c->m->families[ci->family];
  uint32_t p = f->param_count;
  uint32_t n = p + ci->field_count;
  int dep = telescope(f) || ci->depth > 0u;
  const Core **cores = arena_alloc(c->m->arena, ((size_t)n + 1u) * sizeof *cores);
  const Value **vals = arena_alloc(c->m->arena, ((size_t)n + 1u) * sizeof *vals);
  const Value **tvals = arena_alloc(c->m->arena, ((size_t)p + f->index_count + 1u) * sizeof *tvals);
  uint32_t j;
  if (cores == NULL || vals == NULL || tvals == NULL)
    return nul(FAIL(c, "OOM", "out of memory"));
  if (!check_params(c, f, k->args, cores, vals))
    return NULL;
  for (j = 0; j < ci->field_count; j++) {
    cores[p + j] = check(c, k->args[p + j], eval_core(c->m, env_of(c, vals, dep ? p + j : p), ci->fields[j].type));
    if (cores[p + j] == NULL)
      return NULL;
    vals[p + j] = dep ? here(c, cores[p + j]) : NULL;
  }
  for (j = 0; j < p + f->index_count; j++)
    tvals[j] = j < p ? vals[j] : eval_core(c->m, env_of(c, vals, dep ? n : p), ci->indices[j - p]);
  if (ci->depth > 0u)
    return pctor_app(k, ctor, vals, n);
  k->type = val_op(c->m, VAL_OP, OP_FAMILY, ci->family, 0, tvals, p + f->index_count);
  return core_op(c, OP_CTOR, ctor, 0, cores, n);
}

/* A field of a one-constructor family is a projection. */
static const Core *proj_app(Call *k, uint32_t ctor, uint32_t field) {
  Checker *c = k->c;
  const CtorInfo *ci = &c->m->ctors[ctor];
  const FamilyInfo *f = &c->m->families[ci->family];
  uint32_t p = f->param_count;
  uint32_t n = telescope(f) ? p + field : p;
  const Value **vals = arena_alloc(c->m->arena, ((size_t)n + 1u) * sizeof *vals);
  const Value *xt = NULL;
  const Core *x = infer(c, k->args[0], &xt);
  uint32_t e;
  if (x == NULL)
    return NULL;
  if (!val_is(xt, OP_FAMILY) || xt->inst != ci->family)
    return nul(FAIL(c, "TYPE_MISMATCH", "%s needs a value of the family %s, found a term of type %s", ci->fields[field].name, c->m->families[ci->family].name, show(c, xt)));
  if (vals == NULL)
    return nul(FAIL(c, "OOM", "out of memory"));
  for (e = 0; e < n; e++)
    vals[e] = e < p ? xt->args[e] : here(c, core_op(c, OP_PROJ, ctor, e - p, &x, 1));
  k->type = eval_core(c->m, env_of(c, vals, n), ci->fields[field].type);
  return seal_open(k, ci->family, core_op(c, OP_PROJ, ctor, field, &x, 1));
}

static int find_known(Checker *c, const char *name, Head *h) {
  const Machine *m = c->m;
  uint32_t i;
  uint32_t j;
  for (i = 0; i < m->family_count; i++) {
    if (strcmp(m->families[i].name, name) == 0) {
      h->kind = HEAD_FAMILY;
      h->index = i;
      c->self_uses += i == c->self;
      return 1;
    }
  }
  for (i = 0; i < m->ctor_count; i++) {
    if (strcmp(m->ctors[i].name, name) == 0) {
      h->kind = HEAD_CTOR;
      h->index = i;
      return 1;
    }
  }
  for (i = 0; i < m->ctor_count; i++) {
    for (j = 0; m->families[m->ctors[i].family].ctor_count == 1u && j < m->ctors[i].field_count; j++) {
      if (strcmp(m->ctors[i].fields[j].name, name) == 0) {
        h->kind = HEAD_PROJ;
        h->index = i;
        h->field = j;
        return 1;
      }
    }
  }
  for (i = 0; i < BUILTIN_COUNT; i++) {
    if (strcmp(BUILTINS[i].name, name) == 0) {
      h->kind = HEAD_BUILTIN;
      h->builtin = &BUILTINS[i];
      return 1;
    }
  }
  return 0;
}

/* NAME_UNKNOWN, or the refusal when S1 took NAME out of the core. */
static int no_name(Checker *c, const char *name) {
  const Refused *r = refused(name);
  return r != NULL ? FAIL_NAME(c, name, r->code, "%s", r->why) : FAIL_NAME(c, name, "NAME_UNKNOWN", "unknown name %s", name);
}

/* An unknown name. When it names this declaration or a later one, the use
   is recursion (rule R3). */
static int unknown_name(Checker *c, const char *name) {
  size_t i;
  for (i = c->decl_index; i < c->decls->count; i++) {
    if (strcmp(c->decls->items[i].name, name) == 0)
      return FAIL_NAME(c, name, "REFUSE_REC", "%s is this definition or a later one; a definition can use only earlier ones (rule R3)", name);
  }
  return no_name(c, name);
}

/* Name resolution order: locals (the innermost first), definitions,
   families, constructors, projections, core names. */
static int resolve_head(Checker *c, const Term *head, Head *h) {
  memset(h, 0, sizeof *h);
  h->kind = HEAD_TERM;
  if (head->kind != TERM_VAR || find_local(c, head->name) != NULL || find_def(c->m, head->name) != NO_DEF)
    return 1;
  return find_known(c, head->name, h) ? 1 : unknown_name(c, head->name);
}

static uint32_t known_arity(const Checker *c, const Head *h) {
  const CtorInfo *ci = h->kind == HEAD_CTOR ? &c->m->ctors[h->index] : NULL;
  switch (h->kind) {
  case HEAD_TERM:
    return 0u;
  case HEAD_FAMILY:
    return c->m->families[h->index].param_count + c->m->families[h->index].index_count;
  case HEAD_CTOR:
    return ci == NULL ? 0u : c->m->families[ci->family].param_count + ci->field_count;
  case HEAD_PROJ:
    return 1u;
  case HEAD_BUILTIN:
    return h->builtin->arity;
  }
  return 0u;
}

static const char *known_name(const Checker *c, const Head *h) {
  switch (h->kind) {
  case HEAD_TERM:
    return "?";
  case HEAD_FAMILY:
    return c->m->families[h->index].name;
  case HEAD_CTOR:
    return c->m->ctors[h->index].name;
  case HEAD_PROJ:
    return c->m->ctors[h->index].fields[h->field].name;
  case HEAD_BUILTIN:
    return h->builtin->name;
  }
  return "?";
}

static const Core *known_core(Call *k, const Head *h) {
  switch (h->kind) {
  case HEAD_TERM:
    return nul(FAIL(k->c, "INTERNAL", "a plain term reached the core name rules"));
  case HEAD_FAMILY:
    return family_app(k, h->index);
  case HEAD_CTOR:
    return ctor_app(k, h->index);
  case HEAD_PROJ:
    return proj_app(k, h->index, h->field);
  case HEAD_BUILTIN:
    return rule(k);
  }
  return NULL;
}

/* An under-applied core name checked against a function type: WHOLE becomes
   `fun x => WHOLE x`, with a name that the lexer cannot make. */
static const Core *eta(Checker *c, const Term *whole, const Value *hint, const Value **type) {
  char *name = arena_alloc(c->m->arena, 24);
  Term *x = arena_alloc(c->m->arena, sizeof *x);
  Term *app = arena_alloc(c->m->arena, sizeof *app);
  Term *lam = arena_alloc(c->m->arena, sizeof *lam);
  if (name == NULL || x == NULL || app == NULL || lam == NULL)
    return nul(FAIL(c, "OOM", "out of memory"));
  c->eta_count++;
  snprintf(name, 24, "%%eta%u", c->eta_count);
  x->kind = TERM_VAR;
  x->name = name;
  app->kind = TERM_APP;
  app->left = whole;
  app->right = x;
  lam->kind = TERM_LAM;
  lam->name = name;
  lam->right = app;
  return check_lam(c, lam, hint, type);
}

/* F of type *TY applied to ARG. *TY becomes the type of the result. */
static const Core *fn_app(Checker *c, const Core *f, const Value **ty, const Term *arg) {
  const Value *fn = *ty;
  const Core *a;
  if (fn == NULL || fn->kind != VAL_PI)
    return nul(FAIL(c, "TYPE_NOT_FUNCTION", "a term of type %s is applied to an argument", show(c, fn)));
  a = check(c, arg, fn->dom);
  *ty = closure_apply(c->m, fn, here(c, a));
  return core_app(c, f, a);
}

/* Quoted path endpoints can contain sealed eliminations from the declared
   type, even when the proof body is just refl or a local variable. */
static int sealed_endpoint(const Machine *m, const Core *t) {
  uint32_t j;
  if (t == NULL || t->sealed_result)
    return 0;
  switch (t->kind) {
  case CORE_GLOBAL:
    return m->defs[t->index].law_only;
  case CORE_VAR:
  case CORE_NAT:
  case CORE_TRAP:
  case CORE_UNIV:
    return 0;
  case CORE_LAM:
  case CORE_PI:
  case CORE_SIGMA:
  case CORE_APP:
    return sealed_endpoint(m, t->a) || sealed_endpoint(m, t->b);
  case CORE_OP:
    break;
  }
  if ((t->op == OP_FOLD_FAMILY && m->families[t->inst].sealed) ||
      (t->op == OP_PROJ && m->families[m->ctors[t->inst].family].sealed))
    return 1;
  for (j = 0; j < t->argc; j++)
    if (sealed_endpoint(m, t->args[j]))
      return 1;
  return 0;
}

/* The path P of type *TY = PathP L a b at the point ARG of I (former C2).
   The core keeps the ends a and b, so p i0 and p i1 reduce. */
static const Core *path_app(Checker *c, const Core *p, const Value **ty, const Term *arg) {
  const Value *path = *ty;
  const Core *r = check(c, arg, interval_type(c));
  const Core *args[4];
  if (r == NULL)
    return NULL;
  args[0] = p;
  args[1] = r;
  args[2] = quote_value(c->m, c->level, path->args[1]);
  args[3] = quote_value(c->m, c->level, path->args[2]);
  *ty = apply_value(c->m, path->args[0], here(c, r));
  if (!(val_is(*ty, OP_FAMILY) && c->m->families[(*ty)->inst].sealed) &&
      (sealed_endpoint(c->m, args[2]) || sealed_endpoint(c->m, args[3])))
    c->opens = 1;
  return core_op(c, OP_PAPP, 0, 0, args, 4);
}

/* Applies K of type TY to ARGS, one by one. */
static const Core *apply_rest(Checker *c, const Core *k, const Value *ty, const Term *const *args, uint32_t argc, const Value *hint, const Value **type) {
  uint32_t i;
  for (i = 0; i < argc && k != NULL; i++)
    k = val_is(ty, OP_PATHP) ? path_app(c, k, &ty, args[i]) : fn_app(c, k, &ty, args[i]);
  *type = ty;
  return finish(c, k, hint, type);
}

static const Core *var_core(Checker *c, const char *name, const Value **type) {
  const Scope *s = find_local(c, name);
  uint32_t d = find_def(c->m, name);
  if (s != NULL) {
    *type = s->type;
    return core_index(c, CORE_VAR, c->level - 1u - s->level);
  }
  if (d != NO_DEF) {
    *type = c->m->defs[d].type;
    c->opens |= c->m->defs[d].law_only;
    return core_index(c, CORE_GLOBAL, d);
  }
  return nul(no_name(c, name));
}

static const Core *apply_term(Checker *c, const Term *head, const Term *const *args, uint32_t argc, const Value *hint, const Value **type) {
  const Value *ty = NULL;
  const Core *k = head->kind == TERM_VAR ? var_core(c, head->name, &ty) : infer(c, head, &ty);
  return apply_rest(c, k, ty, args, argc, hint, type);
}

static const Core *apply_known(Checker *c, const Term *whole, const Head *h, const Term *const *args, uint32_t argc, const Value *hint, const Value **type) {
  uint32_t arity = known_arity(c, h);
  Call k;
  const Core *core;
  if (argc < arity && hint != NULL && hint->kind == VAL_PI)
    return eta(c, whole, hint, type);
  if (argc < arity)
    return nul(FAIL(c, "TYPE_ARITY", "%s needs %u arguments, found %u", known_name(c, h), arity, argc));
  memset(&k, 0, sizeof k);
  k.c = c;
  k.b = h->builtin;
  k.args = args;
  k.argc = argc;
  k.hint = argc == arity ? hint : NULL;
  k.outer = hint;
  k.used = arity;
  core = known_core(&k, h);
  return apply_rest(c, core, k.type, args + k.used, argc - k.used, hint, type);
}

static const Core *elab_spine(Checker *c, const Term *t, const Value *hint, const Value **type) {
  const Term **args;
  const Term *head = t;
  uint32_t argc = 0;
  uint32_t i;
  Head h;
  while (head->kind == TERM_APP) {
    argc++;
    head = head->left;
  }
  if (argc > SPINE_MAX)
    return nul(FAIL(c, "TYPE_ARITY", "an application has more than %u arguments", SPINE_MAX));
  args = arena_alloc(c->m->arena, ((size_t)argc + 1u) * sizeof *args);
  if (args == NULL)
    return nul(FAIL(c, "OOM", "out of memory"));
  for (head = t, i = argc; head->kind == TERM_APP; head = head->left)
    args[--i] = head->right;
  if (!resolve_head(c, head, &h))
    return NULL;
  return h.kind == HEAD_TERM ? apply_term(c, head, args, argc, hint, type) : apply_known(c, t, &h, args, argc, hint, type);
}

static int annotation_ok(Checker *c, const Term *ann, const Value *dom) {
  uint64_t level = 0;
  const Value *v = here(c, type_term(c, ann, 1, &level));
  if (v == NULL)
    return 0;
  return conv_values(c->m, c->level, v, dom) ? 1 : FAIL(c, "TYPE_MISMATCH", "the binder type %s differs from the expected type %s", show(c, v), show(c, dom));
}

/* 1 when the path FN at END is WANT, the end that its type needs. */
static int path_end(Checker *c, const Value *fn, Op end, const Value *want) {
  const Value *got = apply_value(c->m, fn, tyop(c, end, 0, NULL, NULL, NULL));
  if (conv_on(c, c->level, got, want))
    return 1;
  return FAIL(c, "TYPE_ENDPOINT", "the path at %s is %s, but its type needs %s", end == OP_I0 ? "i0" : "i1", show(c, got), show(c, want));
}

/* λ i → t against PathP L a b (former C2): t : L i, and t at i0 and at i1
   are a and b (TYPE_ENDPOINT). */
static const Core *check_plam(Checker *c, const Term *t, const Value *hint, const Value **type) {
  const Value *i = interval_type(c);
  const Core *body;
  const Core *lam;
  const Value *fn;
  if (t->left != NULL && !annotation_ok(c, t->left, i))
    return NULL;
  if (!push(c, t->name, i))
    return NULL;
  body = check(c, t->right, apply_value(c->m, hint->args[0], c->env->value));
  pop(c);
  lam = core_bind(c, CORE_LAM, t->name, NULL, body);
  fn = here(c, lam);
  if (fn == NULL || !path_end(c, fn, OP_I0, hint->args[1]) || !path_end(c, fn, OP_I1, hint->args[2]))
    return NULL;
  *type = hint;
  return op3(c, OP_PLAM, 0, 1, lam, NULL, NULL);
}

static const Core *check_lam(Checker *c, const Term *t, const Value *hint, const Value **type) {
  const Core *body;
  if (val_is(hint, OP_PATHP))
    return check_plam(c, t, hint, type);
  if (hint->kind != VAL_PI)
    return nul(FAIL(c, "TYPE_MISMATCH", "a function is not a term of type %s", show(c, hint)));
  if (t->left != NULL && !annotation_ok(c, t->left, hint->dom))
    return NULL;
  if (!push(c, t->name, hint->dom))
    return NULL;
  body = check(c, t->right, closure_apply(c->m, hint, c->env->value));
  pop(c);
  *type = hint;
  return core_bind(c, CORE_LAM, t->name, NULL, body);
}

static const Core *infer_lam(Checker *c, const Term *t, const Value **type) {
  uint64_t level = 0;
  const Value *dom;
  const Value *bt = NULL;
  const Core *body;
  const Core *quoted;
  if (t->left == NULL)
    return nul(FAIL(c, "TYPE_INFER", "λ %s → ... needs a binder type here", t->name));
  dom = here(c, type_term(c, t->left, 1, &level));
  if (!push(c, t->name, dom))
    return NULL;
  body = infer(c, t->right, &bt);
  quoted = body == NULL ? NULL : quote_value(c->m, c->level, bt);
  pop(c);
  *type = val_closure(c->m, VAL_PI, t->name, dom, c->env, quoted);
  return core_bind(c, CORE_LAM, t->name, NULL, body);
}

/* (x : A) -> B and Sigma (x : A) B. */
static const Core *elab_binder(Checker *c, const Term *t, CoreKind kind, const Value *hint, const Value **type) {
  uint64_t la = 0;
  uint64_t lb = 0;
  const Core *a = check_type(c, t->left, &la);
  const Core *b;
  if (a == NULL || !push(c, t->name, here(c, a)))
    return NULL;
  b = check_type(c, t->right, &lb);
  pop(c);
  *type = val_univ(c->m, la > lb ? la : lb);
  return finish(c, core_bind(c, kind, t->name, a, b), hint, type);
}

/* `let x = t in u` (A1, D4). x is a defined local. The core is the
   β-redex `(λ x → u) t`, so eval and lower need no new case. */
static const Core *elab_let(Checker *c, const Term *t, const Value *hint, const Value **type) {
  const Value *a = NULL;
  const Core *bound = infer(c, t->left, &a);
  const Core *body;
  if (bound == NULL || !push_value(c, t->name, a, here(c, bound)))
    return NULL;
  body = hint != NULL ? check(c, t->right, hint) : infer(c, t->right, type);
  pop(c);
  *type = hint != NULL ? hint : *type;
  return body == NULL ? NULL : core_app(c, core_bind(c, CORE_LAM, t->name, NULL, body), bound);
}

static const Core *elab_inner(Checker *c, const Term *t, const Value *hint, const Value **type) {
  switch (t->kind) {
  case TERM_VAR:
  case TERM_APP:
    return elab_spine(c, t, hint, type);
  case TERM_NAT:
    *type = nat_type(c);
    return finish(c, core_leaf(c, CORE_NAT, t->nat), hint, type);
  case TERM_LAM:
    return hint != NULL ? check_lam(c, t, hint, type) : infer_lam(c, t, type);
  case TERM_PI:
    return elab_binder(c, t, CORE_PI, hint, type);
  case TERM_SIGMA:
    return elab_binder(c, t, CORE_SIGMA, hint, type);
  case TERM_LET:
    return elab_let(c, t, hint, type);
  case TERM_SYSTEM:
    return nul(FAIL(c, "TYPE_SYSTEM", "a system `λ { ... }` is legal only in the side `λ j → λ { ... }` of primHComp"));
  case TERM_UNIV:
    if (t->right != NULL) return univ_level(c, t, hint, type);
    if (t->nat >= UNIVERSE_MAX)
      return nul(FAIL(c, "TYPE_UNIVERSE", "the universe level %llu is above the largest level %u", (unsigned long long)t->nat, UNIVERSE_MAX - 1u));
    *type = val_univ(c->m, t->nat + 1u);
    return finish(c, core_leaf(c, CORE_UNIV, t->nat), hint, type);
  }
  return NULL;
}

static const Core *elab(Checker *c, const Term *t, const Value *hint, const Value **type) {
  const Core *k;
  if (c->depth >= CHECK_DEPTH_LIMIT)
    return nul(FAIL(c, "CHECK_DEPTH", "the term is nested deeper than %u levels", CHECK_DEPTH_LIMIT));
  c->depth++;
  k = elab_inner(c, t, hint, type);
  c->depth--;
  return k;
}

/* NULL when NAME is free, else the reason it is taken (rule R4). */
static const char *name_owner(const Checker *c, const char *name) {
  const Machine *m = c->m;
  uint32_t i;
  uint32_t j;
  for (i = 0; i < sizeof RESERVED / sizeof RESERVED[0]; i++) {
    if (strcmp(RESERVED[i], name) == 0)
      return "a reserved name";
  }
  for (i = 0; i < BUILTIN_COUNT; i++) {
    if (strcmp(BUILTINS[i].name, name) == 0)
      return "a core name";
  }
  for (i = 0; i < m->family_count; i++) {
    if (strcmp(m->families[i].name, name) == 0)
      return "a domain family";
  }
  for (i = 0; i < m->ctor_count; i++) {
    for (j = 0; j < m->ctors[i].field_count; j++) {
      if (strcmp(m->ctors[i].fields[j].name, name) == 0)
        return "a domain field";
    }
    if (strcmp(m->ctors[i].name, name) == 0)
      return "a domain constructor";
  }
  i = find_def(m, name);
  if (i == NO_DEF)
    return NULL;
  return m->defs[i].origin == ORIGIN_DOMAIN ? "a domain definition" : "already defined";
}

static int name_free(Checker *c, const char *name) {
  const char *why = name_owner(c, name);
  return why == NULL ? 1 : FAIL(c, "REFUSE_NAME", "%s is %s (rule R4)", name, why);
}

/* T ends in a universe, so a parameter of type T is a type argument. */
static int cell_type_argument(const Core *t) {
  while (t != NULL && t->kind == CORE_PI)
    t = t->b;
  return t != NULL && t->kind == CORE_UNIV;
}

static int has_type_param(const FamilyInfo *f) {
  uint32_t k;
  for (k = 0; k < f->param_count; k++)
    if (cell_type_argument(f->param_types[k]))
      return 1;
  return 0;
}

/* The R1 class of a family. check_decl refuses closed program data, so a
   program family here has a type parameter (a cell monad) or value
   parameters only. */
static FamilyClass family_class(const Decl *d, const FamilyInfo *f) {
  if (d->origin == ORIGIN_DOMAIN)
    return FAMILY_BASE;
  return has_type_param(f) ? FAMILY_CM : FAMILY_INDEXED;
}

/* A field type is in the context of the family parameters only, so the
   parameter K is the variable with the index param_count - 1 - K. */

/* The type parameter K that T names, else param_count. */
static uint32_t cell_param(const FamilyInfo *f, const Core *t) {
  uint32_t p = f->param_count;
  uint32_t k;
  if (t == NULL || t->kind != CORE_VAR || t->index >= p)
    return p;
  k = p - 1u - t->index;
  return f->param_types[k]->kind == CORE_UNIV ? k : p;
}

/* T is the family FAM at its own parameters, in order, under EARLIER
   fields, then at any indices. */
static int own_family(const Checker *c, uint32_t fam, const Core *t, uint32_t earlier) {
  uint32_t p = c->m->families[fam].param_count;
  uint32_t i;
  if (t == NULL || t->kind != CORE_OP || t->op != OP_FAMILY || t->inst != fam || t->argc != p + c->m->families[fam].index_count)
    return 0;
  for (i = 0; i < p; i++)
    if (t->args[i] == NULL || t->args[i]->kind != CORE_VAR || t->args[i]->index != earlier + p - 1u - i)
      return 0;
  return 1;
}

/* T has no free variable at DEPTH binders, so it names no parameter. */
static int cell_closed(const Core *t, uint32_t depth) {
  uint32_t i;
  if (t == NULL)
    return 1;
  switch (t->kind) {
  case CORE_VAR:
    return t->index < depth;
  case CORE_GLOBAL:
  case CORE_NAT:
  case CORE_TRAP:
  case CORE_UNIV:
    return 1;
  case CORE_LAM:
  case CORE_PI:
  case CORE_SIGMA:
    return cell_closed(t->a, depth) && cell_closed(t->b, depth + 1u);
  case CORE_APP:
    return cell_closed(t->a, depth) && cell_closed(t->b, depth);
  case CORE_OP:
    break;
  }
  for (i = 0; i < t->argc; i++)
    if (!cell_closed(t->args[i], depth))
      return 0;
  return 1;
}

/* A family with a type argument has only universe parameters (rule R1). */
static int cell_header(Checker *c, const Decl *d, const FamilyInfo *f) {
  uint32_t k;
  c->at = NULL;
  for (k = 0; k < f->param_count; k++)
    if (f->param_types[k]->kind != CORE_UNIV)
      return FAIL(c, "REFUSE_CELL", "%s has a type argument and the parameter %s is not a universe; a cell signature has only type parameters (rule R1)", f->name, d->params[k].name);
  return 1;
}

/* An index type that ends in a universe is a type index. A cell signature
   binds its type arguments as uniform parameters (rule R1). */
static int type_index(Checker *c, const FamilyInfo *f) {
  uint32_t k;
  c->at = NULL;
  for (k = 0; k < f->index_count; k++)
    if (cell_type_argument(f->index_types[k]))
      return FAIL(c, "REFUSE_CELL", "%s has a type index; a cell signature binds its type arguments as uniform parameters (rule R1)", f->name);
  return 1;
}

/* The body of the line of a path type, under one binder; NULL when T is
   not a path type. */
static const Core *path_body(const Core *t) {
  return t != NULL && t->kind == CORE_OP && t->op == OP_PATHP && t->argc == 3u && t->args[0] != NULL && t->args[0]->kind == CORE_LAM ? t->args[0]->b : NULL;
}

/* A field of a cell monad: a type parameter (the one field of its
   constructor), closed data, the family at its own parameters, or a path
   in the family (under EARLIER fields). */
static int cell_field(Checker *c, uint32_t fam, const FieldInfo *out, size_t field_count, uint32_t earlier) {
  const FamilyInfo *f = &c->m->families[fam];
  const Core *t = out->type;
  const Core *line = path_body(t);
  if (t != NULL && t->kind == CORE_VAR && t->index >= earlier && t->index - earlier < f->param_count)
    return field_count == 1u ? 1 : FAIL(c, "REFUSE_CELL", "%s is not a cell signature: the field %s has a type parameter as its type, so it must be the one field of its constructor (rule R1)", f->name, out->name);
  if (own_family(c, fam, t, earlier) || (line != NULL && own_family(c, fam, line, earlier + 1u)) || (c->self_uses == 0u && cell_closed(t, earlier)))
    return 1;
  return FAIL(c, "REFUSE_CELL", "%s is not a cell signature: the field %s must be a type parameter, closed data, %s at its own parameters or a path in %s (rule R1)", f->name, out->name, f->name, f->name);
}

/* Each type parameter has one generator: one constructor with one field
   of that type (rule R1). */
static int cell_generators(Checker *c, const Decl *d, uint32_t fam) {
  const Machine *m = c->m;
  const FamilyInfo *f = &m->families[fam];
  uint32_t k;
  c->at = NULL;
  for (k = 0; k < f->param_count; k++) {
    unsigned count = 0;
    uint32_t j;
    for (j = 0; j < f->ctor_count; j++) {
      const CtorInfo *ci = &m->ctors[f->first_ctor + j];
      count += ci->depth == 0u && ci->field_count == 1u && cell_param(f, ci->fields[0].type) == k;
    }
    if (count == 0u)
      return FAIL(c, "REFUSE_CELL", "%s is not a cell signature: the type parameter %s occurs in no constructor (rule R1)", f->name, d->params[k].name);
    if (count > 1u)
      return FAIL(c, "REFUSE_CELL", "%s is not a cell signature: the type parameter %s has %u generators (rule R1)", f->name, d->params[k].name, count);
  }
  return 1;
}

/* A recursive field must be the whole field type: the family at its own
   parameters (under EARLIER fields), then at any indices. A field of a cell
   monad must pass cell_field first. */
static int check_field(Checker *c, uint32_t fam, const Field *field, size_t field_count, uint32_t earlier, FieldInfo *out) {
  uint64_t level = 0;
  const Core *t;
  if (!name_free(c, field->name))
    return 0;
  c->self_uses = 0;
  t = check_type(c, field->type, &level);
  if (t == NULL)
    return 0;
  if (level > c->m->families[fam].universe)
    c->m->families[fam].universe = level;
  out->name = field->name;
  out->type = t;
  out->recursive = c->self_uses > 0u;
  if (c->m->families[fam].r1 == FAMILY_CM && !cell_field(c, fam, out, field_count, earlier))
    return 0;
  if (c->m->families[fam].r1 == FAMILY_CM && own_family(c, fam, path_body(t), earlier + 1u))
    out->recursive = 0;
  if (out->recursive && !own_family(c, fam, t, earlier))
    return FAIL(c, "DOMAIN_FAMILY", "the recursive field %s must have the type %s itself, at the parameters of the family", field->name, c->m->families[fam].name);
  return 1;
}

/* K is a point term of FAM under DEPTH binders: a recursive field of the
   constructor (N FIELDS), or a point constructor at the params whose
   recursive arguments are point terms and whose other arguments are
   fields (D10). */
static int point_term(const Checker *c, uint32_t fam, const FieldInfo *fields, uint32_t n, const Core *k, uint32_t depth) {
  const Machine *m = c->m;
  uint32_t p = m->families[fam].param_count;
  const CtorInfo *ci;
  uint32_t i;
  if (k != NULL && k->kind == CORE_VAR)
    return k->index >= depth && k->index - depth < n && fields[n - 1u - (k->index - depth)].recursive;
  if (k == NULL || k->kind != CORE_OP || k->op != OP_CTOR || k->inst >= m->ctor_count)
    return 0;
  ci = &m->ctors[k->inst];
  if (ci->family != fam || ci->depth != 0u || k->argc != p + ci->field_count)
    return 0;
  for (i = 0; i < p; i++)
    if (k->args[i] == NULL || k->args[i]->kind != CORE_VAR || k->args[i]->index != depth + n + p - 1u - i)
      return 0;
  for (i = 0; i < ci->field_count; i++) {
    const Core *x = k->args[p + i];
    int ok = ci->fields[i].recursive ? point_term(c, fam, fields, n, x, depth)
                                     : x != NULL && x->kind == CORE_VAR && x->index >= depth && x->index - depth < n;
    if (!ok)
      return 0;
  }
  return 1;
}

/* A path constructor (D10): its type is s ≡ t over point terms (depth 1)
   or p ≡ q over two path fields (depth 2). The fields are pushed. The
   ends x, y of a square leave the line binder by evaluation. */
static int check_pctor(Checker *c, uint32_t fam, const Ctor *ctor, const FieldInfo *fields, CtorInfo *ci) {
  Machine *m = c->m;
  const char *name = m->families[fam].name;
  uint32_t n = (uint32_t)ctor->field_count;
  uint64_t level = 0;
  const Core *t = check_type(c, ctor->result, &level);
  const Core *k = t;
  const Core *inner = path_body(t);
  const Core **ends = arena_alloc(m->arena, 5u * sizeof *ends);
  uint32_t depth = 0;
  uint32_t i;
  if (t == NULL)
    return 0;
  if (ends == NULL)
    return FAIL(c, "OOM", "out of memory");
  while (k != NULL && !own_family(c, fam, k, n + depth)) {
    k = path_body(k);
    depth++;
  }
  if (k == NULL || depth == 0u)
    return FAIL(c, "REFUSE_CELL", "%s is not a cell signature: the path constructor %s must have the type s ≡ t over %s or p ≡ q over a path in %s (rule R1)", name, ctor->name, name, name);
  if (depth > 2u)
    return FAIL(c, "REFUSE_CELL", "%s is not a cell signature: the path constructor %s has dimension %u; only 1 and 2 are available (rule R1)", name, ctor->name, (unsigned)depth);
  ends[0] = t->args[1];
  ends[1] = t->args[2];
  if (depth == 1u && !(point_term(c, fam, fields, n, ends[0], 0u) && point_term(c, fam, fields, n, ends[1], 0u)))
    return FAIL(c, "REFUSE_CELL", "%s is not a cell signature: an end of the path constructor %s must be a point term (rule R1)", name, ctor->name);
  for (i = 0; depth == 2u && i < 2u; i++)
    if (ends[i] == NULL || ends[i]->kind != CORE_VAR || ends[i]->index >= n)
      return FAIL(c, "REFUSE_CELL", "%s is not a cell signature: the ends p, q of the square %s must be fields of the constructor (rule R1)", name, ctor->name);
  for (i = 0; depth == 2u && i < 2u; i++) {
    const Value *v;
    if (!point_term(c, fam, fields, n, inner->args[1u + i], 1u))
      return FAIL(c, "REFUSE_CELL", "%s is not a cell signature: an end of the path constructor %s must be a point term (rule R1)", name, ctor->name);
    if (!push(c, "_", val_op(m, VAL_OP, OP_I, 0, 0, NULL, 0)))
      return 0;
    v = here(c, inner->args[1u + i]);
    pop(c);
    ends[2u + i] = quote_value(m, c->level, v);
  }
  ci->depth = depth;
  ci->type = t;
  ci->ends = ends;
  return 1;
}

static int check_ctor(Checker *c, uint32_t fam, const Ctor *ctor) {
  Machine *m = c->m;
  const FamilyInfo *f = &m->families[fam];
  int dep = telescope(f) || ctor->result != NULL;
  FieldInfo *fields = arena_alloc(m->arena, (ctor->field_count + 1u) * sizeof *fields);
  const Core **indices = arena_alloc(m->arena, (f->index_count + 1u) * sizeof *indices);
  const Value **itypes = arena_alloc(m->arena, (f->index_count + 1u) * sizeof *itypes);
  CtorInfo *ci = &m->ctors[m->ctor_count];
  size_t j;
  if (fields == NULL || indices == NULL || itypes == NULL)
    return FAIL(c, "OOM", "out of memory");
  if (!name_free(c, ctor->name))
    return 0;
  if (ctor->result != NULL && f->r1 != FAMILY_CM)
    return FAIL(c, "DOMAIN_FAMILY", "the path constructor %s is in S2 only in a cell signature (rule R1)", ctor->name);
  for (j = 0; j < f->index_count; j++)
    itypes[j] = here(c, f->index_types[j]);
  for (j = 0; j < ctor->field_count; j++) {
    size_t earlier;
    const char *name = ctor->fields[j].name;
    if (strcmp(name, ctor->name) == 0)
      return FAIL(c, "REFUSE_NAME", "%s is the constructor name (rule R4)", name);
    for (earlier = 0; earlier < j; earlier++)
      if (strcmp(name, ctor->fields[earlier].name) == 0)
        return FAIL(c, "REFUSE_NAME", "%s is already a field of this constructor (rule R4)", name);
    if (!check_field(c, fam, &ctor->fields[j], ctor->field_count, dep ? (uint32_t)j : 0u, &fields[j]))
      return 0;
    if (dep && !push(c, name, here(c, fields[j].type)))
      return 0;
  }
  for (j = 0; j < f->index_count; j++) {
    indices[j] = check(c, ctor->indices[j], itypes[j]);
    if (indices[j] == NULL)
      return 0;
  }
  ci->depth = 0;
  ci->type = NULL;
  ci->ends = NULL;
  if (ctor->result != NULL && !check_pctor(c, fam, ctor, fields, ci))
    return 0;
  for (j = 0; dep && j < ctor->field_count; j++)
    pop(c);
  ci->name = ctor->name;
  ci->family = fam;
  ci->fields = fields;
  ci->indices = indices;
  ci->field_count = (uint32_t)ctor->field_count;
  m->ctor_count++;
  return 1;
}

/* T is the type former OP with no arguments. */
static int is_op_core(const Core *t, Op op) {
  return t != NULL && t->kind == CORE_OP && t->op == op && t->argc == 0u;
}

/* T is the domain base type Code (O68). */
static int is_code_core(const Machine *m, const Core *t) {
  return is_op_core(t, OP_FAMILY) && t->inst < m->family_count && m->families[t->inst].r1 == FAMILY_BASE && strcmp(m->families[t->inst].name, "Code") == 0;
}

/* An indexed family whose indices are all Code is a circuit family (O71).
   Each field is a Code, a ℕ, a Bool or the family itself, so a circuit is
   first order. */
static int circuit_fields(Checker *c, uint32_t fam) {
  const Machine *m = c->m;
  const FamilyInfo *f = &m->families[fam];
  uint32_t j;
  uint32_t i;
  c->at = NULL;
  if (f->index_count == 0u)
    return 1;
  for (i = 0; i < f->index_count; i++)
    if (!is_code_core(m, f->index_types[i]))
      return 1;
  for (j = 0; j < f->ctor_count; j++) {
    const CtorInfo *ci = &m->ctors[f->first_ctor + j];
    for (i = 0; i < ci->field_count; i++) {
      const Core *t = ci->fields[i].type;
      if (!ci->fields[i].recursive && !is_code_core(m, t) && !is_op_core(t, OP_NAT) && !is_op_core(t, OP_FLAG))
        return FAIL(c, "REFUSE_CIRCUIT", "%s is a circuit family: the field %s of %s must be a Code, a ℕ, a Bool or %s itself, so that a circuit is first order (O71)", f->name, ci->fields[i].name, ci->name, f->name);
    }
  }
  return 1;
}

/* O72: a sealed family is a cell monad with one generator: one type
   parameter, no index and one point constructor with one field. */
static int sealed_shape(const Machine *m, const FamilyInfo *f) {
  const CtorInfo *ci = &m->ctors[f->first_ctor];
  return f->param_count == 1u && has_type_param(f) && f->index_count == 0u && f->ctor_count == 1u && ci->field_count == 1u && ci->depth == 0u;
}

/* A family is in scope in its own fields, so a field can be recursive. A
   program family with a type parameter must be a cell signature. */
static int check_family(Checker *c, const Decl *d) {
  Machine *m = c->m;
  uint32_t fam = m->family_count;
  FamilyInfo *f = &m->families[fam];
  const Core **params = arena_alloc(m->arena, (d->param_count + 1u) * sizeof *params);
  const Core **indices = arena_alloc(m->arena, (d->index_count + 1u) * sizeof *indices);
  size_t i;
  if (params == NULL || indices == NULL)
    return FAIL(c, "OOM", "out of memory");
  for (i = 0; i < d->param_count; i++) {
    uint64_t level = 0;
    params[i] = check_type(c, d->params[i].type, &level);
    params[i] = quote_value(m, c->level, here(c, params[i]));
    if (params[i] == NULL || !push(c, d->params[i].name, here(c, params[i])))
      return 0;
  }
  for (i = 0; i < d->index_count; i++) {
    uint64_t level = 0;
    indices[i] = check_type(c, d->indices[i], &level);
    indices[i] = quote_value(m, c->level, here(c, indices[i]));
    if (indices[i] == NULL)
      return 0;
  }
  f->name = d->name;
  f->param_types = params;
  f->param_count = (uint32_t)d->param_count;
  f->index_types = indices;
  f->index_count = (uint32_t)d->index_count;
  f->first_ctor = m->ctor_count;
  f->ctor_count = (uint32_t)d->ctor_count;
  f->r1 = family_class(d, f);
  f->sealed = d->is_sealed;
  m->family_count++;
  if (!type_index(c, f))
    return 0;
  if (f->r1 == FAMILY_CM && !cell_header(c, d, f))
    return 0;
  c->self = fam;
  for (i = 0; i < d->ctor_count; i++) {
    if (!check_ctor(c, fam, &d->ctors[i]))
      return 0;
  }
  if (f->sealed && !sealed_shape(m, f)) {
    c->at = NULL;
    return FAIL(c, "REFUSE_CELL", "%s is sealed but is not a cell monad with one generator: a sealed family has one type parameter and one constructor with one field (O72)", d->name);
  }
  return f->r1 == FAMILY_CM ? cell_generators(c, d, fam) : f->r1 != FAMILY_INDEXED || circuit_fields(c, fam);
}

/* O72: a law type is, after the Pis, a Path type or a universe. */
static int law_type(Checker *c, const Value *t) {
  uint32_t n = c->level;
  while (t != NULL && t->kind == VAL_PI)
    t = closure_apply(c->m, t, val_var(c->m, n++));
  return t != NULL && (t->kind == VAL_UNIV || val_is(t, OP_PATHP));
}

static int check_def(Checker *c, const Decl *d) {
  Machine *m = c->m;
  uint64_t level = 0;
  const Core *t = check_type(c, d->type, &level);
  const Value *tv = here(c, t);
  const Core *body;
  DefInfo *info = &m->defs[m->def_count];
  int law_only;
  /* O72: the seal flag looks at the body only, so a type (a record field
     type too) can name unseal. */
  c->opens = 0;
  body = check(c, d->body, tv);
  if (body == NULL)
    return 0;
  law_only = c->opens && !law_type(c, tv);
  if (law_only && !d->is_law) {
    c->at = NULL;
    return FAIL(c, "REFUSE_LAW", "%s opens the seal (a fold or a projection of a sealed family, or a law-only name such as unseal), but it is not a law and its type does not end in a Path or a universe (O72)", d->name);
  }
  info->name = d->name;
  info->origin = d->origin;
  info->body = body;
  info->type = tv;
  info->value = NULL;
  info->law_only = law_only;
  m->def_count++;
  return 1;
}

/* T ends in a universe after its arrows. */
static int term_ends_in_universe(const Term *t) {
  while (t != NULL && t->kind == TERM_PI)
    t = t->right;
  return t != NULL && t->kind == TERM_UNIV;
}

/* A coinductive record is a cell comonad (Q1 (b)). */
static int refuse_coinductive(Checker *c, const Decl *d) {
  size_t i;
  for (i = 0; i < d->param_count; i++)
    if (term_ends_in_universe(d->params[i].type))
      return FAIL(c, "REFUSE_CELL", "%s is a coinductive record with a type parameter, a cell comonad: R1 admits cell monads only (Q1 (b))", d->name);
  return FAIL(c, "REFUSE_CELL", "%s is a coinductive record: R1 admits cell monads only (Q1 (b))", d->name);
}

/* The bound record value in a projection. The lexer cannot make this name,
   so a parameter or a field cannot capture it. */
static const char RECORD_SELF[] = "%r";

/* A term of the definitions that the record D stands for. OK goes to 0
   when the arena is full. */
static Term *rec_term(Checker *c, const Decl *d, int *ok, TermKind kind, const char *name, const Term *left, const Term *right) {
  Term *t = arena_alloc(c->m->arena, sizeof *t);
  if (t == NULL) {
    *ok = 0;
    return NULL;
  }
  memset(t, 0, sizeof *t);
  t->kind = kind;
  t->line = d->line;
  t->col = d->col;
  t->name = name;
  t->left = left;
  t->right = right;
  return t;
}

/* Field K of the record value R: fst (snd^K r); the last field is
   snd^(N-1) r. */
static const Term *rec_project(Checker *c, const Decl *d, int *ok, size_t k, const Term *r) {
  size_t j;
  for (j = 0; j < k; j++)
    r = rec_term(c, d, ok, TERM_APP, NULL, rec_term(c, d, ok, TERM_VAR, "snd", NULL, NULL), r);
  if (k + 1u == d->field_count)
    return r;
  return rec_term(c, d, ok, TERM_APP, NULL, rec_term(c, d, ok, TERM_VAR, "fst", NULL, NULL), r);
}

/* Checks NAME : TYPE = BODY, one of the definitions that the record D (or
   the section definition D) stands for. */
static int rec_def(Checker *c, const Decl *d, const char *name, const Term *type, const Term *body) {
  Decl def;
  memset(&def, 0, sizeof def);
  def.kind = DECL_DEF;
  def.origin = d->origin;
  def.line = d->line;
  def.col = d->col;
  def.end_line = d->end_line;
  def.source = d->source;
  def.name = name;
  def.type = type;
  def.body = body;
  def.is_law = d->is_law;
  return check_def(c, &def);
}

/* A type argument ends in a universe, including a family-valued argument. */
static int value_type_argument(Checker *c, const Value *type, uint32_t level) {
  while (type != NULL && type->kind == VAL_PI)
    type = closure_apply(c->m, type, val_var(c->m, level++));
  return type != NULL && type->kind == VAL_UNIV;
}

/* Inspect the checked Sigma fields so aliases cannot hide a constructor type. */
static int record_fields_ok(Checker *c, const Decl *d) {
  const Value *row = def_value(c->m, c->m->def_count - 1u);
  uint32_t level = c->level;
  size_t k;
  for (k = 0; k < d->param_count && row != NULL; k++)
    row = apply_value(c->m, row, val_var(c->m, level++));
  for (k = 0; k < d->field_count && row != NULL; k++) {
    const Value *field = k + 1u < d->field_count ? row->dom : row;
    uint32_t inner = level;
    int type_arg = 0;
    while (field != NULL && field->kind == VAL_PI) {
      type_arg |= value_type_argument(c, field->dom, inner);
      field = closure_apply(c->m, field, val_var(c->m, inner++));
    }
    if (field == NULL || c->m->diag->set)
      return 0;
    if (type_arg && field->kind == VAL_UNIV)
      return FAIL(c, "REFUSE_CELL", "%s is not a cell signature: the field %s is type-constructor valued (sec 2.4, rule R1)", d->name, d->fields[k].name);
    if (k + 1u < d->field_count)
      row = closure_apply(c->m, row, val_var(c->m, level++));
  }
  return row != NULL;
}

/* A record is a named Σ (D2): NAME params = Σ A₁ (λ x₁ → ...). Each field
   is a global projection whose type binds the earlier fields with let. */
static int check_record(Checker *c, const Decl *d) {
  int ok = 1;
  size_t i;
  size_t k;
  for (k = 0; k < d->field_count; k++) {
    const Term *t = d->fields[k].type;
    if (t->kind == TERM_PI && t->left->kind == TERM_UNIV && term_ends_in_universe(t->right))
      return FAIL(c, "REFUSE_CELL", "%s is not a cell signature: the field %s is type-constructor valued (sec 2.4, rule R1)", d->name, d->fields[k].name);
  }
  Term *univ = rec_term(c, d, &ok, TERM_UNIV, NULL, NULL, NULL);
  if (univ != NULL)
    univ->nat = d->level;
  const Term *type = univ;
  const Term *body = d->fields[d->field_count - 1u].type;
  for (k = d->field_count - 1u; k > 0; k--)
    body = rec_term(c, d, &ok, TERM_SIGMA, d->fields[k - 1u].name, d->fields[k - 1u].type, body);
  for (i = d->param_count; i > 0; i--) {
    type = rec_term(c, d, &ok, TERM_PI, d->params[i - 1u].name, d->params[i - 1u].type, type);
    body = rec_term(c, d, &ok, TERM_LAM, d->params[i - 1u].name, NULL, body);
  }
  if (!ok)
    return FAIL(c, "OOM", "out of memory");
  if (!rec_def(c, d, d->name, type, body))
    return 0;
  if (!record_fields_ok(c, d))
    return 0;
  const Term *app = rec_term(c, d, &ok, TERM_VAR, d->name, NULL, NULL);
  for (i = 0; i < d->param_count; i++)
    app = rec_term(c, d, &ok, TERM_APP, NULL, app, rec_term(c, d, &ok, TERM_VAR, d->params[i].name, NULL, NULL));
  const Term *self = rec_term(c, d, &ok, TERM_VAR, RECORD_SELF, NULL, NULL);
  for (k = 0; k < d->field_count; k++) {
    const Term *ptype = d->fields[k].type;
    const Term *pbody = rec_project(c, d, &ok, k, self);
    size_t j;
    for (j = k; j > 0; j--)
      ptype = rec_term(c, d, &ok, TERM_LET, d->fields[j - 1u].name, rec_project(c, d, &ok, j - 1u, self), ptype);
    ptype = rec_term(c, d, &ok, TERM_PI, RECORD_SELF, app, ptype);
    pbody = rec_term(c, d, &ok, TERM_LAM, RECORD_SELF, NULL, pbody);
    for (i = d->param_count; i > 0; i--) {
      ptype = rec_term(c, d, &ok, TERM_PI, d->params[i - 1u].name, d->params[i - 1u].type, ptype);
      pbody = rec_term(c, d, &ok, TERM_LAM, d->params[i - 1u].name, NULL, pbody);
    }
    if (!ok)
      return FAIL(c, "OOM", "out of memory");
    if (!name_free(c, d->fields[k].name) || !rec_def(c, d, d->fields[k].name, ptype, pbody))
      return 0;
  }
  return 1;
}

/* The binder names around a term of a section definition (D3). */
typedef struct SecHide SecHide;
struct SecHide {
  const char *name;
  const SecHide *next;
};

static int sec_hidden(const SecHide *h, const char *name) {
  for (; h != NULL; h = h->next)
    if (strcmp(h->name, name) == 0)
      return 1;
  return 0;
}

/* NAME is a definition of the section of D that comes before D. */
static int sec_earlier(const Checker *c, const Decl *d, const char *name) {
  size_t j;
  for (j = d->section; j < c->decl_index; j++)
    if (strcmp(c->decls->items[j].name, name) == 0)
      return 1;
  return 0;
}

/* A use T of a name in the definition D of a section: an earlier definition
   of the section takes the section parameters (D3). OK goes to 0 when the
   arena is full, and to -1 after a refusal. */
static const Term *sec_use(Checker *c, const Decl *d, int *ok, const SecHide *hide, const Term *t) {
  const Decl *s = &c->decls->items[d->section - 1u];
  const Term *app = t;
  size_t i;
  if (sec_hidden(hide, t->name) || !sec_earlier(c, d, t->name))
    return t;
  for (i = 0; i < s->param_count; i++) {
    if (sec_hidden(hide, s->params[i].name)) {
      FAIL(c, "REFUSE_NAME", "%s uses %s where a binder hides the section parameter %s; rename the binder (D3)", d->name, t->name, s->params[i].name);
      *ok = -1;
      return t;
    }
    app = rec_term(c, d, ok, TERM_APP, NULL, app, rec_term(c, d, ok, TERM_VAR, s->params[i].name, NULL, NULL));
  }
  return app;
}

/* T, a term of the definition D of a section, with sec_use at each name.
   A binder hides its name in its body. */
static const Term *sec_term(Checker *c, const Decl *d, int *ok, const SecHide *hide, const Term *t) {
  SecHide inner;
  Term *out;
  Cell *cells;
  size_t i;
  if (t == NULL || *ok != 1 || t->kind == TERM_NAT)
    return t;
  if (t->kind == TERM_VAR)
    return sec_use(c, d, ok, hide, t);
  out = arena_alloc(c->m->arena, sizeof *out);
  if (out == NULL) {
    *ok = 0;
    return t;
  }
  *out = *t;
  switch (t->kind) {
  case TERM_VAR:
  case TERM_NAT:
    break;
  case TERM_APP:
  case TERM_UNIV:
    out->left = sec_term(c, d, ok, hide, t->left);
    out->right = sec_term(c, d, ok, hide, t->right);
    break;
  case TERM_LAM:
  case TERM_PI:
  case TERM_SIGMA:
  case TERM_LET:
    inner.name = t->name;
    inner.next = hide;
    out->left = sec_term(c, d, ok, hide, t->left);
    out->right = sec_term(c, d, ok, t->name != NULL ? &inner : hide, t->right);
    break;
  case TERM_SYSTEM:
    cells = arena_alloc(c->m->arena, (t->cell_count + 1u) * sizeof *cells);
    if (cells == NULL) {
      *ok = 0;
      return t;
    }
    for (i = 0; i < t->cell_count; i++) {
      cells[i] = t->cells[i];
      cells[i].body = sec_term(c, d, ok, hide, t->cells[i].body);
    }
    out->cells = cells;
    break;
  }
  return out;
}

/* A definition of a section (D3): NAME : (params) → TYPE = λ params → BODY,
   where each earlier definition of the section takes the parameters. */
static int check_section(Checker *c, const Decl *d) {
  const Decl *s = &c->decls->items[d->section - 1u];
  int ok = 1;
  size_t i;
  const Term *type = sec_term(c, d, &ok, NULL, d->type);
  const Term *body = sec_term(c, d, &ok, NULL, d->body);
  for (i = s->param_count; i > 0; i--) {
    type = rec_term(c, d, &ok, TERM_PI, s->params[i - 1u].name, s->params[i - 1u].type, type);
    body = rec_term(c, d, &ok, TERM_LAM, s->params[i - 1u].name, NULL, body);
  }
  if (ok < 0)
    return 0;
  if (!ok)
    return FAIL(c, "OOM", "out of memory");
  return rec_def(c, d, d->name, type, body);
}

static int check_decl(Checker *c, const Decl *d) {
  if (d->kind == DECL_MODULE)
    return 1;
  if (d->is_sealed && d->origin == ORIGIN_PROGRAM)
    return FAIL(c, "REFUSE_DATA", "a program cannot declare a sealed family; a sealed family comes only from domain/domain.lang (O72)");
  if (d->kind == DECL_FAMILY && d->origin == ORIGIN_PROGRAM && d->param_count == 0u && d->index_count == 0u)
    return FAIL(c, "REFUSE_DATA", "a program cannot declare closed data; a base type comes only from domain/domain.lang (rule R2)");
  if (d->kind == DECL_AXIOM)
    return FAIL(c, "REFUSE_AXIOM", "a postulate has no proof (rule R2)");
  if (d->kind == DECL_RECORD && d->coinductive)
    return refuse_coinductive(c, d);
  if (d->is_rec)
    return FAIL(c, "REFUSE_REC", "%s names itself, and a definition cannot recur (rule R3); use fold", d->name);
  if (!name_free(c, d->name))
    return 0;
  return d->kind == DECL_FAMILY ? check_family(c, d)
       : d->kind == DECL_RECORD ? check_record(c, d)
       : d->section != 0u ? check_section(c, d)
       : check_def(c, d);
}

int check_program(Arena *arena, const DeclList *decls, Machine *m, Diag *diag) {
  Checker c;
  size_t ctors = 0;
  size_t fields = 0;
  size_t i;
  memset(m, 0, sizeof *m);
  m->arena = arena;
  m->diag = diag;
  m->fuel = EVAL_FUEL_STEPS;
  for (i = 0; i < decls->count; i++) {
    ctors += decls->items[i].ctor_count;
    fields += decls->items[i].field_count;
  }
  m->defs = arena_alloc(arena, (decls->count + fields + 1u) * sizeof *m->defs);
  m->families = arena_alloc(arena, (decls->count + 1u) * sizeof *m->families);
  m->ctors = arena_alloc(arena, (ctors + 1u) * sizeof *m->ctors);
  if (m->defs == NULL || m->families == NULL || m->ctors == NULL)
    return diag_fail(diag, "OOM", NULL, "out of memory");
  m->def_cap = (uint32_t)(decls->count + fields);
  m->family_cap = (uint32_t)decls->count;
  m->ctor_cap = (uint32_t)ctors;
  memset(&c, 0, sizeof c);
  c.m = m;
  c.decls = decls;
  for (i = 0; i < decls->count; i++) {
    c.decl_index = i;
    c.scope = NULL;
    c.env = NULL;
    c.level = 0;
    c.depth = 0;
    c.self = NO_FAMILY;
    m->def = decls->items[i].name;
    c.at = NULL;
    if (!check_decl(&c, &decls->items[i]))
      return 0;
    m->typed += decls->items[i].origin == ORIGIN_PROGRAM;
  }
  m->def = NULL;
  return 1;
}

/* O109 (i): TYPE is an input family. That is a family of
   domain/domain.lang without parameters, indices or seal, with point
   constructors only. Each field is ℕ, Bool, the family itself (LIST only)
   or a record (an input family with LIST 0). A LIST family has a
   constructor with one recursive field and no constructor with two. */
static int input_family(Machine *m, const Value *type, int list) {
  const FamilyInfo *fam;
  const FieldInfo *f;
  const Value *ft;
  uint32_t recs = 0;
  uint32_t r;
  uint32_t c;
  uint32_t k;
  if (!val_is(type, OP_FAMILY) || type->inst >= m->family_count)
    return 0;
  fam = &m->families[type->inst];
  if (fam->r1 != FAMILY_BASE || fam->param_count != 0u || fam->index_count != 0u || fam->sealed)
    return 0;
  for (c = fam->first_ctor; c < fam->first_ctor + fam->ctor_count; c++) {
    if (m->ctors[c].depth != 0u)
      return 0;
    r = 0;
    for (k = 0; k < m->ctors[c].field_count; k++) {
      f = &m->ctors[c].fields[k];
      ft = f->recursive ? NULL : eval_core(m, NULL, f->type);
      r += f->recursive ? 1u : 0u;
      if (!f->recursive && !val_is(ft, OP_NAT) && !val_is(ft, OP_FLAG) && !(list && input_family(m, ft, 0)))
        return 0;
    }
    if (r > (uint32_t)list)
      return 0;
    recs += r;
  }
  return !list || recs > 0u;
}

/* The kind of an entry parameter of type DOM. */
static EntryParam param_kind_of(const Value *dom) {
  if (val_is(dom, OP_NAT))
    return ENTRY_PARAM_NAT;
  if (val_is(dom, OP_FLAG))
    return ENTRY_PARAM_FLAG;
  return ENTRY_PARAM_INPUT;
}

/* The decimal word at *P, then *P goes past it and past one comma. */
static int next_word(const char **p, uint64_t *out) {
  const char *s = *p;
  uint64_t n = 0;
  unsigned d;
  if (*s < '0' || *s > '9')
    return 0;
  for (; *s >= '0' && *s <= '9'; s++) {
    d = (unsigned)(*s - '0');
    if (n > (UINT64_MAX - d) / 10u)
      return 0;
    n = n * 10u + d;
  }
  *p = *s == ',' ? s + 1 : s;
  *out = n;
  return 1;
}

static const Value *input_value(Machine *m, uint32_t family, const char **p);

/* Field F of a block of FAMILY at *P. */
static const Value *input_field(Machine *m, uint32_t family, const FieldInfo *f, const char **p) {
  const Value *ft = f->recursive ? NULL : eval_core(m, NULL, f->type);
  uint64_t w = 0;
  if (f->recursive)
    return input_value(m, family, p);
  if (val_is(ft, OP_FAMILY))
    return input_value(m, ft->inst, p);
  if (!next_word(p, &w) || (val_is(ft, OP_FLAG) && w > 1u))
    return NULL;
  return val_is(ft, OP_FLAG) ? val_make(m, w == 1u ? OP_FLAG_YES : OP_FLAG_NO, 0, 0, NULL, NULL, NULL) : val_nat(m, w);
}

/* An input value of FAMILY at *P in the pre-order form: the tag of the
   block, then each field (a ℕ in decimal, a Bool as 0 or 1, or a block),
   comma-separated. "1,3,1,4,0" is push 3 (push 4 bottom). NULL when the
   text does not fit. */
static const Value *input_value(Machine *m, uint32_t family, const char **p) {
  const FamilyInfo *fam = &m->families[family];
  const CtorInfo *c;
  const Value **args;
  uint64_t tag = 0;
  uint32_t k;
  int ok = 1;
  if (!next_word(p, &tag) || tag >= fam->ctor_count || m->depth >= EVAL_DEPTH_LIMIT)
    return NULL;
  c = &m->ctors[fam->first_ctor + (uint32_t)tag];
  args = arena_alloc(m->arena, ((size_t)c->field_count + 1u) * sizeof *args);
  if (args == NULL)
    return NULL;
  m->depth++;
  for (k = 0; k < c->field_count && ok; k++) {
    args[k] = input_field(m, family, &c->fields[k], p);
    ok = args[k] != NULL;
  }
  m->depth--;
  return ok ? val_op(m, VAL_OP, OP_CTOR, fam->first_ctor + (uint32_t)tag, 0, (const Value *const *)args, c->field_count)
            : NULL;
}

int entry_of(Machine *m, const Value *type, Entry *out) {
  const Value *t = type;
  memset(out, 0, sizeof *out);
  while (t != NULL && t->kind == VAL_PI && out->param_count < ENTRY_PARAMS_MAX) {
    if (!val_is(t->dom, OP_NAT) && !val_is(t->dom, OP_FLAG) && !input_family(m, t->dom, 1))
      return 0;
    out->param_kind[out->param_count] = param_kind_of(t->dom);
    out->param_family[out->param_count] = t->dom->inst;
    t = closure_apply(m, t, val_var(m, out->param_count));
    out->param_count++;
  }
  out->result_flag = val_is(t, OP_FLAG);
  return val_is(t, OP_NAT) || val_is(t, OP_FLAG);
}

static int parse_u64(const char *s, uint64_t *out) {
  uint64_t n = 0;
  size_t i;
  if (s[0] == '\0')
    return 0;
  for (i = 0; s[i] != '\0'; i++) {
    unsigned d = (unsigned)(unsigned char)s[i] - (unsigned)'0';
    if (d > 9u || n > (UINT64_MAX - d) / 10u)
      return 0;
    n = n * 10u + d;
  }
  *out = n;
  return 1;
}

/* An entry argument: a ℕ in decimal, a Bool as 0 or 1, or an input in the
   pre-order form (input_value). */
static const Value *entry_arg(Machine *m, const char *text, EntryParam kind, uint32_t family) {
  uint64_t n = 0;
  const char *p = text;
  const Value *v = kind == ENTRY_PARAM_INPUT ? input_value(m, family, &p) : NULL;
  if (kind == ENTRY_PARAM_INPUT && (v == NULL || *p != '\0')) {
    diag_fail(m->diag, "EVAL_ARGS", m->def, "'%s' is not a %s (the tags and words in pre-order, comma-separated)", text,
              m->families[family].name);
    return NULL;
  }
  if (kind == ENTRY_PARAM_INPUT)
    return v;
  if (!parse_u64(text, &n) || (kind == ENTRY_PARAM_FLAG && n > 1u)) {
    diag_fail(m->diag, "EVAL_ARGS", m->def, "'%s' is not a %s", text,
              kind == ENTRY_PARAM_FLAG ? "Bool (0 or 1)" : "ℕ (0 to 2^64-1)");
    return NULL;
  }
  return kind == ENTRY_PARAM_FLAG ? val_make(m, n == 1u ? OP_FLAG_YES : OP_FLAG_NO, 0, 0, NULL, NULL, NULL) : val_nat(m, n);
}

static int print_result(Machine *m, const char *name, const Value *v, FILE *out, FILE *err) {
  switch (v->kind) {
  case VAL_NAT:
    fprintf(out, "%llu\n", (unsigned long long)v->nat);
    return 0;
  case VAL_TRAP:
    fputs("trap\n", out);
    fprintf(err, "langc: EVAL_OVERFLOW: %s: a ℕ operation overflowed past 2^64-1\n", name);
    return 0;
  case VAL_OP:
    if (val_is(v, OP_FLAG_YES) || val_is(v, OP_FLAG_NO)) {
      fprintf(out, "%d\n", val_is(v, OP_FLAG_YES));
      return 0;
    }
    break;
  case VAL_UNIV:
  case VAL_LAM:
  case VAL_PI:
  case VAL_SIGMA:
  case VAL_VAR:
  case VAL_APP:
  case VAL_STUCK:
    break;
  }
  diag_fail(m->diag, "EVAL_ENTRY", name, "the entry did not compute a number");
  return 1;
}

int eval_command(Machine *m, const char *name, char *const *args, int arg_count, FILE *out, FILE *err) {
  uint32_t d = find_def(m, name);
  Entry entry;
  const Value *v;
  char *buf;
  uint32_t i;
  m->def = name;
  if (d == NO_DEF) {
    diag_fail(m->diag, "EVAL_ENTRY", name, "no definition has this name");
    return 1;
  }
  v = def_value(m, d);
  if (v == NULL)
    return 1;
  if (!entry_of(m, m->defs[d].type, &entry) && arg_count != 0) {
    diag_fail(m->diag, "EVAL_ARGS", name, "the definition is not an entry, so it takes no arguments");
    return 2;
  }
  if (!entry_of(m, m->defs[d].type, &entry)) {
    buf = arena_alloc(m->arena, PRINT_MAX);
    if (buf == NULL)
      return diag_fail(m->diag, "OOM", name, "out of memory") + 1;
    if (!value_print(m, NULL, 0, v, buf, PRINT_MAX)) {
      diag_fail(m->diag, "EVAL_PRINT", name, "the normal form exceeds the printer limits");
      return 1;
    }
    fprintf(out, "%s\n", buf);
    return 0;
  }
  if ((uint32_t)arg_count != entry.param_count) {
    diag_fail(m->diag, "EVAL_ARGS", name, "the entry takes %u arguments, found %d", entry.param_count, arg_count);
    return 2;
  }
  for (i = 0; i < entry.param_count && v != NULL; i++) {
    const Value *arg = entry_arg(m, args[i], entry.param_kind[i], entry.param_family[i]);
    v = arg == NULL ? NULL : apply_value(m, v, arg);
  }
  if (v == NULL)
    return strcmp(m->diag->code != NULL ? m->diag->code : "", "EVAL_ARGS") == 0 ? 2 : 1;
  return print_result(m, name, v, out, err);
}
