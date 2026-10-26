/* The evaluator, the conversion test, quote and the printer (see
   front/core.h). SHARED by the tcc kits. */
#include "front/core.h"

#include <string.h>

#define PRINT_DEPTH_MAX 200u
#define PRINT_NAMES_MAX PRINT_DEPTH_MAX
#define VARIES 0xffu

static const char *const OP_NAMES[] = {
  [OP_NAT] = "ℕ", [OP_FLAG] = "Bool", [OP_UNIT] = "Unit",
  [OP_SUM] = "Sum", [OP_OPTION] = "Maybe", [OP_LIST] = "List",
  [OP_FAMILY] = "?", [OP_UNIT_VAL] = "unit", [OP_FLAG_YES] = "true",
  [OP_FLAG_NO] = "false", [OP_INL] = "inl", [OP_INR] = "inr",
  [OP_NONE] = "nothing", [OP_SOME] = "just", [OP_NIL] = "nil", [OP_CONS] = "cons",
  [OP_PACK] = "pack", [OP_CTOR] = "?",
  [OP_EITHER] = "either", [OP_OPTION_ELIM] = "option",
  [OP_PURE] = "pure", [OP_MAP] = "map", [OP_BIND] = "bind", [OP_FOLD_NAT] = "fold",
  [OP_FOLD_LIST] = "fold", [OP_FOLD_FAMILY] = "fold", [OP_UNFOLD] = "unfold",
  [OP_FILTER] = "filter", [OP_WITNESS] = "fst", [OP_PAYLOAD] = "snd",
  [OP_NAT_ADD] = "natAdd", [OP_NAT_SUB] = "natSub",
  [OP_NAT_MUL] = "natMul", [OP_NAT_EQ] = "natEq", [OP_NAT_LE] = "natLe",
  [OP_FLAG_IF] = "flagIf", [OP_PROJ] = "?", [OP_LEVEL] = "Level", [OP_SSET] = "SSet", [OP_I] = "I",
  [OP_I0] = "i0", [OP_I1] = "i1", [OP_INEG] = "~", [OP_IMIN] = "_∧_",
  [OP_IMAX] = "_∨_", [OP_PATHP] = "PathP", [OP_PLAM] = "λ", [OP_PAPP] = "@",
  [OP_PARTIAL] = "Partial", [OP_SYSTEM] = "system", [OP_SYSNIL] = "[]",
  [OP_FROMPARTIAL] = "fromPartial", [OP_TRANSP] = "primTransp",
  [OP_TPART] = "%tpart", [OP_TCOD] = "%tcod", [OP_HCOMP] = "primHComp",
  [OP_SYSMAP] = "%sysmap", [OP_PCTOR] = "?"
};

/* The number of arguments of each operation. VARIES: it comes from the
   family tables. */
static const unsigned char OP_ARITY[] = {
  [OP_NAT] = 0, [OP_FLAG] = 0, [OP_UNIT] = 0, [OP_SUM] = 2,
  [OP_OPTION] = 1, [OP_LIST] = 1, [OP_FAMILY] = VARIES,
  [OP_UNIT_VAL] = 0, [OP_FLAG_YES] = 0, [OP_FLAG_NO] = 0,
  [OP_INL] = 1, [OP_INR] = 1, [OP_NONE] = 0, [OP_SOME] = 1, [OP_NIL] = 0,
  [OP_CONS] = 2, [OP_PACK] = 2, [OP_CTOR] = VARIES, [OP_PCTOR] = VARIES,
  [OP_EITHER] = 3, [OP_OPTION_ELIM] = 3, [OP_PURE] = 1,
  [OP_MAP] = 2, [OP_BIND] = 2, [OP_FOLD_NAT] = 3, [OP_FOLD_LIST] = 3,
  [OP_FOLD_FAMILY] = VARIES, [OP_UNFOLD] = 3, [OP_FILTER] = 2, [OP_WITNESS] = 1,
  [OP_PAYLOAD] = 1,
  [OP_NAT_ADD] = 2, [OP_NAT_SUB] = 2, [OP_NAT_MUL] = 2,
  [OP_NAT_EQ] = 2, [OP_NAT_LE] = 2, [OP_FLAG_IF] = 3, [OP_PROJ] = 1,
  [OP_LEVEL] = 0, [OP_SSET] = 0, [OP_I] = 0, [OP_I0] = 0, [OP_I1] = 0, [OP_INEG] = 1,
  [OP_IMIN] = 2, [OP_IMAX] = 2, [OP_PATHP] = 3, [OP_PLAM] = 1, [OP_PAPP] = 4,
  [OP_PARTIAL] = 2, [OP_SYSTEM] = 3, [OP_SYSNIL] = 0, [OP_FROMPARTIAL] = 1,
  [OP_TRANSP] = 3, [OP_TPART] = 1, [OP_TCOD] = 2, [OP_HCOMP] = 4,
  [OP_SYSMAP] = 2
};

typedef enum {
  SCRUT_VALUE,
  SCRUT_TRAP,
  SCRUT_NEUTRAL
} Scrut;

typedef struct {
  const Value **items;
  uint32_t count;
  uint32_t cap;
} ValBuf;

/* A list value: its cons cells, then the end (nil, a trap or a neutral). */
typedef struct {
  const Value *const *cells;
  uint32_t count;
  const Value *tail;
} Spine;

static const Value *oom(Machine *m) {
  diag_fail(m->diag, "OOM", m->def, "the arena limit is reached");
  return NULL;
}

static const Value *internal(Machine *m, const char *what) {
  diag_fail(m->diag, "INTERNAL", m->def, "the evaluator found %s", what);
  return NULL;
}

static int spend(Machine *m, uint64_t steps) {
  if (m->fuel >= steps) {
    m->fuel -= steps;
    return 1;
  }
  m->fuel = 0;
  return diag_fail(m->diag, "EVAL_FUEL", m->def, "the evaluation takes more than %u steps", EVAL_FUEL_STEPS);
}

static int enter(Machine *m) {
  if (m->depth < EVAL_DEPTH_LIMIT) {
    m->depth++;
    return 1;
  }
  return diag_fail(m->diag, "EVAL_DEPTH", m->def, "the evaluation nests deeper than %u levels", EVAL_DEPTH_LIMIT);
}

static Value *new_value(Machine *m, ValKind kind) {
  Value *v = arena_alloc(m->arena, sizeof *v);
  if (v == NULL) {
    oom(m);
    return NULL;
  }
  v->kind = kind;
  return v;
}

const Value *val_nat(Machine *m, uint64_t n) {
  Value *v = new_value(m, VAL_NAT);
  if (v != NULL)
    v->nat = n;
  return v;
}

static const Value *val_trap(Machine *m) {
  return new_value(m, VAL_TRAP);
}

static const Value *overflow(Machine *m) {
  m->overflowed = 1;
  return val_trap(m);
}

const Value *val_var(Machine *m, uint32_t level) {
  Value *v = new_value(m, VAL_VAR);
  if (v != NULL)
    v->nat = level;
  if (level >= m->fresh_level)
    m->fresh_level = level + 1u;
  return v;
}

const Value *val_univ(Machine *m, uint64_t level) {
  Value *v = new_value(m, VAL_UNIV);
  if (v != NULL)
    v->nat = level;
  return v;
}

const Value *val_op(Machine *m, ValKind kind, Op op, uint32_t inst, uint32_t field, const Value *const *args, uint32_t argc) {
  const Value **copy;
  Value *v;
  uint32_t i;
  for (i = 0; i < argc; i++)
    if (args[i] == NULL)
      return NULL;
  copy = arena_alloc(m->arena, ((size_t)argc + 1u) * sizeof *copy);
  if (copy == NULL)
    return oom(m);
  v = new_value(m, kind);
  if (v == NULL)
    return NULL;
  for (i = 0; i < argc; i++)
    copy[i] = args[i];
  v->op = op;
  v->inst = inst;
  v->field = field;
  v->args = copy;
  v->argc = argc;
  return v;
}

static const Value *make(Machine *m, ValKind kind, Op op, uint32_t inst, uint32_t argc, const Value *a, const Value *b, const Value *c) {
  const Value *args[3];
  args[0] = a;
  args[1] = b;
  args[2] = c;
  return val_op(m, kind, op, inst, 0, args, argc);
}

const Value *val_make(Machine *m, Op op, uint32_t inst, uint32_t argc, const Value *a, const Value *b, const Value *c) {
  return make(m, VAL_OP, op, inst, argc, a, b, c);
}

static const Value *constant(Machine *m, Op op) {
  return make(m, VAL_OP, op, 0, 0, NULL, NULL, NULL);
}

static const Value *flag(Machine *m, int yes) {
  return constant(m, yes ? OP_FLAG_YES : OP_FLAG_NO);
}

const Value *val_arrow(Machine *m, const Value *dom, const Value *cod) {
  Value *v;
  if (dom == NULL || cod == NULL)
    return NULL;
  v = new_value(m, VAL_PI);
  if (v == NULL)
    return NULL;
  v->dom = dom;
  v->arg = cod;
  return v;
}

const Value *val_closure(Machine *m, ValKind kind, const char *name, const Value *dom, const Env *env, const Core *body) {
  Value *v;
  if (body == NULL || (dom == NULL && kind != VAL_LAM))
    return NULL;
  v = new_value(m, kind);
  if (v == NULL)
    return NULL;
  v->name = name;
  v->dom = dom;
  v->env = env;
  v->body = body;
  return v;
}

int val_is(const Value *v, Op op) {
  return v != NULL && v->kind == VAL_OP && v->op == op;
}

const Env *env_push(Machine *m, const Env *env, const Value *value) {
  Env *e;
  if (value == NULL)
    return NULL;
  e = arena_alloc(m->arena, sizeof *e);
  if (e == NULL) {
    oom(m);
    return NULL;
  }
  e->value = value;
  e->next = env;
  return e;
}

static const Value *env_lookup(Machine *m, const Env *env, uint32_t index) {
  uint32_t i;
  for (i = 0; i < index && env != NULL; i++)
    env = env->next;
  if (env == NULL)
    return internal(m, "a variable outside its scope");
  return env->value;
}

const Value *def_value(Machine *m, uint32_t index) {
  DefInfo *d;
  if (index >= m->def_count)
    return internal(m, "an unknown definition");
  d = &m->defs[index];
  if (d->value == NULL)
    d->value = eval_core(m, NULL, d->body);
  return d->value;
}

static Scrut scrut_of(const Value *v) {
  switch (v->kind) {
  case VAL_TRAP:
    return SCRUT_TRAP;
  case VAL_VAR:
  case VAL_APP:
  case VAL_STUCK:
    return SCRUT_NEUTRAL;
  case VAL_NAT:
  case VAL_UNIV:
  case VAL_LAM:
  case VAL_PI:
  case VAL_SIGMA:
  case VAL_OP:
    return SCRUT_VALUE;
  }
  return SCRUT_VALUE;
}

/* 1 when the scrutinee S stops the operation: a trap gives the trap, a
   neutral S gives the stuck operation. */
static int blocked(Machine *m, const Value *s, Op op, uint32_t inst, uint32_t field, const Value *const *a, uint32_t n, const Value **out) {
  switch (scrut_of(s)) {
  case SCRUT_TRAP:
    *out = s;
    return 1;
  case SCRUT_NEUTRAL:
    *out = val_op(m, VAL_STUCK, op, inst, field, a, n);
    return 1;
  case SCRUT_VALUE:
    return 0;
  }
  return 0;
}

static void buf_init(ValBuf *buf) {
  buf->items = NULL;
  buf->count = 0;
  buf->cap = 0;
}

static int buf_push(Machine *m, ValBuf *buf, const Value *v) {
  const Value **grown;
  uint32_t cap;
  uint32_t i;
  if (v == NULL)
    return 0;
  if (buf->count < buf->cap) {
    buf->items[buf->count++] = v;
    return 1;
  }
  cap = buf->cap == 0 ? 16u : buf->cap * 2u;
  grown = arena_alloc(m->arena, (size_t)cap * sizeof *grown);
  if (grown == NULL) {
    oom(m);
    return 0;
  }
  for (i = 0; i < buf->count; i++)
    grown[i] = buf->items[i];
  buf->items = grown;
  buf->cap = cap;
  buf->items[buf->count++] = v;
  return 1;
}

static int spine_of(Machine *m, const Value *xs, Spine *out) {
  ValBuf cells;
  buf_init(&cells);
  while (val_is(xs, OP_CONS)) {
    if (!buf_push(m, &cells, xs) || !spend(m, 1))
      return 0;
    xs = xs->args[1];
  }
  out->cells = cells.items;
  out->count = cells.count;
  out->tail = xs;
  return xs != NULL;
}

static const Value *build_list(Machine *m, const Value *const *items, uint32_t count, const Value *tail) {
  const Value *acc = tail;
  uint32_t i;
  for (i = count; i > 0 && acc != NULL; i--)
    acc = make(m, VAL_OP, OP_CONS, 0, 2, items[i - 1u], acc, NULL);
  return acc;
}

/* The end of a list result: nil stays nil, a trap stays a trap, a neutral
   end gives OP FIRST END. */
static const Value *list_tail(Machine *m, const Value *tail, Op op, uint32_t inst, const Value *first) {
  switch (scrut_of(tail)) {
  case SCRUT_TRAP:
    return tail;
  case SCRUT_NEUTRAL:
    return make(m, VAL_STUCK, op, inst, 2, first, tail, NULL);
  case SCRUT_VALUE:
    break;
  }
  return val_is(tail, OP_NIL) ? tail : internal(m, "a list that does not end in nil");
}

const Value *apply_value(Machine *m, const Value *fn, const Value *arg) {
  Value *v;
  if (fn == NULL || arg == NULL)
    return NULL;
  switch (fn->kind) {
  case VAL_LAM:
    return closure_apply(m, fn, arg);
  case VAL_TRAP:
    return fn;
  case VAL_VAR:
  case VAL_APP:
  case VAL_STUCK:
    v = new_value(m, VAL_APP);
    if (v == NULL)
      return NULL;
    v->dom = fn;
    v->arg = arg;
    return v;
  case VAL_NAT:
  case VAL_UNIV:
  case VAL_PI:
  case VAL_SIGMA:
  case VAL_OP:
    break;
  }
  return internal(m, "an application of a value that is not a function");
}

const Value *closure_apply(Machine *m, const Value *binder, const Value *arg) {
  const Env *env;
  if (binder == NULL || arg == NULL)
    return NULL;
  if (binder->body == NULL)
    return binder->arg;
  env = env_push(m, binder->env, arg);
  if (env == NULL)
    return NULL;
  return eval_core(m, env, binder->body);
}

static const Value *reduce_part(Machine *m, Op op, const Value *const *a, uint32_t n, Op ctor, uint32_t index) {
  const Value *out;
  if (blocked(m, a[0], op, 0, 0, a, n, &out))
    return out;
  if (!val_is(a[0], ctor))
    return internal(m, "a projection of a value of the wrong type");
  return a[0]->args[index];
}

static const Value *reduce_either(Machine *m, const Value *const *a, uint32_t n) {
  const Value *out;
  if (blocked(m, a[2], OP_EITHER, 0, 0, a, n, &out))
    return out;
  if (val_is(a[2], OP_INL))
    return apply_value(m, a[0], a[2]->args[0]);
  if (val_is(a[2], OP_INR))
    return apply_value(m, a[1], a[2]->args[0]);
  return internal(m, "an either of a value that is not a Sum");
}

static const Value *reduce_option(Machine *m, const Value *const *a, uint32_t n) {
  const Value *out;
  if (blocked(m, a[2], OP_OPTION_ELIM, 0, 0, a, n, &out))
    return out;
  if (val_is(a[2], OP_NONE))
    return a[0];
  if (val_is(a[2], OP_SOME))
    return apply_value(m, a[1], a[2]->args[0]);
  return internal(m, "an option of a value that is not a Maybe");
}

static const Value *reduce_pure(Machine *m, uint32_t inst, const Value *x) {
  switch ((Carrier)inst) {
  case CARRIER_OPTION:
    return make(m, VAL_OP, OP_SOME, 0, 1, x, NULL, NULL);
  case CARRIER_LIST:
    return make(m, VAL_OP, OP_CONS, 0, 2, x, constant(m, OP_NIL), NULL);
  case CARRIER_SUM:
    return make(m, VAL_OP, OP_INR, 0, 1, x, NULL, NULL);
  }
  return internal(m, "an unknown carrier");
}

static const Value *map_list(Machine *m, const Value *f, const Value *xs) {
  Spine s;
  ValBuf out;
  uint32_t i;
  if (!spine_of(m, xs, &s))
    return NULL;
  buf_init(&out);
  for (i = 0; i < s.count; i++)
    if (!buf_push(m, &out, apply_value(m, f, s.cells[i]->args[0])))
      return NULL;
  return build_list(m, out.items, out.count, list_tail(m, s.tail, OP_MAP, CARRIER_LIST, f));
}

static const Value *reduce_map(Machine *m, uint32_t inst, const Value *const *a, uint32_t n) {
  const Value *x = a[1];
  const Value *out;
  if (blocked(m, x, OP_MAP, inst, 0, a, n, &out))
    return out;
  switch ((Carrier)inst) {
  case CARRIER_OPTION:
    return val_is(x, OP_SOME) ? make(m, VAL_OP, OP_SOME, 0, 1, apply_value(m, a[0], x->args[0]), NULL, NULL) : x;
  case CARRIER_SUM:
    return val_is(x, OP_INR) ? make(m, VAL_OP, OP_INR, 0, 1, apply_value(m, a[0], x->args[0]), NULL, NULL) : x;
  case CARRIER_LIST:
    return map_list(m, a[0], x);
  }
  return internal(m, "an unknown carrier");
}

static int buf_append(Machine *m, ValBuf *buf, const Spine *s) {
  uint32_t i;
  for (i = 0; i < s->count; i++)
    if (!buf_push(m, buf, s->cells[i]->args[0]))
      return 0;
  return 1;
}

/* A list bind concatenates the lists F X. A neutral end in any of them
   leaves the whole bind stuck. */
static const Value *bind_list(Machine *m, const Value *const *a, uint32_t n) {
  Spine s;
  Spine t;
  ValBuf out;
  uint32_t i;
  if (!spine_of(m, a[0], &s))
    return NULL;
  if (scrut_of(s.tail) == SCRUT_NEUTRAL)
    return val_op(m, VAL_STUCK, OP_BIND, CARRIER_LIST, 0, a, n);
  buf_init(&out);
  for (i = 0; i < s.count; i++) {
    if (!spine_of(m, apply_value(m, a[1], s.cells[i]->args[0]), &t) || !buf_append(m, &out, &t))
      return NULL;
    if (scrut_of(t.tail) == SCRUT_NEUTRAL)
      return val_op(m, VAL_STUCK, OP_BIND, CARRIER_LIST, 0, a, n);
    if (scrut_of(t.tail) == SCRUT_TRAP)
      return build_list(m, out.items, out.count, t.tail);
  }
  return build_list(m, out.items, out.count, list_tail(m, s.tail, OP_BIND, CARRIER_LIST, a[1]));
}

static const Value *reduce_bind(Machine *m, uint32_t inst, const Value *const *a, uint32_t n) {
  const Value *x = a[0];
  const Value *out;
  if (blocked(m, x, OP_BIND, inst, 0, a, n, &out))
    return out;
  switch ((Carrier)inst) {
  case CARRIER_OPTION:
    return val_is(x, OP_SOME) ? apply_value(m, a[1], x->args[0]) : x;
  case CARRIER_SUM:
    return val_is(x, OP_INR) ? apply_value(m, a[1], x->args[0]) : x;
  case CARRIER_LIST:
    return bind_list(m, a, n);
  }
  return internal(m, "an unknown carrier");
}

/* fold step z n: step applied n times to z. */
static const Value *reduce_fold_nat(Machine *m, const Value *const *a, uint32_t n) {
  const Value *acc = a[1];
  const Value *out;
  uint64_t k;
  if (blocked(m, a[2], OP_FOLD_NAT, 0, 0, a, n, &out))
    return out;
  if (a[2]->kind != VAL_NAT)
    return internal(m, "a fold of a value that is not a ℕ");
  for (k = 0; k < a[2]->nat && acc != NULL; k++)
    acc = spend(m, 1) ? apply_value(m, a[0], acc) : NULL;
  return acc;
}

/* fold f z xs: the right fold. The end of the list is folded first. */
static const Value *reduce_fold_list(Machine *m, const Value *const *a) {
  const Value *acc = NULL;
  Spine s;
  uint32_t i;
  if (!spine_of(m, a[2], &s))
    return NULL;
  switch (scrut_of(s.tail)) {
  case SCRUT_TRAP:
    acc = s.tail;
    break;
  case SCRUT_NEUTRAL:
    acc = make(m, VAL_STUCK, OP_FOLD_LIST, 0, 3, a[0], a[1], s.tail);
    break;
  case SCRUT_VALUE:
    acc = val_is(s.tail, OP_NIL) ? a[1] : internal(m, "a list that does not end in nil");
    break;
  }
  for (i = s.count; i > 0 && acc != NULL; i--)
    acc = apply_value(m, apply_value(m, a[0], s.cells[i - 1u]->args[0]), acc);
  return acc;
}

static const Value *stuck_fold(Machine *m, uint32_t family, const Value *const *cases, uint32_t ncases, const Value *x) {
  const Value **args = arena_alloc(m->arena, ((size_t)ncases + 1u) * sizeof *args);
  uint32_t i;
  if (args == NULL)
    return oom(m);
  for (i = 0; i < ncases; i++)
    args[i] = cases[i];
  args[ncases] = x;
  return val_op(m, VAL_STUCK, OP_FOLD_FAMILY, family, 0, args, ncases + 1u);
}

/* fold case... x over a domain family: the case of the constructor of X,
   applied to its fields. A recursive field arrives folded. */
static const Value *fold_family(Machine *m, uint32_t family, const Value *const *cases, uint32_t ncases, const Value *x) {
  const FamilyInfo *fam;
  const CtorInfo *ctor;
  const Value *acc;
  const Value *field;
  uint32_t i;
  if (x == NULL)
    return NULL;
  switch (scrut_of(x)) {
  case SCRUT_TRAP:
    return x;
  case SCRUT_NEUTRAL:
    return stuck_fold(m, family, cases, ncases, x);
  case SCRUT_VALUE:
    break;
  }
  if (!val_is(x, OP_CTOR) || x->inst >= m->ctor_count || family >= m->family_count)
    return internal(m, "a fold of a value that is not in the family");
  fam = &m->families[family];
  ctor = &m->ctors[x->inst];
  if (x->inst < fam->first_ctor || x->inst - fam->first_ctor >= ncases || x->argc != fam->param_count + ctor->field_count)
    return internal(m, "a fold of a constructor of another family");
  if (!enter(m))
    return NULL;
  acc = cases[x->inst - fam->first_ctor];
  for (i = 0; i < ctor->field_count && acc != NULL; i++) {
    field = x->args[fam->param_count + i];
    acc = apply_value(m, acc, ctor->fields[i].recursive ? fold_family(m, family, cases, ncases, field) : field);
  }
  m->depth--;
  return acc;
}

/* 1 when the step result R ends the list. *TAIL is then the end. */
static int unfold_end(Machine *m, const Value *g, uint64_t left, const Value *seed, const Value *r, const Value **tail) {
  const Value *p = val_is(r, OP_SOME) ? r->args[0] : r;
  if (val_is(r, OP_NONE)) {
    *tail = constant(m, OP_NIL);
    return 1;
  }
  switch (scrut_of(p)) {
  case SCRUT_TRAP:
    *tail = p;
    return 1;
  case SCRUT_NEUTRAL:
    *tail = make(m, VAL_STUCK, OP_UNFOLD, 0, 3, g, val_nat(m, left), seed);
    return 1;
  case SCRUT_VALUE:
    break;
  }
  if (val_is(p, OP_PACK))
    return 0;
  *tail = internal(m, "an unfold step that is not a Maybe of a pair");
  return 1;
}

/* unfold g limit seed: at most LIMIT elements. */
static const Value *reduce_unfold(Machine *m, const Value *const *a, uint32_t n) {
  const Value *seed = a[2];
  const Value *out;
  const Value *r;
  const Value *tail = NULL;
  ValBuf items;
  uint64_t i;
  if (blocked(m, a[1], OP_UNFOLD, 0, 0, a, n, &out))
    return out;
  if (a[1]->kind != VAL_NAT)
    return internal(m, "an unfold limit that is not a ℕ");
  buf_init(&items);
  for (i = 0; i < a[1]->nat; i++) {
    r = spend(m, 1) ? apply_value(m, a[0], seed) : NULL;
    if (r == NULL)
      return NULL;
    if (unfold_end(m, a[0], a[1]->nat - i, seed, r, &tail))
      return build_list(m, items.items, items.count, tail);
    if (!buf_push(m, &items, r->args[0]->args[0]))
      return NULL;
    seed = r->args[0]->args[1];
  }
  return build_list(m, items.items, items.count, constant(m, OP_NIL));
}

static const Value *filter_option(Machine *m, const Value *const *a, uint32_t n) {
  const Value *test;
  const Value *out;
  if (!val_is(a[1], OP_SOME))
    return a[1];
  test = apply_value(m, a[0], a[1]->args[0]);
  if (test == NULL)
    return NULL;
  if (blocked(m, test, OP_FILTER, CARRIER_OPTION, 0, a, n, &out))
    return out;
  return val_is(test, OP_FLAG_YES) ? a[1] : constant(m, OP_NONE);
}

static const Value *filter_list(Machine *m, const Value *const *a) {
  const Value *test;
  Spine s;
  ValBuf kept;
  uint32_t i;
  if (!spine_of(m, a[1], &s))
    return NULL;
  buf_init(&kept);
  for (i = 0; i < s.count; i++) {
    test = apply_value(m, a[0], s.cells[i]->args[0]);
    if (test == NULL)
      return NULL;
    switch (scrut_of(test)) {
    case SCRUT_TRAP:
      return build_list(m, kept.items, kept.count, test);
    case SCRUT_NEUTRAL:
      return build_list(m, kept.items, kept.count, make(m, VAL_STUCK, OP_FILTER, CARRIER_LIST, 2, a[0], s.cells[i], NULL));
    case SCRUT_VALUE:
      break;
    }
    if (val_is(test, OP_FLAG_YES) && !buf_push(m, &kept, s.cells[i]->args[0]))
      return NULL;
  }
  return build_list(m, kept.items, kept.count, list_tail(m, s.tail, OP_FILTER, CARRIER_LIST, a[0]));
}

static const Value *reduce_filter(Machine *m, uint32_t inst, const Value *const *a, uint32_t n) {
  const Value *out;
  if (blocked(m, a[1], OP_FILTER, inst, 0, a, n, &out))
    return out;
  switch ((Carrier)inst) {
  case CARRIER_OPTION:
    return filter_option(m, a, n);
  case CARRIER_LIST:
    return filter_list(m, a);
  case CARRIER_SUM:
    break;
  }
  return internal(m, "a filter with no instance");
}

/* 1 when both arguments are numbers. Else *OUT is the trap or the stuck
   operation. */
static int nat_args(Machine *m, Op op, const Value *const *a, uint32_t n, uint64_t *x, uint64_t *y, const Value **out) {
  *out = a[0]->kind == VAL_TRAP ? a[0] : a[1];
  if (a[0]->kind == VAL_TRAP || a[1]->kind == VAL_TRAP)
    return 0;
  if (blocked(m, a[0], op, 0, 0, a, n, out) || blocked(m, a[1], op, 0, 0, a, n, out))
    return 0;
  if (a[0]->kind != VAL_NAT || a[1]->kind != VAL_NAT) {
    *out = internal(m, "a ℕ operation on a value that is not a ℕ");
    return 0;
  }
  *x = a[0]->nat;
  *y = a[1]->nat;
  return 1;
}

static const Value *nat_add(Machine *m, const Value *const *a, uint32_t n) {
  const Value *out;
  uint64_t x = 0;
  uint64_t y = 0;
  if (!nat_args(m, OP_NAT_ADD, a, n, &x, &y, &out))
    return out;
  return x + y < x ? overflow(m) : val_nat(m, x + y);
}

static const Value *nat_sub(Machine *m, const Value *const *a, uint32_t n) {
  const Value *out;
  uint64_t x = 0;
  uint64_t y = 0;
  if (!nat_args(m, OP_NAT_SUB, a, n, &x, &y, &out))
    return out;
  return val_nat(m, x < y ? 0 : x - y);
}

static const Value *nat_mul(Machine *m, const Value *const *a, uint32_t n) {
  const Value *out;
  uint64_t x = 0;
  uint64_t y = 0;
  if (!nat_args(m, OP_NAT_MUL, a, n, &x, &y, &out))
    return out;
  return y != 0 && x > UINT64_MAX / y ? overflow(m) : val_nat(m, x * y);
}

static const Value *nat_test(Machine *m, Op op, const Value *const *a, uint32_t n) {
  const Value *out;
  uint64_t x = 0;
  uint64_t y = 0;
  if (!nat_args(m, op, a, n, &x, &y, &out))
    return out;
  return flag(m, op == OP_NAT_EQ ? x == y : x <= y);
}

static const Value *reduce_flag_if(Machine *m, const Value *const *a, uint32_t n) {
  const Value *out;
  if (blocked(m, a[0], OP_FLAG_IF, 0, 0, a, n, &out))
    return out;
  if (val_is(a[0], OP_FLAG_YES))
    return a[1];
  if (val_is(a[0], OP_FLAG_NO))
    return a[2];
  return internal(m, "a flagIf of a value that is not a Bool");
}

static const Value *reduce_proj(Machine *m, uint32_t inst, uint32_t field, const Value *const *a, uint32_t n) {
  const Value *x = a[0];
  const Value *out;
  uint32_t at;
  if (blocked(m, x, OP_PROJ, inst, field, a, n, &out))
    return out;
  if (!val_is(x, OP_CTOR) || x->inst != inst || inst >= m->ctor_count || m->ctors[inst].family >= m->family_count)
    return internal(m, "a projection of a value of the wrong family");
  at = m->families[m->ctors[inst].family].param_count + field;
  return at < x->argc ? x->args[at] : internal(m, "a projection of a missing field");
}

/* The interval (former C1). A value of type I in normal form is a join of
   meets of literals. A literal names a variable or neutral atom, plus its
   polarity. De Morgan
   laws only: `i /\ ~ i` stays. */
#define DNF_CONJ_MAX FACE_MEETS_MAX
#define DNF_LIT_MAX FACE_LITS_MAX

typedef struct {
  uint32_t lit[DNF_CONJ_MAX][DNF_LIT_MAX];
  uint32_t len[DNF_CONJ_MAX];
  uint32_t count;
} Dnf;

/* Neutral interval terms, including applications and projections, are atoms.
   The table is local: endpoint metadata must stay with the original value. */
typedef struct {
  Machine *m;
  uint32_t level;
  ValBuf atoms;
} DnfCtx;

/* Adds the meet of the literals X and Y to D. */
static int dnf_conj(Dnf *d, const uint32_t *x, uint32_t nx, const uint32_t *y, uint32_t ny) {
  uint32_t i;
  if (d->count >= DNF_CONJ_MAX || nx + ny > DNF_LIT_MAX)
    return 0;
  for (i = 0; i < nx; i++)
    d->lit[d->count][i] = x[i];
  for (i = 0; i < ny; i++)
    d->lit[d->count][nx + i] = y[i];
  d->len[d->count] = nx + ny;
  d->count++;
  return 1;
}

static int dnf_meet(const Dnf *x, const Dnf *y, Dnf *out) {
  uint32_t i;
  uint32_t j;
  out->count = 0;
  for (i = 0; i < x->count; i++)
    for (j = 0; j < y->count; j++)
      if (!dnf_conj(out, x->lit[i], x->len[i], y->lit[j], y->len[j]))
        return 0;
  return 1;
}

static int dnf_join(const Dnf *x, const Dnf *y, Dnf *out) {
  uint32_t i;
  *out = *x;
  for (i = 0; i < y->count; i++)
    if (!dnf_conj(out, y->lit[i], y->len[i], NULL, 0))
      return 0;
  return 1;
}

/* ~ (c1 \/ c2) = ~ c1 /\ ~ c2 and ~ (l1 /\ l2) = ~ l1 \/ ~ l2. */
static int dnf_neg(const Dnf *x, Dnf *out) {
  Dnf acc;
  Dnf one;
  uint32_t i;
  uint32_t j;
  uint32_t lit;
  acc.count = 0;
  if (!dnf_conj(&acc, NULL, 0, NULL, 0))
    return 0;
  for (i = 0; i < x->count; i++) {
    one.count = 0;
    for (j = 0; j < x->len[i]; j++) {
      lit = x->lit[i][j] ^ 1u;
      if (!dnf_conj(&one, &lit, 1, NULL, 0))
        return 0;
    }
    if (!dnf_meet(&acc, &one, out))
      return 0;
    acc = *out;
  }
  *out = acc;
  return 1;
}

/* 0 when V is not an interval value in normal form. */
static int dnf_of(DnfCtx *ctx, const Value *v, Dnf *d) {
  Dnf x;
  Dnf y;
  uint32_t lit;
  d->count = 0;
  if (v == NULL)
    return 0;
  if (v->kind == VAL_VAR || (val_is(v, OP_INEG) && v->args[0]->kind == VAL_VAR)) {
    lit = v->kind == VAL_VAR ? (uint32_t)v->nat * 2u : (uint32_t)v->args[0]->nat * 2u + 1u;
    return dnf_conj(d, &lit, 1, NULL, 0);
  }
  if (val_is(v, OP_I0))
    return 1;
  if (val_is(v, OP_I1))
    return dnf_conj(d, NULL, 0, NULL, 0);
  if (val_is(v, OP_INEG))
    return dnf_of(ctx, v->args[0], &x) && dnf_neg(&x, d);
  if (!val_is(v, OP_IMIN) && !val_is(v, OP_IMAX)) {
    uint32_t i;
    if (scrut_of(v) != SCRUT_NEUTRAL)
      return 0;
    for (i = 0; i < ctx->atoms.count; i++)
      if (conv_values(ctx->m, ctx->level, v, ctx->atoms.items[i]))
        break;
    if (i == ctx->atoms.count && !buf_push(ctx->m, &ctx->atoms, v))
      return 0;
    lit = (ctx->level + i) * 2u;
    return dnf_conj(d, &lit, 1, NULL, 0);
  }
  if (!dnf_of(ctx, v->args[0], &x) || !dnf_of(ctx, v->args[1], &y))
    return 0;
  return val_is(v, OP_IMIN) ? dnf_meet(&x, &y, d) : dnf_join(&x, &y, d);
}

/* Sorts the literals A and removes the duplicates. */
static uint32_t lits_norm(uint32_t *a, uint32_t n) {
  uint32_t i;
  uint32_t j;
  uint32_t k = 0;
  uint32_t t;
  for (i = 1; i < n; i++)
    for (j = i; j > 0 && a[j - 1u] > a[j]; j--) {
      t = a[j];
      a[j] = a[j - 1u];
      a[j - 1u] = t;
    }
  for (i = 0; i < n; i++)
    if (k == 0 || a[k - 1u] != a[i])
      a[k++] = a[i];
  return k;
}

/* 1 when each literal of X is in Y. Both are sorted. */
static int lits_sub(const uint32_t *x, uint32_t nx, const uint32_t *y, uint32_t ny) {
  uint32_t i = 0;
  uint32_t j;
  for (j = 0; i < nx && j < ny; j++)
    i += x[i] == y[j] ? 1u : 0u;
  return i == nx;
}

static int lits_cmp(const uint32_t *x, uint32_t nx, const uint32_t *y, uint32_t ny) {
  uint32_t i;
  for (i = 0; i < nx && i < ny; i++)
    if (x[i] != y[i])
      return x[i] < y[i] ? -1 : 1;
  return nx == ny ? 0 : (nx < ny ? -1 : 1);
}

/* Removes each meet that another meet absorbs. */
static int dnf_norm(Dnf *d, Dnf *out) {
  uint32_t i;
  uint32_t j;
  int keep;
  int sub;
  out->count = 0;
  for (i = 0; i < d->count; i++)
    d->len[i] = lits_norm(d->lit[i], d->len[i]);
  for (i = 0; i < d->count; i++) {
    keep = 1;
    for (j = 0; j < d->count && keep; j++) {
      sub = j != i && lits_sub(d->lit[j], d->len[j], d->lit[i], d->len[i]);
      keep = !sub || (lits_cmp(d->lit[j], d->len[j], d->lit[i], d->len[i]) == 0 && j > i);
    }
    if (keep && !dnf_conj(out, d->lit[i], d->len[i], NULL, 0))
      return 0;
  }
  return 1;
}

static const Value *lit_value(DnfCtx *ctx, uint32_t lit) {
  Machine *m = ctx->m;
  uint32_t level = lit / 2u;
  const Value *x = level < ctx->level ? val_var(m, level) : ctx->atoms.items[level - ctx->level];
  return lit % 2u == 0 ? x : make(m, VAL_OP, OP_INEG, 0, 1, x, NULL, NULL);
}

static const Value *conj_value(DnfCtx *ctx, const uint32_t *lits, uint32_t n) {
  Machine *m = ctx->m;
  const Value *acc = lit_value(ctx, lits[n - 1u]);
  uint32_t i;
  for (i = n - 1u; i > 0; i--)
    acc = make(m, VAL_OP, OP_IMIN, 0, 2, lit_value(ctx, lits[i - 1u]), acc, NULL);
  return acc;
}

/* An interval value for D, using the atom table's literal order for the
   right-nested meets and joins. */
static const Value *dnf_value(DnfCtx *ctx, const Dnf *d) {
  Machine *m = ctx->m;
  uint32_t order[DNF_CONJ_MAX];
  uint32_t i;
  uint32_t j;
  uint32_t t;
  const Value *acc;
  if (d->count == 0)
    return constant(m, OP_I0);
  for (i = 0; i < d->count; i++) {
    if (d->len[i] == 0)
      return constant(m, OP_I1);
    order[i] = i;
  }
  for (i = 1; i < d->count; i++)
    for (j = i; j > 0 && lits_cmp(d->lit[order[j - 1u]], d->len[order[j - 1u]], d->lit[order[j]], d->len[order[j]]) > 0; j--) {
      t = order[j];
      order[j] = order[j - 1u];
      order[j - 1u] = t;
    }
  acc = conj_value(ctx, d->lit[order[d->count - 1u]], d->len[order[d->count - 1u]]);
  for (i = d->count - 1u; i > 0; i--)
    acc = make(m, VAL_OP, OP_IMAX, 0, 2, conj_value(ctx, d->lit[order[i - 1u]], d->len[order[i - 1u]]), acc, NULL);
  return acc;
}

static int dnf_apply(Op op, const Dnf *x, const Dnf *y, Dnf *out) {
  if (op == OP_INEG)
    return dnf_neg(x, out);
  return op == OP_IMIN ? dnf_meet(x, y, out) : dnf_join(x, y, out);
}

/* ~ r, r /\ s and r \/ s. A value outside the normal form stays as it is. */
static const Value *reduce_interval(Machine *m, Op op, const Value *const *a, uint32_t n) {
  DnfCtx ctx;
  Dnf x;
  Dnf y;
  Dnf d;
  Dnf out;
  ctx.m = m;
  ctx.level = m->fresh_level;
  buf_init(&ctx.atoms);
  y.count = 0;
  if (!dnf_of(&ctx, a[0], &x) || (n == 2u && !dnf_of(&ctx, a[1], &y)) || !dnf_apply(op, &x, &y, &d) || !dnf_norm(&d, &out))
    return val_op(m, VAL_OP, op, 0, 0, a, n);
  return dnf_value(&ctx, &out);
}

/* 1 when X and Y hold the same meets. Both are in normal form. */
static int dnf_same(const Dnf *x, const Dnf *y) {
  uint32_t i;
  uint32_t j;
  if (x->count != y->count)
    return 0;
  for (i = 0; i < x->count; i++) {
    for (j = 0; j < y->count; j++)
      if (lits_cmp(x->lit[i], x->len[i], y->lit[j], y->len[j]) == 0)
        break;
    if (j == y->count)
      return 0;
  }
  return 1;
}

static void face_ctx(DnfCtx *ctx, Machine *m, uint32_t level) {
  ctx->m = m;
  ctx->level = m->fresh_level > level ? m->fresh_level : level;
  buf_init(&ctx->atoms);
}

/* The face normal form (former C1): `i /\ ~ i` is the empty face. The
   literals of a meet are sorted, so 2k and 2k + 1 are next to each other. */
static int face_norm(DnfCtx *ctx, const Value *v, Dnf *out) {
  Dnf d;
  Dnf n;
  uint32_t i;
  uint32_t j;
  int empty;
  out->count = 0;
  if (!dnf_of(ctx, v, &d) || !dnf_norm(&d, &n))
    return 0;
  for (i = 0; i < n.count; i++) {
    empty = 0;
    for (j = 0; j + 1u < n.len[i]; j++)
      empty = empty || (n.lit[i][j] % 2u == 0 && n.lit[i][j + 1u] == n.lit[i][j] + 1u);
    if (!empty && !dnf_conj(out, n.lit[i], n.len[i], NULL, 0))
      return 0;
  }
  return 1;
}

static int dnf_holds(const Dnf *d) {
  uint32_t i;
  for (i = 0; i < d->count; i++)
    if (d->len[i] == 0)
      return 1;
  return 0;
}

int face_holds(Machine *m, uint32_t level, const Value *phi) {
  DnfCtx ctx;
  Dnf d;
  face_ctx(&ctx, m, level);
  return face_norm(&ctx, phi, &d) && dnf_holds(&d);
}

int face_equal(Machine *m, uint32_t level, const Value *a, const Value *b) {
  DnfCtx ctx;
  Dnf x;
  Dnf y;
  face_ctx(&ctx, m, level);
  return face_norm(&ctx, a, &x) && face_norm(&ctx, b, &y) && dnf_same(&x, &y);
}


int face_meets(Machine *m, uint32_t level, const Value *phi, FaceMeets *out) {
  DnfCtx ctx;
  Dnf d;
  uint32_t i;
  uint32_t j;
  face_ctx(&ctx, m, level);
  out->count = 0;
  if (!face_norm(&ctx, phi, &d))
    return 0;
  for (i = 0; i < d.count; i++) {
    out->len[i] = 0;
    for (j = 0; j < d.len[i]; j++)
      if (d.lit[i][j] / 2u < ctx.level)
        out->lit[i][out->len[i]++] = d.lit[i][j];
  }
  out->count = d.count;
  return 1;
}

/* Compare with a shared atom table; separate reductions can encounter neutral
   atoms in different orders. -1 leaves terms outside the DNF bounds structural. */
static int conv_interval(Machine *m, uint32_t level, const Value *a, const Value *b) {
  DnfCtx ctx;
  Dnf x;
  Dnf y;
  Dnf nx;
  Dnf ny;
  face_ctx(&ctx, m, level);
  if (!dnf_of(&ctx, a, &x) || !dnf_of(&ctx, b, &y)
      || !dnf_norm(&x, &nx) || !dnf_norm(&y, &ny))
    return -1;
  return dnf_same(&nx, &ny);
}

/* p @ r with the endpoints a[2] and a[3] of the type of p (former C2). */
static const Value *reduce_papp(Machine *m, const Value *const *a, uint32_t n) {
  if (val_is(a[1], OP_I0))
    return a[2];
  if (val_is(a[1], OP_I1))
    return a[3];
  if (val_is(a[0], OP_PLAM))
    return apply_value(m, a[0]->args[0], a[1]);
  return val_op(m, VAL_STUCK, OP_PAPP, 0, 0, a, n);
}

/* A path constructor at an end of a dimension is that end (D10). The
   arguments are the params and the fields, then one interval for each
   dimension. */
static const Value *reduce_pctor(Machine *m, uint32_t inst, const Value *const *a, uint32_t n) {
  const CtorInfo *ci = inst < m->ctor_count ? &m->ctors[inst] : NULL;
  const Env *env = NULL;
  const Value *pa[4];
  uint32_t d = ci != NULL ? ci->depth : 0u;
  uint32_t k;
  uint32_t i;
  if (ci == NULL || ci->ends == NULL || d == 0u || d > 2u || d > n)
    return internal(m, "a path constructor without ends");
  k = n - d;
  for (i = 0; i < k; i++)
    env = env_push(m, env, a[i]);
  if (d == 1u && (val_is(a[k], OP_I0) || val_is(a[k], OP_I1)))
    return eval_core(m, env, ci->ends[val_is(a[k], OP_I1) ? 1 : 0]);
  if (d == 2u && (val_is(a[k], OP_I0) || val_is(a[k], OP_I1))) {
    pa[0] = eval_core(m, env, ci->ends[val_is(a[k], OP_I1) ? 1 : 0]);
    pa[1] = a[k + 1u];
    pa[2] = eval_core(m, env, ci->ends[2]);
    pa[3] = eval_core(m, env, ci->ends[3]);
    return reduce_papp(m, pa, 4);
  }
  if (d == 2u && (val_is(a[k + 1u], OP_I0) || val_is(a[k + 1u], OP_I1)))
    return eval_core(m, env, ci->ends[val_is(a[k + 1u], OP_I1) ? 3 : 2]);
  return val_op(m, VAL_OP, OP_PCTOR, inst, 0, a, n);
}

/* Keep a total cell around its branch so Partial values stay distinct from
   their payloads, including neutral payloads. Empty faces drop out. */
static const Value *reduce_system(Machine *m, const Value *const *a, uint32_t n) {
  DnfCtx ctx;
  Dnf d;
  const Value *total[3];
  face_ctx(&ctx, m, 0);
  if (!face_norm(&ctx, a[0], &d))
    return val_op(m, VAL_OP, OP_SYSTEM, 0, 0, a, n);
  if (dnf_holds(&d)) {
    total[0] = constant(m, OP_I1);
    total[1] = a[1];
    total[2] = constant(m, OP_SYSNIL);
    return val_op(m, VAL_OP, OP_SYSTEM, 0, 0, total, 3);
  }
  if (val_is(a[2], OP_SYSTEM) && face_holds(m, 0, a[2]->args[0]))
    return a[2];
  return d.count == 0 ? a[2] : val_op(m, VAL_OP, OP_SYSTEM, 0, 0, a, n);
}

/* fromPartial p: a system with no face that holds, or a neutral p, stays. */
static const Value *reduce_from_partial(Machine *m, const Value *const *a, uint32_t n) {
  if (val_is(a[0], OP_SYSTEM) && face_holds(m, 0, a[0]->args[0]))
    return a[0]->args[1];
  return val_op(m, VAL_STUCK, OP_FROMPARTIAL, 0, 0, a, n);
}

/* A part of the type T: field 0 is the domain of a Pi or a Sigma,
   field k + 1 is argument k of a type operation. */
static const Value *reduce_tpart(Machine *m, uint32_t field, const Value *const *a, uint32_t n) {
  const Value *t = a[0];
  switch (t->kind) {
  case VAL_PI:
  case VAL_SIGMA:
    if (field == 0u)
      return t->dom;
    break;
  case VAL_OP:
    if (field >= 1u && field - 1u < t->argc)
      return t->args[field - 1u];
    break;
  case VAL_TRAP:
    return t;
  case VAL_NAT:
  case VAL_UNIV:
  case VAL_LAM:
  case VAL_VAR:
  case VAL_APP:
  case VAL_STUCK:
    break;
  }
  return val_op(m, VAL_STUCK, OP_TPART, 0, field, a, n);
}

/* The codomain of the Pi or Sigma T at x. */
static const Value *reduce_tcod(Machine *m, const Value *const *a, uint32_t n) {
  const Value *t = a[0];
  switch (t->kind) {
  case VAL_PI:
  case VAL_SIGMA:
    return closure_apply(m, t, a[1]);
  case VAL_TRAP:
    return t;
  case VAL_NAT:
  case VAL_UNIV:
  case VAL_LAM:
  case VAL_OP:
  case VAL_VAR:
  case VAL_APP:
  case VAL_STUCK:
    break;
  }
  return val_op(m, VAL_STUCK, OP_TCOD, 0, 0, a, n);
}

/* transp A r u (former C3): u when r holds. At a fresh point, a universe or
   a kit base type gives u; any other line stays stuck (S2 D14). */
static const Value *reduce_transp(Machine *m, const Value *const *a, uint32_t n) {
  const Value *point;
  const Value *h;
  if (face_holds(m, 0, a[1]))
    return a[2];
  point = val_var(m, m->fresh_level);
  h = point == NULL ? NULL : apply_value(m, a[0], point);
  if (h == NULL)
    return NULL;
  switch (h->kind) {
  case VAL_UNIV:
    return a[2];
  case VAL_TRAP:
    return h;
  case VAL_OP:
    if (val_is(h, OP_NAT) || val_is(h, OP_FLAG) || val_is(h, OP_UNIT))
      return a[2];
    break;
  case VAL_NAT:
  case VAL_LAM:
  case VAL_PI:
  case VAL_SIGMA:
  case VAL_VAR:
  case VAL_APP:
  case VAL_STUCK:
    break;
  }
  return val_op(m, VAL_STUCK, OP_TRANSP, 0, 0, a, n);
}

/* SYSMAP f sys (C5): f on each branch of the chain sys. Each cell is
   rebuilt through reduce_system (C4). */
static const Value *reduce_sysmap(Machine *m, const Value *const *a, uint32_t n) {
  const Value *cell[3];
  const Value *tail[2];
  if (val_is(a[1], OP_SYSNIL))
    return a[1];
  if (!val_is(a[1], OP_SYSTEM))
    return val_op(m, VAL_STUCK, OP_SYSMAP, 0, 0, a, n);
  tail[0] = a[0];
  tail[1] = a[1]->args[2];
  cell[0] = a[1]->args[0];
  cell[1] = apply_value(m, a[0], a[1]->args[1]);
  cell[2] = reduce_sysmap(m, tail, 2u);
  if (cell[1] == NULL || cell[2] == NULL)
    return NULL;
  return reduce_system(m, cell, 3u);
}

/* hcomp A phi side u0 (former C3): when phi holds, the side at i1. Else
   stuck: S2 ports no Kan case (D14). */
static const Value *reduce_hcomp(Machine *m, const Value *const *a, uint32_t n) {
  const Value *point;
  const Value *top;
  if (!face_holds(m, 0, a[1]))
    return a[0]->kind == VAL_TRAP ? a[0] : val_op(m, VAL_STUCK, OP_HCOMP, 0, 0, a, n);
  point = constant(m, OP_I1);
  top = point == NULL ? NULL : apply_value(m, a[2], point);
  return top == NULL ? NULL : reduce_from_partial(m, &top, 1u);
}

static uint32_t varied_arity(const Machine *m, Op op, uint32_t inst) {
  const CtorInfo *c = inst < m->ctor_count ? &m->ctors[inst] : NULL;
  const FamilyInfo *f = inst < m->family_count ? &m->families[inst] : NULL;
  if (op == OP_CTOR && c != NULL && c->family < m->family_count)
    return m->families[c->family].param_count + c->field_count;
  if (op == OP_PCTOR && c != NULL && c->family < m->family_count)
    return m->families[c->family].param_count + c->field_count + c->depth;
  if (op == OP_FAMILY && f != NULL)
    return f->param_count + f->index_count;
  if (op == OP_FOLD_FAMILY && f != NULL)
    return f->ctor_count + 1u;
  return UINT32_MAX;
}

static int arity_ok(const Machine *m, Op op, uint32_t inst, uint32_t n) {
  if ((size_t)op >= sizeof OP_ARITY)
    return 0;
  if (OP_ARITY[op] != VARIES)
    return n == (uint32_t)OP_ARITY[op];
  return n == varied_arity(m, op, inst);
}

static const Value *reduce_op(Machine *m, Op op, uint32_t inst, uint32_t field, const Value *const *a, uint32_t n) {
  if (!arity_ok(m, op, inst, n))
    return internal(m, "an operation with the wrong number of arguments");
  switch (op) {
  case OP_NAT:
  case OP_FLAG:
  case OP_UNIT:
  case OP_SUM:
  case OP_OPTION:
  case OP_LIST:
  case OP_FAMILY:
  case OP_UNIT_VAL:
  case OP_FLAG_YES:
  case OP_FLAG_NO:
  case OP_INL:
  case OP_INR:
  case OP_NONE:
  case OP_SOME:
  case OP_NIL:
  case OP_CONS:
  case OP_PACK:
  case OP_CTOR:
  case OP_LEVEL:
  case OP_SSET:
  case OP_I:
  case OP_I0:
  case OP_I1:
  case OP_PATHP:
  case OP_PLAM:
  case OP_PARTIAL:
  case OP_SYSNIL:
    return val_op(m, VAL_OP, op, inst, field, a, n);
  case OP_INEG:
  case OP_IMIN:
  case OP_IMAX:
    return reduce_interval(m, op, a, n);
  case OP_PAPP:
    return reduce_papp(m, a, n);
  case OP_PCTOR:
    return reduce_pctor(m, inst, a, n);
  case OP_SYSTEM:
    return reduce_system(m, a, n);
  case OP_FROMPARTIAL:
    return reduce_from_partial(m, a, n);
  case OP_TRANSP:
    return reduce_transp(m, a, n);
  case OP_TPART:
    return reduce_tpart(m, field, a, n);
  case OP_TCOD:
    return reduce_tcod(m, a, n);
  case OP_HCOMP:
    return reduce_hcomp(m, a, n);
  case OP_SYSMAP:
    return reduce_sysmap(m, a, n);
  case OP_WITNESS:
    return reduce_part(m, op, a, n, OP_PACK, 0);
  case OP_PAYLOAD:
    return reduce_part(m, op, a, n, OP_PACK, 1);
  case OP_EITHER:
    return reduce_either(m, a, n);
  case OP_OPTION_ELIM:
    return reduce_option(m, a, n);
  case OP_PURE:
    return reduce_pure(m, inst, a[0]);
  case OP_MAP:
    return reduce_map(m, inst, a, n);
  case OP_BIND:
    return reduce_bind(m, inst, a, n);
  case OP_FOLD_NAT:
    return reduce_fold_nat(m, a, n);
  case OP_FOLD_LIST:
    return reduce_fold_list(m, a);
  case OP_FOLD_FAMILY:
    return fold_family(m, inst, a, n - 1u, a[n - 1u]);
  case OP_UNFOLD:
    return reduce_unfold(m, a, n);
  case OP_FILTER:
    return reduce_filter(m, inst, a, n);
  case OP_NAT_ADD:
    return nat_add(m, a, n);
  case OP_NAT_SUB:
    return nat_sub(m, a, n);
  case OP_NAT_MUL:
    return nat_mul(m, a, n);
  case OP_NAT_EQ:
  case OP_NAT_LE:
    return nat_test(m, op, a, n);
  case OP_FLAG_IF:
    return reduce_flag_if(m, a, n);
  case OP_PROJ:
    return reduce_proj(m, inst, field, a, n);
  }
  return internal(m, "an unknown operation");
}

static const Value *eval_op(Machine *m, const Env *env, const Core *c) {
  const Value **args = arena_alloc(m->arena, ((size_t)c->argc + 1u) * sizeof *args);
  uint32_t i;
  if (args == NULL)
    return oom(m);
  for (i = 0; i < c->argc; i++) {
    args[i] = eval_core(m, env, c->args[i]);
    if (args[i] == NULL)
      return NULL;
  }
  return reduce_op(m, c->op, c->inst, c->field, args, c->argc);
}

static const Value *eval_inner(Machine *m, const Env *env, const Core *c) {
  switch (c->kind) {
  case CORE_VAR:
    return env_lookup(m, env, c->index);
  case CORE_GLOBAL:
    return def_value(m, c->index);
  case CORE_NAT:
    return val_nat(m, c->nat);
  case CORE_TRAP:
    return val_trap(m);
  case CORE_UNIV:
    return val_univ(m, c->nat);
  case CORE_LAM:
    return val_closure(m, VAL_LAM, c->name, NULL, env, c->b);
  case CORE_PI:
    return val_closure(m, VAL_PI, c->name, eval_core(m, env, c->a), env, c->b);
  case CORE_SIGMA:
    return val_closure(m, VAL_SIGMA, c->name, eval_core(m, env, c->a), env, c->b);
  case CORE_APP:
    return apply_value(m, eval_core(m, env, c->a), eval_core(m, env, c->b));
  case CORE_OP:
    return eval_op(m, env, c);
  }
  return internal(m, "an unknown core term");
}

const Value *eval_core(Machine *m, const Env *env, const Core *c) {
  const Value *v;
  if (c == NULL || !spend(m, 1) || !enter(m))
    return NULL;
  v = eval_inner(m, env, c);
  m->depth--;
  return v;
}

/* Eta: a function is equal to G when the two agree on a fresh variable. */
static int conv_fun(Machine *m, uint32_t level, const Value *a, const Value *b) {
  const Value *x = val_var(m, level);
  return conv_values(m, level + 1u, apply_value(m, a, x), apply_value(m, b, x));
}

static int conv_binder(Machine *m, uint32_t level, const Value *a, const Value *b) {
  const Value *x = val_var(m, level);
  return conv_values(m, level, a->dom, b->dom) && conv_values(m, level + 1u, closure_apply(m, a, x), closure_apply(m, b, x));
}

static int same_head(const Value *a, const Value *b) {
  return a->op == b->op && a->inst == b->inst && a->field == b->field && a->argc == b->argc;
}

/* Sigma eta: compare a pair with the projections of a neutral. */
static int conv_pair(Machine *m, uint32_t level, const Value *pair, const Value *neutral) {
  return conv_values(m, level, pair->args[0], make(m, VAL_STUCK, OP_WITNESS, 0, 1, neutral, NULL, NULL))
      && conv_values(m, level, pair->args[1], make(m, VAL_STUCK, OP_PAYLOAD, 0, 1, neutral, NULL, NULL));
}

/* Path eta (former C2): <i> f i against q compares f x with q @ x. The
   endpoints of q @ x are fillers: x is not i0 or i1. */
static int conv_plam(Machine *m, uint32_t level, const Value *p, const Value *q) {
  const Value *x = val_var(m, level);
  const Value *args[4];
  args[0] = q;
  args[1] = x;
  args[2] = x;
  args[3] = x;
  return conv_values(m, level + 1u, apply_value(m, p->args[0], x), reduce_papp(m, args, 4u));
}

/* The last argument of an operation is compared in the loop, so a long
   list does not nest. */
static int conv_loop(Machine *m, uint32_t level, const Value *a, const Value *b) {
  uint32_t i;
  while (a != NULL && b != NULL && spend(m, 1)) {
    if (val_is(a, OP_PARTIAL) && val_is(b, OP_PARTIAL)) {
      if (!face_equal(m, level, a->args[0], b->args[0])
          && !conv_values(m, level, a->args[0], b->args[0]))
        return 0;
      a = a->args[1];
      b = b->args[1];
      continue;
    }
    if (val_is(a, OP_INEG) || val_is(a, OP_IMIN) || val_is(a, OP_IMAX)
        || val_is(b, OP_INEG) || val_is(b, OP_IMIN) || val_is(b, OP_IMAX)) {
      int equal = conv_interval(m, level, a, b);
      if (equal >= 0)
        return equal;
    }
    if (a->kind == VAL_LAM || b->kind == VAL_LAM)
      return conv_fun(m, level, a, b);
    if (val_is(a, OP_PACK) && scrut_of(b) == SCRUT_NEUTRAL)
      return conv_pair(m, level, a, b);
    if (val_is(b, OP_PACK) && scrut_of(a) == SCRUT_NEUTRAL)
      return conv_pair(m, level, b, a);
    if (val_is(a, OP_PLAM) != val_is(b, OP_PLAM))
      return conv_plam(m, level, val_is(a, OP_PLAM) ? a : b, val_is(a, OP_PLAM) ? b : a);
    if (a->kind == VAL_STUCK && b->kind == VAL_STUCK && a->op == OP_PAPP && b->op == OP_PAPP) {
      /* The endpoints come from the types; only p and r count. */
      if (!conv_values(m, level, a->args[0], b->args[0]))
        return 0;
      a = a->args[1];
      b = b->args[1];
      continue;
    }
    if (a->kind != b->kind)
      return 0;
    switch (a->kind) {
    case VAL_NAT:
    case VAL_UNIV:
    case VAL_VAR:
      return a->nat == b->nat;
    case VAL_TRAP:
      return 1;
    case VAL_LAM:
      return 0;
    case VAL_PI:
    case VAL_SIGMA:
      return conv_binder(m, level, a, b);
    case VAL_APP:
      if (!conv_values(m, level, a->dom, b->dom))
        return 0;
      a = a->arg;
      b = b->arg;
      break;
    case VAL_OP:
    case VAL_STUCK:
      if (!same_head(a, b))
        return 0;
      if (a->argc == 0)
        return 1;
      for (i = 0; i + 1u < a->argc; i++)
        if (!conv_values(m, level, a->args[i], b->args[i]))
          return 0;
      a = a->args[a->argc - 1u];
      b = b->args[b->argc - 1u];
      break;
    }
  }
  return 0;
}

int conv_values(Machine *m, uint32_t level, const Value *a, const Value *b) {
  int same;
  if (a == NULL || b == NULL || !enter(m))
    return 0;
  same = conv_loop(m, level, a, b);
  m->depth--;
  return same;
}

static Core *new_core(Machine *m, CoreKind kind) {
  Core *c = arena_alloc(m->arena, sizeof *c);
  if (c == NULL) {
    oom(m);
    return NULL;
  }
  c->kind = kind;
  return c;
}

static const Core *core_leaf(Machine *m, CoreKind kind, uint64_t nat) {
  Core *c = new_core(m, kind);
  if (c != NULL)
    c->nat = nat;
  return c;
}

static const Core *quote_var(Machine *m, uint32_t level, const Value *v) {
  Core *c;
  if (v->nat >= level) {
    internal(m, "a variable above its level");
    return NULL;
  }
  c = new_core(m, CORE_VAR);
  if (c != NULL)
    c->index = level - 1u - (uint32_t)v->nat;
  return c;
}

static const Core *quote_app(Machine *m, uint32_t level, const Value *v) {
  const Core *fn = quote_value(m, level, v->dom);
  const Core *arg = quote_value(m, level, v->arg);
  Core *c;
  if (fn == NULL || arg == NULL)
    return NULL;
  c = new_core(m, CORE_APP);
  if (c == NULL)
    return NULL;
  c->a = fn;
  c->b = arg;
  return c;
}

static const Core *quote_binder(Machine *m, uint32_t level, const Value *v, CoreKind kind) {
  const Core *dom = kind == CORE_LAM ? NULL : quote_value(m, level, v->dom);
  const Core *body = quote_value(m, level + 1u, closure_apply(m, v, val_var(m, level)));
  Core *c;
  if (body == NULL || (dom == NULL && kind != CORE_LAM))
    return NULL;
  c = new_core(m, kind);
  if (c == NULL)
    return NULL;
  c->name = v->name;
  c->a = dom;
  c->b = body;
  return c;
}

static const Core *quote_op(Machine *m, uint32_t level, const Value *v) {
  const Core **args = arena_alloc(m->arena, ((size_t)v->argc + 1u) * sizeof *args);
  Core *c;
  uint32_t i;
  if (args == NULL) {
    oom(m);
    return NULL;
  }
  for (i = 0; i < v->argc; i++) {
    args[i] = quote_value(m, level, v->args[i]);
    if (args[i] == NULL)
      return NULL;
  }
  c = new_core(m, CORE_OP);
  if (c == NULL)
    return NULL;
  c->op = v->op;
  c->inst = v->inst;
  c->field = v->field;
  c->args = args;
  c->argc = v->argc;
  return c;
}

static const Core *quote_inner(Machine *m, uint32_t level, const Value *v) {
  switch (v->kind) {
  case VAL_NAT:
    return core_leaf(m, CORE_NAT, v->nat);
  case VAL_TRAP:
    return core_leaf(m, CORE_TRAP, 0);
  case VAL_UNIV:
    return core_leaf(m, CORE_UNIV, v->nat);
  case VAL_VAR:
    return quote_var(m, level, v);
  case VAL_APP:
    return quote_app(m, level, v);
  case VAL_LAM:
    return quote_binder(m, level, v, CORE_LAM);
  case VAL_PI:
    return quote_binder(m, level, v, CORE_PI);
  case VAL_SIGMA:
    return quote_binder(m, level, v, CORE_SIGMA);
  case VAL_OP:
  case VAL_STUCK:
    return quote_op(m, level, v);
  }
  internal(m, "an unknown value");
  return NULL;
}

const Core *quote_value(Machine *m, uint32_t level, const Value *v) {
  const Core *c;
  if (v == NULL || !enter(m))
    return NULL;
  c = quote_inner(m, level, v);
  m->depth--;
  return c;
}

const char *op_name(const Machine *m, Op op, uint32_t inst, uint32_t field) {
  if (op == OP_FAMILY)
    return inst < m->family_count ? m->families[inst].name : "?";
  if (op == OP_CTOR || op == OP_PCTOR)
    return inst < m->ctor_count ? m->ctors[inst].name : "?";
  if (op == OP_PROJ)
    return inst < m->ctor_count && field < m->ctors[inst].field_count ? m->ctors[inst].fields[field].name : "?";
  return (size_t)op < sizeof OP_NAMES / sizeof OP_NAMES[0] ? OP_NAMES[op] : "?";
}

/* The printer keeps len + 4 <= cap, so "..." always fits. */
typedef struct {
  Machine *m;
  char *buf;
  size_t cap;
  size_t len;
  int full;
  const char *const *names;
  uint32_t name_count;
  const char *extra[PRINT_NAMES_MAX];
  uint32_t extra_count;
  unsigned depth;
} Printer;

static void put(Printer *p, const char *s) {
  size_t n = strlen(s);
  if (p->full)
    return;
  if (p->len + n + 4u <= p->cap) {
    memcpy(p->buf + p->len, s, n + 1u);
    p->len += n;
    return;
  }
  memcpy(p->buf + p->len, "...", 4u);
  p->len += 3u;
  p->full = 1;
}

static const char *var_name(const Printer *p, uint64_t level) {
  if (level < p->name_count && p->names[level] != NULL)
    return p->names[level];
  if (level >= p->name_count && level - p->name_count < p->extra_count
      && level - p->name_count < PRINT_NAMES_MAX)
    return p->extra[level - p->name_count];
  return "_";
}

static void print_value(Printer *p, const Value *v, int atom);

static int is_chain(const Value *v) {
  return v != NULL && (v->kind == VAL_OP || v->kind == VAL_STUCK) && v->argc > 0;
}

/* A printed binder must not capture another variable or a global name. */
static int name_used(const Printer *p, const char *name) {
  uint32_t i;
  uint32_t j;
  if (name[0] == '%')
    return 1; /* checker-generated eta names are not surface identifiers */
  for (i = 0; i < p->name_count; i++)
    if (p->names[i] != NULL && strcmp(name, p->names[i]) == 0)
      return 1;
  for (i = 0; i < p->extra_count && i < PRINT_NAMES_MAX; i++)
    if (strcmp(name, p->extra[i]) == 0)
      return 1;
  for (i = 0; i < sizeof OP_NAMES / sizeof OP_NAMES[0]; i++)
    if (strcmp(name, OP_NAMES[i]) == 0)
      return 1;
  for (i = 0; i < p->m->def_count; i++)
    if (strcmp(name, p->m->defs[i].name) == 0)
      return 1;
  for (i = 0; i < p->m->family_count; i++)
    if (strcmp(name, p->m->families[i].name) == 0)
      return 1;
  for (i = 0; i < p->m->ctor_count; i++) {
    const CtorInfo *c = &p->m->ctors[i];
    if (strcmp(name, c->name) == 0)
      return 1;
    for (j = 0; j < c->field_count; j++)
      if (strcmp(name, c->fields[j].name) == 0)
        return 1;
  }
  return 0;
}

/* `Type`, `Type₁`, `Type₂`, ...: the level in subscript digits, as in print.c. */
static void put_universe(Printer *p, uint64_t level) {
  char digits[24];
  char sub[4];
  int n = level == 0 ? 0 : snprintf(digits, sizeof digits, "%llu", (unsigned long long)level);
  int i;
  put(p, "Type");
  for (i = 0; i < n; i++) {
    sub[0] = (char)0xe2;
    sub[1] = (char)0x82;
    sub[2] = (char)(0x80 + (digits[i] - '0'));
    sub[3] = '\0';
    put(p, sub);
  }
}

/* A Sigma with the binder `_` (a constant codomain, D9) prints infix as
   `A × B`, as in print.c. */
static int is_times(const Value *v) {
  return v != NULL && v->kind == VAL_SIGMA && v->name != NULL && strcmp(v->name, "_") == 0;
}

/* A λ or a Π operand of `×` needs parentheses. */
static int is_binder(const Value *v) {
  return v != NULL && (v->kind == VAL_LAM || v->kind == VAL_PI);
}

/* The left operand binds tighter than `×`, so `(A × B) × C` keeps them. */
static void print_times(Printer *p, const Value *v, int atom) {
  const Value *b = closure_apply(p->m, v, val_var(p->m, p->name_count + p->extra_count));
  if (atom)
    put(p, "(");
  print_value(p, v->dom, is_times(v->dom) || is_binder(v->dom));
  put(p, " × ");
  print_value(p, b, is_binder(b));
  if (atom)
    put(p, ")");
}

/* `λ x y → t` (nested lambdas merge), `(x : A) → B`, `A → B` and
   `Σ A (λ x → B)`. MERGED is 1 for an inner lambda of a merged group. */
static void print_binder(Printer *p, const Value *v, int merged) {
  uint32_t level = p->name_count + p->extra_count;
  const char *name = v->name != NULL ? v->name : "x";
  char fresh[32];
  uint32_t suffix = 0;
  const Value *body = closure_apply(p->m, v, val_var(p->m, level));
  int binder_dom = is_binder(v->dom);
  while (name_used(p, name)) {
    snprintf(fresh, sizeof fresh, "_x%u", suffix++);
    name = fresh;
  }
  switch (v->kind) {
  case VAL_LAM:
    put(p, merged ? " " : "λ ");
    put(p, name);
    break;
  case VAL_PI:
    if (v->name == NULL) {
      print_value(p, v->dom, binder_dom);
      break;
    }
    put(p, "(");
    put(p, name);
    put(p, " : ");
    print_value(p, v->dom, 0);
    put(p, ")");
    break;
  case VAL_SIGMA:
    put(p, "Σ ");
    print_value(p, v->dom, 1);
    put(p, " (λ ");
    put(p, name);
    break;
  case VAL_NAT:
  case VAL_TRAP:
  case VAL_UNIV:
  case VAL_OP:
  case VAL_VAR:
  case VAL_APP:
  case VAL_STUCK:
    break;
  }
  if (p->extra_count < PRINT_NAMES_MAX)
    p->extra[p->extra_count] = name;
  p->extra_count++;
  if (v->kind == VAL_LAM && body != NULL && body->kind == VAL_LAM && p->depth < PRINT_DEPTH_MAX) {
    p->depth++;
    print_binder(p, body, 1);
    p->depth--;
  } else {
    put(p, " → ");
    print_value(p, body, 0);
  }
  if (v->kind == VAL_SIGMA)
    put(p, ")");
  p->extra_count--;
}

static void print_other(Printer *p, const Value *v, int atom) {
  char num[32];
  if (v == NULL) {
    put(p, "?");
    return;
  }
  switch (v->kind) {
  case VAL_NAT:
    snprintf(num, sizeof num, "%llu", (unsigned long long)v->nat);
    put(p, num);
    return;
  case VAL_TRAP:
    put(p, "trap");
    return;
  case VAL_VAR:
    put(p, var_name(p, v->nat));
    return;
  case VAL_OP:
  case VAL_STUCK:
    put(p, op_name(p->m, v->op, v->inst, v->field));
    return;
  case VAL_UNIV:
    put_universe(p, v->nat);
    return;
  case VAL_APP:
  case VAL_LAM:
  case VAL_PI:
  case VAL_SIGMA:
    break;
  }
  if (atom)
    put(p, "(");
  switch (v->kind) {
  case VAL_APP:
    print_value(p, v->dom, v->dom->kind != VAL_APP && v->dom->kind != VAL_VAR);
    put(p, " ");
    print_value(p, v->arg, 1);
    break;
  case VAL_LAM:
  case VAL_PI:
  case VAL_SIGMA:
    print_binder(p, v, 0);
    break;
  case VAL_NAT:
  case VAL_TRAP:
  case VAL_UNIV:
  case VAL_VAR:
  case VAL_OP:
  case VAL_STUCK:
    break;
  }
  if (atom)
    put(p, ")");
}

/* An operation prints as its name and its arguments. A pair prints as
   `a , b` and a path abstraction prints as its line `λ i → a`. The last
   argument is printed in the loop, so a long list does not nest. */
static void print_value(Printer *p, const Value *v, int atom) {
  uint32_t open = 0;
  uint32_t i;
  if (p->depth >= PRINT_DEPTH_MAX) {
    put(p, "...");
    p->full = 1;
    return;
  }
  p->depth++;
  while (is_chain(v) && !is_times(v) && !p->full) {
    if (v->op == OP_PLAM) {
      v = v->args[0];
      continue;
    }
    if (atom) {
      put(p, "(");
      open++;
    }
    if (v->op == OP_PACK) {
      print_value(p, v->args[0], 1);
      put(p, " , ");
      v = v->args[1];
      atom = 0;
      continue;
    }
    put(p, op_name(p->m, v->op, v->inst, v->field));
    for (i = 0; i + 1u < v->argc; i++) {
      put(p, " ");
      print_value(p, v->args[i], 1);
    }
    put(p, " ");
    v = v->args[v->argc - 1u];
    atom = 1;
  }
  if (is_times(v) && !p->full)
    print_times(p, v, atom);
  else
    print_other(p, v, atom);
  for (i = 0; i < open; i++)
    put(p, ")");
  p->depth--;
}

int value_print(Machine *m, const char *const *names, uint32_t name_count, const Value *v, char *buf, size_t cap) {
  Printer p;
  if (cap == 0)
    return 0;
  buf[0] = '\0';
  if (cap < 4u)
    return 0;
  memset(&p, 0, sizeof p);
  p.m = m;
  p.buf = buf;
  p.cap = cap;
  p.names = names;
  p.name_count = name_count;
  print_value(&p, v, 0);
  return !p.full && !m->diag->set;
}
