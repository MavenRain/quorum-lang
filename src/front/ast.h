/* The syntax tree. SHARED by the tcc kits. Terms and types share one syntax. */
#ifndef LANG_FRONT_AST_H
#define LANG_FRONT_AST_H

#include <stddef.h>
#include <stdint.h>

/* The product type former. The parser gives `A × B` as `_×_ A B`. */
#define AST_TIMES_NAME "_×_"

typedef enum {
  TERM_VAR,   /* name */
  TERM_NAT,   /* nat */
  TERM_APP,   /* left applied to right */
  TERM_LAM,   /* λ (name : left) → right; left is NULL for a bare binder */
  TERM_PI,    /* (name : left) → right; name is NULL for left → right */
  TERM_SIGMA, /* Σ left (λ name → right) */
  TERM_UNIV   /* Type at level nat */
} TermKind;

typedef struct Term Term;
struct Term {
  TermKind kind;
  int line;
  int col;
  const char *name;
  uint64_t nat;
  const Term *left;
  const Term *right;
};

/* A named field of a constructor, or a parameter of a data type. */
typedef struct {
  const char *name;
  const Term *type;
  int line;
  int col;
} Field;

typedef struct {
  const char *name;
  const Field *fields;
  size_t field_count;
  int line;
  int col;
} Ctor;

typedef enum {
  DECL_DEF,    /* name : type, then the clause name patterns = body */
  DECL_AXIOM,  /* postulate name : type */
  DECL_FAMILY  /* data name params : Type where ctors */
} DeclKind;

/* A data type is legal only in the domain file (rule R1). */
typedef enum {
  ORIGIN_DOMAIN,
  ORIGIN_PROGRAM
} Origin;

typedef struct {
  DeclKind kind;
  Origin origin;
  int is_rec;     /* the body names the definition itself */
  int line;
  int col;
  int end_line;   /* the line of the last token */
  const char *source; /* the file that holds the declaration */
  const char *name;
  const Term *type;
  const Term *body;   /* clause patterns are bare lambdas around the right side */
  const Field *params;
  size_t param_count;
  uint64_t level;     /* the level after `data NAME params :`; S1 does not check it */
  const Ctor *ctors;
  size_t ctor_count;
} Decl;

/* Domain declarations come first, then the program. */
typedef struct {
  Decl *items;
  size_t count;
  size_t cap;
} DeclList;

#endif
