/* The syntax tree. SHARED by the tcc kits. Terms and types share one syntax. */
#ifndef LANG_FRONT_AST_H
#define LANG_FRONT_AST_H

#include <stddef.h>
#include <stdint.h>

/* The product type former. The parser gives `A × B` as `_×_ A B`. */
#define AST_TIMES_NAME "_×_"

/* The other operators are named applications too: `a ≡ b` is `_≡_ a b`,
   `a , b` is `_,_ a b`, `r ∧ s` is `_∧_ r s`, `r ∨ s` is `_∨_ r s` and
   `~ r` is `~_ r`. The lexer gives each operator as a symbol, so no source
   name is one of these names. */
#define AST_PATH_NAME "_≡_"
#define AST_PAIR_NAME "_,_"
#define AST_MIN_NAME "_∧_"
#define AST_MAX_NAME "_∨_"
#define AST_NEG_NAME "~_"

typedef enum {
  TERM_VAR,   /* name */
  TERM_NAT,   /* nat */
  TERM_APP,   /* left applied to right */
  TERM_LAM,   /* λ (name : left) → right; left is NULL for a bare binder */
  TERM_PI,    /* (name : left) → right; name is NULL for left → right */
  TERM_SIGMA, /* Σ left (λ name → right) */
  TERM_UNIV,  /* Type at level nat, or `Type right` when right is not NULL */
  TERM_SYSTEM, /* λ { cell ; ... ; cell }: cells */
  TERM_LET     /* let name = left in right (A1) */
} TermKind;

typedef struct Term Term;
typedef struct Cell Cell;
struct Term {
  TermKind kind;
  int line;
  int col;
  const char *name;
  uint64_t nat;
  const Term *left;
  const Term *right;
  const Cell *cells;
  size_t cell_count;
};

/* One `(i = i0)` group of a face. END is 0 for i0 and 1 for i1. */
typedef struct {
  const char *name;
  int end;
  int line;
  int col;
} FaceAtom;

/* One cell `(i = i0) (j = i1) → body` of a system. The face is the
   conjunction of its atoms. */
struct Cell {
  const FaceAtom *atoms;
  size_t atom_count;
  const Term *body;
  int line;
  int col;
};

/* A named field of a constructor or a record, or a parameter of a data type. */
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
  const Term *const *indices; /* one atom for each index of the data type */
  const Term *result;         /* a path constructor: its type s ≡ t or p ≡ q; NULL for a point constructor */
  int line;
  int col;
} Ctor;

typedef enum {
  DECL_DEF,    /* name : type, then the clause name patterns = body */
  DECL_AXIOM,  /* postulate name : type */
  DECL_FAMILY, /* data name params : Type where ctors */
  DECL_RECORD, /* record name params : Type where fields (D2) */
  DECL_MODULE  /* module name params where, then the definitions of the section (D3) */
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
  const Term *const *indices; /* the index types before the universe */
  size_t index_count;
  const Ctor *ctors;
  size_t ctor_count;
  const Field *fields; /* the fields of a record */
  size_t field_count;
  int coinductive;     /* the record has the line `coinductive` */
  size_t section;      /* 1 + the list index of the module that holds the definition; 0 outside a module (D3) */
} Decl;

/* Domain declarations come first, then the program. */
typedef struct {
  Decl *items;
  size_t count;
  size_t cap;
} DeclList;

#endif
