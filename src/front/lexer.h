/* Tokens of the DSL. SHARED by the tcc kits. */
#ifndef LANG_FRONT_LEXER_H
#define LANG_FRONT_LEXER_H

#include "front/base.h"

typedef enum {
  TOK_EOF,
  TOK_IDENT,
  TOK_NAT,
  TOK_LPAREN,
  TOK_RPAREN,
  TOK_COLON,
  TOK_EQUALS,
  TOK_ARROW,       /* → (U+2192), or -> (not canonical) */
  TOK_LAMBDA,      /* λ (U+03BB), or \ (not canonical) */
  TOK_TIMES,       /* × (U+00D7) */
  TOK_SIGMA,       /* Σ (U+03A3) */
  TOK_EQUIV,       /* ≡ (U+2261) */
  TOK_TILDE,       /* ~ */
  TOK_AND,         /* ∧ (U+2227) */
  TOK_OR,          /* ∨ (U+2228) */
  TOK_COMMA,       /* , */
  TOK_LBRACE,      /* { */
  TOK_RBRACE,      /* } */
  TOK_SEMI,        /* ; */
  TOK_OPER,        /* ∷, ++, ∘ or ∙ (S3 D5) */
  TOK_TRUNC_OPEN,  /* ∥ */
  TOK_TRUNC_CLOSE, /* ∥₁ */
  TOK_EXISTS,      /* ∃[ */
  TOK_TYPED,       /* ꞉ (U+A789) */
  TOK_RBRACKET,    /* ] */
  TOK_KW_DATA,
  TOK_KW_WHERE,
  TOK_KW_POSTULATE,
  TOK_KW_LET,
  TOK_KW_IN,
  TOK_KW_RECORD,
  TOK_KW_COINDUCTIVE,
  TOK_KW_MODULE,
  TOK_KW_LAW,
  TOK_KW_SEALED,
  TOK_KW_TYPE      /* Type, Type₁, ...: the level is in nat */
} TokKind;

/* COL counts code points, not bytes. */
typedef struct {
  TokKind kind;
  const char *text;
  size_t len;
  uint64_t nat;
  int line;
  int col;
} Token;

/* A `--` comment. TEXT starts at the `--`. LEN does not include the
   white space at the end of the line. */
typedef struct {
  const char *text;
  size_t len;
  int line;
  int col;
} Comment;

/* The last token is TOK_EOF. */
typedef struct {
  const Token *items;
  size_t count;
  const Comment *comments;
  size_t comment_count;
} TokenList;

/* SOURCE names the input in diagnostics. Returns 1, or 0 after a diagnostic. */
int lex_source(Arena *arena, const char *source, const char *text, size_t len, TokenList *out, Diag *diag);
const char *tok_kind_name(TokKind kind);

#endif
