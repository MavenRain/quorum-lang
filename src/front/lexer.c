#include <string.h>

#include "front/lexer.h"

typedef struct {
  const char *text;
  size_t len;
  size_t pos;
  int line;
  int col;
  Token *out;
  size_t count;
  Comment *comments;
  size_t comment_count;
  Diag *diag;
  const char *source;
} Lexer;

static const struct {
  const char *word;
  TokKind kind;
} KEYWORDS[] = {
  {"data", TOK_KW_DATA},
  {"where", TOK_KW_WHERE},
  {"postulate", TOK_KW_POSTULATE},
  {"let", TOK_KW_LET},
  {"in", TOK_KW_IN},
  {"record", TOK_KW_RECORD},
  {"coinductive", TOK_KW_COINDUCTIVE},
  {"module", TOK_KW_MODULE},
};

/* The reserved code points. Each one is a symbol, never part of a name. */
static const struct {
  const char *bytes;
  TokKind kind;
} SYMBOLS[] = {
  {"→", TOK_ARROW},
  {"λ", TOK_LAMBDA},
  {"×", TOK_TIMES},
  {"Σ", TOK_SIGMA},
  {"≡", TOK_EQUIV},
  {"∧", TOK_AND},
  {"∨", TOK_OR},
};

const char *tok_kind_name(TokKind kind) {
  switch (kind) {
    case TOK_EOF: return "end of input";
    case TOK_IDENT: return "a name";
    case TOK_NAT: return "a ℕ literal";
    case TOK_LPAREN: return "'('";
    case TOK_RPAREN: return "')'";
    case TOK_COLON: return "':'";
    case TOK_EQUALS: return "'='";
    case TOK_ARROW: return "'→'";
    case TOK_LAMBDA: return "'λ'";
    case TOK_TIMES: return "'×'";
    case TOK_SIGMA: return "'Σ'";
    case TOK_EQUIV: return "'≡'";
    case TOK_TILDE: return "'~'";
    case TOK_AND: return "'∧'";
    case TOK_OR: return "'∨'";
    case TOK_COMMA: return "','";
    case TOK_LBRACE: return "'{'";
    case TOK_RBRACE: return "'}'";
    case TOK_SEMI: return "';'";
    case TOK_KW_DATA: return "'data'";
    case TOK_KW_WHERE: return "'where'";
    case TOK_KW_POSTULATE: return "'postulate'";
    case TOK_KW_LET: return "'let'";
    case TOK_KW_IN: return "'in'";
    case TOK_KW_RECORD: return "'record'";
    case TOK_KW_COINDUCTIVE: return "'coinductive'";
    case TOK_KW_MODULE: return "'module'";
    case TOK_KW_TYPE: return "'Type'";
  }
  return "a token";
}

static int is_digit(char c) {
  return c >= '0' && c <= '9';
}

static char peek(const Lexer *lx, size_t ahead) {
  return lx->pos + ahead < lx->len ? lx->text[lx->pos + ahead] : '\0';
}

/* Returns the byte width of the reserved symbol at the cursor, or 0. */
static size_t symbol_at(const Lexer *lx, TokKind *kind) {
  for (size_t i = 0; i < sizeof SYMBOLS / sizeof SYMBOLS[0]; i++) {
    size_t width = strlen(SYMBOLS[i].bytes);
    if (lx->len - lx->pos >= width && memcmp(lx->text + lx->pos, SYMBOLS[i].bytes, width) == 0) {
      *kind = SYMBOLS[i].kind;
      return width;
    }
  }
  return 0;
}

/* A name starts with a letter, '_' or a byte >= 0x80 that does not begin a
   reserved symbol, so ℕ and Type₁ are names. Digits and '\'' continue it. */
static int at_name_start(const Lexer *lx) {
  unsigned char c = (unsigned char)peek(lx, 0);
  TokKind kind = TOK_EOF;
  int letter = (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_';
  return letter || (c >= 0x80 && symbol_at(lx, &kind) == 0);
}

/* A '-' continues a name when a name start follows it, so ℓ-max is one
   name. `->` and `--` keep their meaning. */
static int at_name_dash(const Lexer *lx) {
  Lexer next = *lx;
  next.pos++;
  return peek(lx, 0) == '-' && lx->pos + 1 < lx->len && at_name_start(&next);
}

static int at_name_char(const Lexer *lx) {
  char c = peek(lx, 0);
  return at_name_start(lx) || is_digit(c) || c == '\'' || at_name_dash(lx);
}

/* A UTF-8 continuation byte does not move the column. */
static void advance(Lexer *lx, size_t width) {
  for (size_t i = 0; i < width && lx->pos < lx->len; i++) {
    unsigned char c = (unsigned char)lx->text[lx->pos];
    int newline = c == '\n';
    int continuation = (c & 0xc0) == 0x80;
    lx->line += newline;
    lx->col = newline ? 1 : continuation ? lx->col : lx->col + 1;
    lx->pos++;
  }
}

static Token *push(Lexer *lx, TokKind kind, size_t start, int line, int col) {
  Token *tok = &lx->out[lx->count];
  lx->count++;
  tok->kind = kind;
  tok->text = lx->text + start;
  tok->len = lx->pos - start;
  tok->nat = 0;
  tok->line = line;
  tok->col = col;
  return tok;
}

/* Skips white space. Keeps each `--` comment, which runs to the end of the
   line, for the printer. */
static void skip_trivia(Lexer *lx) {
  for (;;) {
    char c = peek(lx, 0);
    int space = lx->pos < lx->len && (c == ' ' || c == '\t' || c == '\n' || c == '\r');
    int comment = c == '-' && peek(lx, 1) == '-';
    if (!space && !comment) return;
    if (space) {
      advance(lx, 1);
      continue;
    }
    Comment *note = &lx->comments[lx->comment_count];
    lx->comment_count++;
    size_t start = lx->pos;
    note->text = lx->text + start;
    note->line = lx->line;
    note->col = lx->col;
    while (lx->pos < lx->len && lx->text[lx->pos] != '\n') advance(lx, 1);
    size_t end = lx->pos;
    while (end > start && (lx->text[end - 1] == ' ' || lx->text[end - 1] == '\t' || lx->text[end - 1] == '\r')) end--;
    note->len = end - start;
  }
}

static TokKind keyword_kind(const char *text, size_t len) {
  for (size_t i = 0; i < sizeof KEYWORDS / sizeof KEYWORDS[0]; i++) {
    if (strlen(KEYWORDS[i].word) == len && memcmp(KEYWORDS[i].word, text, len) == 0) return KEYWORDS[i].kind;
  }
  return TOK_IDENT;
}

/* `Type` and subscript digits (U+2080 to U+2089) is the universe keyword at
   that level. Returns 0 for any other name. */
static int universe_level(const char *text, size_t len, uint64_t *level, int *overflow) {
  if (len < 4 || memcmp(text, "Type", 4) != 0) return 0;
  uint64_t value = 0;
  int big = 0;
  size_t i = 4;
  while (i + 3 <= len && (unsigned char)text[i] == 0xe2 && (unsigned char)text[i + 1] == 0x82
         && (unsigned char)text[i + 2] >= 0x80 && (unsigned char)text[i + 2] <= 0x89) {
    uint64_t digit = (uint64_t)((unsigned char)text[i + 2] - 0x80);
    big |= value > (UINT64_MAX - digit) / 10u;
    value = value * 10u + digit;
    i += 3;
  }
  if (i != len) return 0;
  *level = value;
  *overflow = big;
  return 1;
}

static int lex_ident(Lexer *lx) {
  size_t start = lx->pos;
  int line = lx->line;
  int col = lx->col;
  while (at_name_char(lx)) advance(lx, 1);
  size_t len = lx->pos - start;
  uint64_t level = 0;
  int overflow = 0;
  if (!universe_level(lx->text + start, len, &level, &overflow)) {
    push(lx, keyword_kind(lx->text + start, len), start, line, col);
    return 1;
  }
  if (overflow) {
    return diag_fail_at(lx->diag, "LEX_NAT_RANGE", NULL, (Span){lx->source, line, col, line, col + 1}, NULL, NULL, "%s:%d:%d: a universe level is larger than 2^64 - 1", lx->source, line, col);
  }
  push(lx, TOK_KW_TYPE, start, line, col)->nat = level;
  return 1;
}

static int lex_nat(Lexer *lx) {
  size_t start = lx->pos;
  int line = lx->line;
  int col = lx->col;
  uint64_t value = 0;
  int overflow = 0;
  while (is_digit(peek(lx, 0))) {
    uint64_t digit = (uint64_t)(peek(lx, 0) - '0');
    overflow |= value > (UINT64_MAX - digit) / 10u;
    value = value * 10u + digit;
    advance(lx, 1);
  }
  if (overflow) {
    return diag_fail_at(lx->diag, "LEX_NAT_RANGE", NULL, (Span){lx->source, line, col, line, col + 1}, NULL, NULL, "%s:%d:%d: a ℕ literal is larger than 2^64 - 1", lx->source, line, col);
  }
  if (at_name_start(lx)) {
    return diag_fail_at(lx->diag, "LEX_CHAR", NULL, (Span){lx->source, lx->line, lx->col, lx->line, lx->col + 1}, NULL, NULL, "%s:%d:%d: a letter follows a ℕ literal", lx->source, lx->line, lx->col);
  }
  push(lx, TOK_NAT, start, line, col)->nat = value;
  return 1;
}

static int lex_symbol(Lexer *lx) {
  size_t start = lx->pos;
  int line = lx->line;
  int col = lx->col;
  char c = peek(lx, 0);
  TokKind kind = TOK_EOF;
  size_t width = symbol_at(lx, &kind);
  if (width == 0) {
    width = 1;
    switch (c) {
      case '(': kind = TOK_LPAREN; break;
      case ')': kind = TOK_RPAREN; break;
      case ':': kind = TOK_COLON; break;
      case '=': kind = TOK_EQUALS; break;
      case '\\': kind = TOK_LAMBDA; break;
      case ',': kind = TOK_COMMA; break;
      case '~': kind = TOK_TILDE; break;
      case '{': kind = TOK_LBRACE; break;
      case '}': kind = TOK_RBRACE; break;
      case ';': kind = TOK_SEMI; break;
      case '-':
        kind = peek(lx, 1) == '>' ? TOK_ARROW : TOK_EOF;
        width = 2;
        break;
      default: break;
    }
  }
  if (kind == TOK_EOF) {
    return diag_fail_at(lx->diag, "LEX_CHAR", NULL, (Span){lx->source, line, col, line, col + 1}, NULL, NULL, "%s:%d:%d: unexpected byte 0x%02x", lx->source, line, col, (unsigned)(unsigned char)c);
  }
  advance(lx, width);
  push(lx, kind, start, line, col);
  return 1;
}

/* Validate comments too: every source byte can reach a formatter fix or
   diagnostic string. NUL cannot be represented by the text interfaces. */
static int validate_text(const char *source, const char *text, size_t len, Diag *diag) {
  int line = 1;
  int col = 1;
  for (size_t pos = 0; pos < len;) {
    unsigned char c = (unsigned char)text[pos];
    size_t width = utf8_char_size(text + pos, len - pos);
    if (c == 0 || width == 0)
      return diag_fail_at(diag, "LEX_CHAR", NULL, (Span){source, line, col, line, col + 1}, NULL, NULL,
                          "%s:%d:%d: %s", source, line, col,
                          c == 0 ? "NUL is not allowed in source text" : "invalid UTF-8 sequence");
    pos += width;
    line += c == '\n';
    col = c == '\n' ? 1 : col + 1;
  }
  return 1;
}

int lex_source(Arena *arena, const char *source, const char *text, size_t len, TokenList *out, Diag *diag) {
  if (!validate_text(source, text, len, diag)) return 0;
  /* Each token takes at least one byte, and one EOF token follows. Each
     comment takes at least two bytes. */
  Token *tokens = arena_alloc(arena, (len + 1) * sizeof(Token));
  Comment *comments = arena_alloc(arena, (len / 2 + 1) * sizeof(Comment));
  if (tokens == NULL || comments == NULL) return diag_fail(diag, "OOM", NULL, "%s: no memory for the tokens", source);
  Lexer lx = {
    .text = text, .len = len, .pos = 0, .line = 1, .col = 1,
    .out = tokens, .count = 0, .comments = comments, .comment_count = 0,
    .diag = diag, .source = source,
  };
  for (;;) {
    skip_trivia(&lx);
    if (lx.pos >= lx.len) break;
    int ok = at_name_start(&lx) ? lex_ident(&lx) : is_digit(peek(&lx, 0)) ? lex_nat(&lx) : lex_symbol(&lx);
    if (!ok) return 0;
  }
  push(&lx, TOK_EOF, lx.pos, lx.line, lx.col);
  out->items = tokens;
  out->count = lx.count;
  out->comments = comments;
  out->comment_count = lx.comment_count;
  return 1;
}
