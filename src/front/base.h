/* Arena allocation and the diagnostic sink. SHARED by the tcc kits. */
#ifndef LANG_FRONT_BASE_H
#define LANG_FRONT_BASE_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

typedef struct ArenaChunk ArenaChunk;

/* Every compiler object lives in one arena. The arena frees all at once. */
typedef struct {
  ArenaChunk *head;
  size_t used_bytes;
  size_t limit_bytes;
} Arena;

void arena_init(Arena *arena, size_t limit_bytes);
/* Returns zeroed memory, or NULL when the limit is reached. */
void *arena_alloc(Arena *arena, size_t size);
char *arena_strndup(Arena *arena, const char *text, size_t len);
void arena_release(Arena *arena);

/* A span in a source file. END is the position after the last
   character, so a point span has END = START. Columns count code points.
   FILE is NULL when no span applies. */
typedef struct {
  const char *file;
  int line;
  int col;
  int end_line;
  int end_col;
} Span;

/* The first failure wins. Later failures do not overwrite it. */
typedef struct {
  int set;
  const char *code;
  char def[64];
  char msg[512];
  Span span;
  int has_expected;
  int has_found;
  char expected[128]; /* the text that the checker wants there */
  char found[128];    /* the text that is there */
  const char *fix;    /* a full replacement text, or NULL */
} Diag;

void diag_init(Diag *diag);
/* Records the failure and returns 0, so a caller can write
   `return diag_fail(...)`. DEF is NULL when no definition applies. */
int diag_fail(Diag *diag, const char *code, const char *def, const char *fmt, ...);
/* As diag_fail, and records SPAN, EXPECTED and FOUND. EXPECTED and FOUND
   are NULL when not known. */
int diag_fail_at(Diag *diag, const char *code, const char *def, Span span,
                 const char *expected, const char *found, const char *fmt, ...);
/* Prints `langc: CODE: DEF: message`. */
void diag_print(const Diag *diag, FILE *out);

/* The count of code points in the LEN bytes of TEXT. */
int utf8_width(const char *text, size_t len);
/* The byte size of the first UTF-8 scalar, or 0 for an invalid sequence. */
size_t utf8_char_size(const char *text, size_t len);
/* Copies at most CAP - 1 bytes of SRC into DST and ends it with NUL. A
   cut does not split a UTF-8 sequence. */
void text_copy(char *dst, size_t cap, const char *src, size_t len);

#endif
