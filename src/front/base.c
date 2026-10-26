#include <stdarg.h>
#include <stdlib.h>
#include <string.h>

#include "front/base.h"

#define ARENA_CHUNK_BYTES ((size_t)1 << 16)

/* The header is 32 bytes, so data stays 16-byte aligned. */
struct ArenaChunk {
  ArenaChunk *next;
  size_t size;
  size_t used;
  size_t pad;
  unsigned char data[];
};

void arena_init(Arena *arena, size_t limit_bytes) {
  arena->head = NULL;
  arena->used_bytes = 0;
  arena->limit_bytes = limit_bytes;
}

static int arena_grow(Arena *arena, size_t need) {
  size_t size = need > ARENA_CHUNK_BYTES ? need : ARENA_CHUNK_BYTES;
  if (size > arena->limit_bytes - arena->used_bytes) return 0;
  ArenaChunk *chunk = calloc(1, sizeof(ArenaChunk) + size);
  if (chunk == NULL) return 0;
  chunk->next = arena->head;
  chunk->size = size;
  arena->head = chunk;
  arena->used_bytes += size;
  return 1;
}

void *arena_alloc(Arena *arena, size_t size) {
  size_t need = (size + 15u) & ~(size_t)15u;
  if (need < size) return NULL;
  int fits = arena->head != NULL && arena->head->size - arena->head->used >= need;
  if (!fits && !arena_grow(arena, need)) return NULL;
  void *block = arena->head->data + arena->head->used;
  arena->head->used += need;
  return block;
}

char *arena_strndup(Arena *arena, const char *text, size_t len) {
  char *copy = arena_alloc(arena, len + 1);
  if (copy == NULL) return NULL;
  if (len > 0) memcpy(copy, text, len);
  copy[len] = '\0';
  return copy;
}

void arena_release(Arena *arena) {
  ArenaChunk *chunk = arena->head;
  while (chunk != NULL) {
    ArenaChunk *next = chunk->next;
    free(chunk);
    chunk = next;
  }
  arena_init(arena, arena->limit_bytes);
}

void diag_init(Diag *diag) {
  memset(diag, 0, sizeof *diag);
}

static void diag_record(Diag *diag, const char *code, const char *def, const char *fmt, va_list args) {
  diag->set = 1;
  diag->code = code;
  snprintf(diag->def, sizeof diag->def, "%s", def == NULL ? "-" : def);
  vsnprintf(diag->msg, sizeof diag->msg, fmt, args);
}

int diag_fail(Diag *diag, const char *code, const char *def, const char *fmt, ...) {
  if (diag->set) return 0;
  va_list args;
  va_start(args, fmt);
  diag_record(diag, code, def, fmt, args);
  va_end(args);
  return 0;
}

int diag_fail_at(Diag *diag, const char *code, const char *def, Span span,
                 const char *expected, const char *found, const char *fmt, ...) {
  if (diag->set) return 0;
  va_list args;
  va_start(args, fmt);
  diag_record(diag, code, def, fmt, args);
  va_end(args);
  diag->span = span;
  diag->has_expected = expected != NULL;
  diag->has_found = found != NULL;
  text_copy(diag->expected, sizeof diag->expected, expected, expected != NULL ? strlen(expected) : 0);
  text_copy(diag->found, sizeof diag->found, found, found != NULL ? strlen(found) : 0);
  return 0;
}

void diag_print(const Diag *diag, FILE *out) {
  fprintf(out, "langc: %s: %s: %s\n", diag->code, diag->def, diag->msg);
}

int utf8_width(const char *text, size_t len) {
  int width = 0;
  for (size_t i = 0; i < len; i++) width += ((unsigned char)text[i] & 0xC0) != 0x80;
  return width;
}

size_t utf8_char_size(const char *text, size_t len) {
  if (len == 0) return 0;
  unsigned char c = (unsigned char)text[0];
  size_t width = c < 0x80 ? 1 : c >= 0xc2 && c <= 0xdf ? 2
    : c >= 0xe0 && c <= 0xef ? 3 : c >= 0xf0 && c <= 0xf4 ? 4 : 0;
  if (width == 0 || width > len) return 0;
  for (size_t i = 1; i < width; i++)
    if (((unsigned char)text[i] & 0xc0) != 0x80) return 0;
  if (width >= 3) {
    unsigned char next = (unsigned char)text[1];
    if ((c == 0xe0 && next < 0xa0) || (c == 0xed && next >= 0xa0)
        || (c == 0xf0 && next < 0x90) || (c == 0xf4 && next >= 0x90)) return 0;
  }
  return width;
}

void text_copy(char *dst, size_t cap, const char *src, size_t len) {
  size_t n = len < cap - 1 ? len : cap - 1;
  while (n > 0 && n < len && ((unsigned char)src[n] & 0xC0) == 0x80) n--;
  if (n > 0) memcpy(dst, src, n);
  dst[n] = '\0';
}
