#include "front/json.h"

#include <string.h>

/* An author can repair the failure and check again. REFUSE_*, IO*, OOM,
   USAGE and EVAL_* are not in this set. */
static int is_retry(const char *code) {
  static const char *const PREFIXES[] = {"LEX_", "PARSE_", "NAME_", "TYPE_", "W_"};
  int retry = 0;
  for (size_t i = 0; i < sizeof PREFIXES / sizeof PREFIXES[0]; i++)
    retry = retry || strncmp(code, PREFIXES[i], strlen(PREFIXES[i])) == 0;
  return retry;
}

/* UTF-8 bytes pass through. Quote, backslash and control bytes escape. */
static void put_char(unsigned char c, FILE *out) {
  const char *escape = c == '"' ? "\\\"" : c == '\\' ? "\\\\" : c == '\n' ? "\\n" : c == '\t' ? "\\t" : NULL;
  if (escape != NULL) {
    fputs(escape, out);
    return;
  }
  if (c < 0x20) {
    fprintf(out, "\\u%04x", c);
    return;
  }
  fputc(c, out);
}

static void put_string(const char *text, FILE *out) {
  fputc('"', out);
  size_t len = strlen(text);
  for (size_t pos = 0; pos < len;) {
    size_t width = utf8_char_size(text + pos, len - pos);
    /* Paths and truncated diagnostic buffers can contain invalid bytes. */
    if (width == 0) {
      fputs("\\ufffd", out);
      pos++;
      continue;
    }
    for (size_t i = 0; i < width; i++) put_char((unsigned char)text[pos + i], out);
    pos += width;
  }
  fputc('"', out);
}

static void put_field(const char *key, const char *text, int known, FILE *out) {
  fprintf(out, ",\"%s\":", key);
  if (!known) {
    fputs("null", out);
    return;
  }
  put_string(text, out);
}

static void put_span(const Span *span, FILE *out) {
  fputs(",\"span\":", out);
  if (span->file == NULL) {
    fputs("null", out);
    return;
  }
  fputs("{\"file\":", out);
  put_string(span->file, out);
  fprintf(out, ",\"line\":%d,\"col\":%d,\"endLine\":%d,\"endCol\":%d}",
          span->line, span->col, span->end_line, span->end_col);
}

void json_diag(const Diag *diag, FILE *out) {
  fputs("{\"code\":", out);
  put_string(diag->code, out);
  put_span(&diag->span, out);
  put_field("expected", diag->expected, diag->has_expected, out);
  put_field("found", diag->found, diag->has_found, out);
  put_field("fix", diag->fix, diag->fix != NULL, out);
  fprintf(out, ",\"retry\":%s", is_retry(diag->code) ? "true" : "false");
  put_field("message", diag->msg, 1, out);
  fputs("}\n", out);
}

void json_summary(const Counts *counts, FILE *out) {
  fprintf(out, "{\"parsed\":%zu,\"typed\":%zu,\"laws\":{\"discharged\":0,\"total\":0}}\n",
          counts->parsed, counts->typed);
}
