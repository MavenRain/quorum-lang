/* Domain declaration regressions use the same parser and checker as langc. */
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <sys/wait.h>
#include <unistd.h>

#include "front/check.h"
#include "front/lexer.h"
#include "front/json.h"
#include "front/parser.h"

static int domain(const char *text, const char *want) {
  Arena arena;
  Diag diag;
  TokenList tokens = {0};
  DeclList decls = {0};
  Machine machine;
  arena_init(&arena, (size_t)1 << 24);
  diag_init(&diag);
  int ok = lex_source(&arena, "test-domain", text, strlen(text), &tokens, &diag)
    && parse_source(&arena, "test-domain", ORIGIN_DOMAIN, &tokens, &decls, &diag)
    && check_program(&arena, &decls, &machine, &diag);
  int passed = want == NULL ? ok : !ok && diag.code != NULL && strcmp(diag.code, want) == 0;
  if (!passed) {
    fprintf(stderr, "FAIL domain: wanted %s, got %s: %s\n", want == NULL ? "ok" : want,
            ok ? "ok" : diag.code == NULL ? "no diagnostic" : diag.code, text);
  }
  arena_release(&arena);
  return passed;
}

static int lex_case(const char *text, size_t len, int line, int col) {
  Arena arena;
  Diag diag;
  TokenList tokens = {0};
  arena_init(&arena, (size_t)1 << 20);
  diag_init(&diag);
  int ok = lex_source(&arena, "test-encoding", text, len, &tokens, &diag);
  int passed = line == 0 ? ok : !ok && diag.code != NULL && strcmp(diag.code, "LEX_CHAR") == 0
    && diag.span.line == line && diag.span.col == col && diag.span.end_line == line && diag.span.end_col == col + 1;
  if (!passed) fprintf(stderr, "FAIL encoding: expected %d:%d, got %s at %d:%d\n", line, col,
                       ok ? "ok" : diag.code == NULL ? "no diagnostic" : diag.code, diag.span.line, diag.span.col);
  arena_release(&arena);
  return passed;
}

static int encoding(void) {
  static const char *const invalid[] = {
    "\x80", "\xc0\x80", "\xc1\xbf", "\xc2", "\xc2 ", "\xe0\x80\x80",
    "\xed\xa0\x80", "\xe2\x82", "\xf0\x80\x80\x80", "\xf4\x90\x80\x80", "\xf5\x80\x80\x80", "\xff"
  };
  int ok = 1;
  for (size_t i = 0; i < sizeof invalid / sizeof invalid[0]; i++)
    ok &= lex_case(invalid[i], strlen(invalid[i]), 1, 1);
  static const char comment[] = "-- α 😀\n-- invalid \xff";
  static const char nul[] = "-- hidden\0text\n";
  static const char valid[] = "-- \xc2\x80\xed\x9f\xbf\xee\x80\x80\xf4\x8f\xbf\xbf\nα : ℕ\nα = 0\n";
  ok &= lex_case(comment, sizeof comment - 1, 2, 12);
  ok &= lex_case(nul, sizeof nul - 1, 1, 10);
  ok &= lex_case(valid, sizeof valid - 1, 0, 0);
  return ok;
}

static int json_text(void) {
  Diag diag;
  char name[1201];
  for (size_t i = 0; i < 300; i++) memcpy(name + i * 4, "😀", 4);
  name[sizeof name - 1] = '\0';
  diag_init(&diag);
  diag_fail_at(&diag, "NAME_UNKNOWN", NULL, (Span){"bad\xff.lang", 1, 1, 1, 2}, NULL, NULL,
               "unknown name %s", name);
  FILE *out = tmpfile();
  if (out == NULL) return 0;
  json_diag(&diag, out);
  rewind(out);
  char text[4096];
  size_t len = fread(text, 1, sizeof text - 1, out);
  text[len] = '\0';
  int ok = !ferror(out) && feof(out) && strstr(text, "bad\\ufffd.lang") != NULL;
  for (size_t pos = 0; ok && pos < len;) {
    size_t width = utf8_char_size(text + pos, len - pos);
    ok = width != 0;
    pos += width;
  }
  fclose(out);
  if (!ok) fputs("FAIL JSON: invalid UTF-8 in a diagnostic string\n", stderr);
  return ok;
}

static int cli_usage(int extra) {
  int fds[2];
  if (pipe(fds) != 0) return 0;
  pid_t child = fork();
  if (child == 0) {
    close(fds[0]);
    if (dup2(fds[1], STDOUT_FILENO) < 0 || dup2(fds[1], STDERR_FILENO) < 0) _exit(127);
    close(fds[1]);
    char *args[] = {"build/langc", "check", "--json", NULL, NULL, NULL};
    if (extra) {
      args[3] = "examples/functions.lang";
      args[4] = "extra";
    }
    execv(args[0], args);
    _exit(127);
  }
  close(fds[1]);
  if (child < 0) {
    close(fds[0]);
    return 0;
  }
  char text[2048];
  size_t len = 0;
  ssize_t got;
  while (len < sizeof text - 1) {
    got = read(fds[0], text + len, sizeof text - 1 - len);
    if (got < 0 && errno == EINTR) continue;
    if (got <= 0) break;
    len += (size_t)got;
  }
  close(fds[0]);
  text[len] = '\0';
  int status;
  pid_t waited;
  do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
  char want[512];
  snprintf(want, sizeof want, "{\"code\":\"USAGE\",\"span\":null,\"expected\":null,\"found\":null,\"fix\":null,\"retry\":false,\"message\":\"%s\"}\n"
           "{\"parsed\":0,\"typed\":0,\"laws\":{\"discharged\":0,\"total\":0}}\n",
           extra ? "too many arguments" : "check needs a program path");
  int ok = waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 2 && strcmp(text, want) == 0;
  if (!ok) fprintf(stderr, "FAIL JSON usage (%s): %s\n", extra ? "extra argument" : "missing path", text);
  return ok;
}

int main(void) {
  int ok = encoding() & json_text();
  ok &= cli_usage(0);
  ok &= cli_usage(1);
  ok &= domain("data F : Type where\n  makeF : (field : ℕ) → (field : Bool) → F", "REFUSE_NAME");
  ok &= domain("data F : Type where\n  makeF : (makeF : ℕ) → F", "REFUSE_NAME");
  ok &= domain("data F : Type where\n  makeF : (firstField : ℕ) → (secondField : Bool) → F", NULL);
  ok &= domain("data F : Type where\n  a : (field : ℕ) → F\n  b : (field : ℕ) → F", "REFUSE_NAME");
  ok &= domain("s : Maybe ℕ\ns = just 7\n\nbad : Maybe Bool\nbad = bind s (λ (x : ℕ) → just x)", "TYPE_MISMATCH");
  ok &= domain("data Lot (n : ℕ) : Type where\n  makeLot : (amount : ℕ) → Lot n\n\n"
               "s : Maybe ℕ\ns = just 0\n\n"
               "f : (n : ℕ) → ℕ → Lot n\nf n x = makeLot n x\n\n"
               "bad : (n : ℕ) → Lot n\nbad = fst (option f (λ (k : ℕ) → f) s , 0)", "TYPE_MISMATCH");
  ok &= domain("bad : Type₁\nbad = ℕ", "TYPE_MISMATCH");
  ok &= domain("bad : Type₂\nbad = Type₁", "TYPE_UNIVERSE");
  ok &= domain("data U : Type₁ where\n  makeU : (decode : Type) → U\n\nbad : Type\nbad = U", "TYPE_MISMATCH");
  ok &= domain("data U : Type₁ where\n  makeU : (decode : Type) → U\n\n"
               "data W : Type₁ where\n  makeW : (wrapped : U) → W\n\nbad : Type\nbad = W", "TYPE_MISMATCH");
  ok &= domain("data Box (A : Type₁) : Type₁ where\n  box : (unbox : A) → Box A\n\nbad : Type\nbad = Box Type", "TYPE_MISMATCH");
  ok &= domain("data U : Type₁ where\n  makeU : (decode : Type) → U\n\ngood : Type₁\ngood = U", NULL);
  ok &= domain("eta : (p : ℕ × ℕ) → (fst p , snd p) ≡ p\neta p = refl", NULL);
  ok &= domain("eta : (p : Σ ℕ (λ n → n ≡ n)) → p ≡ (fst p , snd p)\n"
               "eta p = refl", NULL);
  if (ok) puts("domain regressions: passed");
  return ok ? 0 : 1;
}
