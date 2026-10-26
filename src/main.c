/* The langc command line. SHARED by the tcc kits.
   Exit 0: ok. Exit 1: the program is refused. Exit 2: usage or IO. */
#include <stdio.h>
#include <string.h>

#include "front/check.h"
#include "front/front.h"
#include "front/json.h"
#include "front/lower.h"
#include "front/print.h"
#include "target.h"

#define ARENA_LIMIT_BYTES ((size_t)1 << 30)

typedef enum {
  CMD_CHECK,
  CMD_EVAL,
  CMD_IR,
  CMD_ABI,
  CMD_BUILD,
  CMD_FMT
} Command;

typedef struct {
  Command command;
  const char *prog_path;
  const char *entry;
  char **args;
  int arg_count;
  const char *out_path;
  int runtime;
  int json; /* check --json */
} Options;

static const struct {
  const char *word;
  Command command;
} COMMANDS[] = {
  {"check", CMD_CHECK},
  {"eval", CMD_EVAL},
  {"ir", CMD_IR},
  {"abi", CMD_ABI},
  {"build", CMD_BUILD},
  {"fmt", CMD_FMT},
};

static int usage(FILE *err) {
  fputs("usage: langc check [--json] PROG\n"
        "       langc eval PROG NAME [ARGS...]\n"
        "       langc ir PROG\n"
        "       langc abi PROG\n"
        "       langc build PROG -o OUT [--runtime]\n"
        "       langc fmt PROG\n", err);
  return 2;
}

static int find_command(const char *word, Command *out) {
  for (size_t i = 0; i < sizeof COMMANDS / sizeof COMMANDS[0]; i++) {
    if (strcmp(COMMANDS[i].word, word) == 0) {
      *out = COMMANDS[i].command;
      return 1;
    }
  }
  return 0;
}

static int parse_build_options(int argc, char **argv, Options *opt, Diag *diag) {
  for (int i = 3; i < argc; i++) {
    int is_out = strcmp(argv[i], "-o") == 0 && i + 1 < argc;
    int is_runtime = strcmp(argv[i], "--runtime") == 0;
    if (!is_out && !is_runtime) return diag_fail(diag, "USAGE", NULL, "unknown build argument '%s'", argv[i]);
    opt->out_path = is_out ? argv[i + 1] : opt->out_path;
    opt->runtime |= is_runtime;
    i += is_out;
  }
  return opt->out_path != NULL ? 1 : diag_fail(diag, "USAGE", NULL, "build needs -o OUT");
}

static int parse_options(int argc, char **argv, Options *opt, Diag *diag) {
  memset(opt, 0, sizeof *opt);
  if (argc < 3 || !find_command(argv[1], &opt->command)) {
    return diag_fail(diag, "USAGE", NULL, "expected a command and a program path");
  }
  opt->prog_path = argv[2];
  switch (opt->command) {
    case CMD_CHECK:
      opt->json = strcmp(argv[2], "--json") == 0;
      if (argc < 3 + opt->json) return diag_fail(diag, "USAGE", NULL, "check needs a program path");
      if (argc > 3 + opt->json) return diag_fail(diag, "USAGE", NULL, "too many arguments");
      opt->prog_path = argv[2 + opt->json];
      return 1;
    case CMD_IR:
    case CMD_ABI:
    case CMD_FMT:
      return argc == 3 ? 1 : diag_fail(diag, "USAGE", NULL, "too many arguments");
    case CMD_EVAL:
      if (argc < 4) return diag_fail(diag, "USAGE", NULL, "eval needs a definition name");
      opt->entry = argv[3];
      opt->args = argv + 4;
      opt->arg_count = argc - 4;
      return 1;
    case CMD_BUILD:
      return parse_build_options(argc, argv, opt, diag);
  }
  return 0;
}

static int read_source(Arena *arena, const char *path, char **out, size_t *len, Diag *diag) {
  FILE *file = fopen(path, "rb");
  if (file == NULL) return diag_fail(diag, "IO", NULL, "cannot open %s", path);
  char *buf = arena_alloc(arena, SOURCE_MAX_BYTES + 1);
  size_t count = buf == NULL ? 0 : fread(buf, 1, SOURCE_MAX_BYTES + 1, file);
  int read_error = ferror(file);
  fclose(file);
  if (buf == NULL) return diag_fail(diag, "OOM", NULL, "no memory for %s", path);
  if (read_error) return diag_fail(diag, "IO", NULL, "cannot read %s", path);
  if (count > SOURCE_MAX_BYTES) return diag_fail(diag, "IO_SIZE", NULL, "%s is larger than %zu bytes", path, SOURCE_MAX_BYTES);
  *out = buf;
  *len = count;
  return 1;
}

/* Lowers the entries, then runs the ir, abi or build command. */
static int run_target(const Options *opt, Machine *machine, Diag *diag) {
  IrProgram prog;
  FILE *out;
  size_t i;
  int ok = 1;
  if (!lower_program(machine, &prog)) return 1;
  switch (opt->command) {
    case CMD_IR:
      ir_print(&prog, stdout);
      return 0;
    case CMD_ABI:
      for (i = 0; i < prog.func_count && ok; i++) ok = target_abi_line(&prog.funcs[i], stdout, stderr);
      return ok ? 0 : 1;
    case CMD_CHECK:
    case CMD_EVAL:
    case CMD_BUILD:
    case CMD_FMT:
      break;
  }
  out = fopen(opt->out_path, "wb");
  if (out == NULL) return diag_fail(diag, "IO", NULL, "cannot write '%s'", opt->out_path) + 1;
  ok = target_write(&prog, opt->runtime ? TARGET_PART_RUNTIME : TARGET_PART_MAIN, out, stderr);
  return fclose(out) == 0 && ok ? 0 : 1;
}

/* Prints PROG in the canonical form. The domain file is not loaded. */
static int run_fmt(const Options *opt, Arena *arena, const char *text, size_t len, Diag *diag) {
  TokenList toks = {0};
  DeclList decls = {0};
  Printed printed;
  if (!front_parse_one(arena, opt->prog_path, text, len, &toks, &decls, diag)) return 1;
  if (!print_source(arena, &toks, &decls, &printed, diag)) return 1;
  if (fwrite(printed.text, 1, printed.len, stdout) != printed.len || fflush(stdout) != 0) {
    return diag_fail(diag, "IO", NULL, "cannot write the output") + 2;
  }
  return 0;
}

/* The byte AT of TEXT as a line and a column. The column counts code
   points, as the lexer does. */
static void position(const char *text, size_t at, int *line, int *col) {
  *line = 1;
  *col = 1;
  for (size_t i = 0; i < at; i++) {
    int newline = text[i] == '\n';
    int continuation = ((unsigned char)text[i] & 0xC0) == 0x80;
    *line += newline;
    *col = newline ? 1 : continuation ? *col : *col + 1;
  }
}

/* Copies the line of TEXT that holds byte AT into DST, without the
   newline. */
static void copy_line(char *dst, size_t cap, const char *text, size_t len, size_t at) {
  size_t start = at;
  while (start > 0 && text[start - 1] != '\n') start--;
  const char *end = memchr(text + start, '\n', len - start);
  text_copy(dst, cap, text + start, end != NULL ? (size_t)(end - text) - start : len - start);
}

/* Sets WARN to W_NONCANON when TEXT is not in the canonical form. The
   span runs from the first byte that differs to the end of the file.
   A lex or parse failure gives no warning: the caller reports it. */
static void check_canonical(const Options *opt, Arena *arena, const char *text, size_t len, Diag *warn) {
  TokenList toks = {0};
  DeclList decls = {0};
  Printed printed;
  Diag scratch;
  diag_init(&scratch);
  if (!front_parse_one(arena, opt->prog_path, text, len, &toks, &decls, &scratch)) return;
  if (!print_source(arena, &toks, &decls, &printed, &scratch)) return;
  if (printed.len == len && memcmp(printed.text, text, len) == 0) return;
  size_t at = 0;
  while (at < len && at < printed.len && printed.text[at] == text[at]) at++;
  while (at > 0 && at < len && ((unsigned char)text[at] & 0xC0) == 0x80) at--;
  int line, col, end_line, end_col;
  position(text, at, &line, &col);
  position(text, len, &end_line, &end_col);
  char expected[128];
  char found[128];
  copy_line(expected, sizeof expected, printed.text, printed.len, at);
  copy_line(found, sizeof found, text, len, at);
  Span span = {opt->prog_path, line, col, end_line, end_col};
  diag_fail_at(warn, "W_NONCANON", NULL, span, expected, found,
               "%s:%d:%d: the text is not in the canonical form; langc fmt %s prints it",
               opt->prog_path, line, col, opt->prog_path);
  warn->fix = printed.text;
}

/* What `langc check` reports in addition to the first failure. */
typedef struct {
  Diag warn;     /* W_NONCANON, or unset */
  Counts counts; /* the summary of `check --json` */
} Report;

static size_t program_decls(const DeclList *decls) {
  size_t count = 0;
  for (size_t i = 0; i < decls->count; i++) count += decls->items[i].origin == ORIGIN_PROGRAM;
  return count;
}

static int run(const Options *opt, Arena *arena, Diag *diag, Report *rep) {
  char *text = NULL;
  size_t len = 0;
  if (!read_source(arena, opt->prog_path, &text, &len, diag)) return 2;
  if (opt->command == CMD_FMT) return run_fmt(opt, arena, text, len, diag);
  DeclList decls;
  int loaded = front_load(arena, opt->prog_path, text, len, &decls, diag);
  rep->counts.parsed = program_decls(&decls);
  if (!loaded) return 1;
  if (opt->command == CMD_CHECK) check_canonical(opt, arena, text, len, &rep->warn);
  Machine machine;
  int checked = check_program(arena, &decls, &machine, diag);
  rep->counts.typed = machine.typed;
  if (!checked) return 1;
  switch (opt->command) {
    case CMD_CHECK:
      if (!opt->json) puts("ok");
      return 0;
    case CMD_EVAL:
      return eval_command(&machine, opt->entry, opt->args, opt->arg_count, stdout, stderr);
    case CMD_FMT:
    case CMD_IR:
    case CMD_ABI:
    case CMD_BUILD:
      break;
  }
  return run_target(opt, &machine, diag);
}

/* `check --json` writes JSON lines on stdout: the first failure, the
   warning, then the summary. */
static void report_json(int status, const Diag *diag, const Report *rep) {
  if (status != 0 && diag->set) json_diag(diag, stdout);
  if (rep->warn.set) json_diag(&rep->warn, stdout);
  json_summary(&rep->counts, stdout);
}

/* The text mode writes the first failure, then the warning, on stderr. */
static void report_text(int status, const Diag *diag, const Report *rep) {
  if (status != 0 && diag->set) diag_print(diag, stderr);
  if (rep->warn.set) diag_print(&rep->warn, stderr);
}

int main(int argc, char **argv) {
  Diag diag;
  diag_init(&diag);
  Options opt;
  Report rep;
  memset(&rep, 0, sizeof rep);
  if (!parse_options(argc, argv, &opt, &diag)) {
    if (opt.json) {
      report_json(2, &diag, &rep);
      return 2;
    }
    diag_print(&diag, stderr);
    return usage(stderr);
  }
  Arena arena;
  arena_init(&arena, ARENA_LIMIT_BYTES);
  int status = run(&opt, &arena, &diag, &rep);
  if (opt.json) report_json(status, &diag, &rep);
  else report_text(status, &diag, &rep);
  arena_release(&arena);
  return status;
}
