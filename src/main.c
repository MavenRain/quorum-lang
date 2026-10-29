/* The langc command line. SHARED by the tcc kits.
   Exit 0: ok. Exit 1: the program is refused. Exit 2: usage or IO. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>

#include "front/basenames.h"
#include "front/check.h"
#include "front/front.h"
#include "front/json.h"
#include "front/jsonin.h"
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
  CMD_FMT,
  CMD_LAWS,
  CMD_EXPLAIN,
  CMD_LIST_BASE,
  CMD_MCP,
  CMD_HELP
} Command;

typedef struct {
  Command command;
  const char *prog_path;
  const char *entry;
  char **args;
  int arg_count;
  const char *out_path;
  int runtime;
  int json; /* check --json, explain --json */
  const char *name; /* explain NAME */
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
  {"laws", CMD_LAWS},
  {"explain", CMD_EXPLAIN},
  {"list-base", CMD_LIST_BASE},
  {"mcp", CMD_MCP},
  {"help", CMD_HELP},
  {"--help", CMD_HELP},
};

/* The usage text. `langc --help` and `langc help` print it on stdout
   (O118). */
static void print_usage(FILE *out) {
  fputs("usage: langc check [--json] PROG\n"
        "       langc eval PROG NAME [ARGS...]\n"
        "       langc ir PROG\n"
        "       langc abi PROG\n"
        "       langc build PROG -o OUT [--runtime]\n"
        "       langc fmt PROG\n"
        "       langc laws PROG\n"
        "       langc explain [--json] NAME\n"
        "       langc list-base\n"
        "       langc mcp\n"
        "       langc help\n", out);
}

static int usage(FILE *err) {
  print_usage(err);
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
  if (argc < 2 || !find_command(argv[1], &opt->command)) {
    return diag_fail(diag, "USAGE", NULL, "expected a command and a program path");
  }
  if (opt->command == CMD_HELP || opt->command == CMD_LIST_BASE || opt->command == CMD_MCP) {
    return argc == 2 ? 1 : diag_fail(diag, "USAGE", NULL, "too many arguments");
  }
  if (argc < 3) {
    return diag_fail(diag, "USAGE", NULL, "%s",
                     opt->command == CMD_EXPLAIN ? "explain needs a name" : "expected a command and a program path");
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
    case CMD_LAWS:
      return argc == 3 ? 1 : diag_fail(diag, "USAGE", NULL, "too many arguments");
    case CMD_EVAL:
      if (argc < 4) return diag_fail(diag, "USAGE", NULL, "eval needs a definition name");
      opt->entry = argv[3];
      opt->args = argv + 4;
      opt->arg_count = argc - 4;
      return 1;
    case CMD_EXPLAIN:
      opt->json = strcmp(argv[2], "--json") == 0;
      if (argc < 3 + opt->json) return diag_fail(diag, "USAGE", NULL, "explain needs a name");
      if (argc > 3 + opt->json) return diag_fail(diag, "USAGE", NULL, "too many arguments");
      opt->name = argv[2 + opt->json];
      return 1;
    case CMD_LIST_BASE:
    case CMD_MCP:
    case CMD_HELP:
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
    case CMD_LAWS:
    case CMD_EXPLAIN:
    case CMD_LIST_BASE:
    case CMD_MCP:
    case CMD_HELP:
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

/* S4 O64: the program laws, and the laws among the first TYPED program
   declarations. Each of those declarations checks, and R2 refuses a
   postulate, so each of those laws has a proof. */
static void count_laws(const DeclList *decls, Counts *counts) {
  size_t k = 0;
  counts->laws = 0;
  counts->discharged = 0;
  for (size_t i = 0; i < decls->count; i++) {
    const Decl *d = &decls->items[i];
    int law = d->origin == ORIGIN_PROGRAM && d->is_law;
    counts->laws += law;
    counts->discharged += law && k < counts->typed;
    k += d->origin == ORIGIN_PROGRAM;
  }
}

/* `langc laws`: one line for each program law in source order, then the
   counts. Exit 0 only when the program checks and each law is discharged. */
static int print_laws(const DeclList *decls, const Counts *counts, int checked) {
  size_t k = 0;
  for (size_t i = 0; i < decls->count; i++) {
    const Decl *d = &decls->items[i];
    if (d->origin == ORIGIN_PROGRAM && d->is_law)
      printf("law %s %s\n", d->name, k < counts->typed ? "discharged" : "open");
    k += d->origin == ORIGIN_PROGRAM;
  }
  printf("laws: %zu of %zu discharged\n", counts->discharged, counts->laws);
  return checked && counts->discharged == counts->laws ? 0 : 1;
}

static int run(const Options *opt, Arena *arena, Diag *diag, Report *rep) {
  char *text = NULL;
  size_t len = 0;
  if (!read_source(arena, opt->prog_path, &text, &len, diag)) return 2;
  if (opt->command == CMD_FMT) return run_fmt(opt, arena, text, len, diag);
  DeclList decls;
  int loaded = front_load(arena, opt->prog_path, text, len, &decls, diag);
  rep->counts.parsed = program_decls(&decls);
  count_laws(&decls, &rep->counts);
  if (!loaded)
    return opt->command == CMD_LAWS ? print_laws(&decls, &rep->counts, 0) : 1;
  if (opt->command == CMD_CHECK) check_canonical(opt, arena, text, len, &rep->warn);
  Machine machine;
  int checked = check_program(arena, &decls, &machine, diag);
  rep->counts.typed = machine.typed;
  count_laws(&decls, &rep->counts);
  if (opt->command == CMD_LAWS) return print_laws(&decls, &rep->counts, checked);
  if (!checked) return 1;
  switch (opt->command) {
    case CMD_CHECK:
      if (!opt->json) puts("ok");
      return 0;
    case CMD_EVAL:
      return eval_command(&machine, opt->entry, opt->args, opt->arg_count, stdout, stderr);
    case CMD_FMT:
    case CMD_LAWS:
    case CMD_IR:
    case CMD_ABI:
    case CMD_BUILD:
    case CMD_EXPLAIN:
    case CMD_LIST_BASE:
    case CMD_MCP:
    case CMD_HELP:
      break;
  }
  return run_target(opt, &machine, diag);
}

/* The R1 class of a family (O25). */
static const char *class_name(FamilyClass r1) {
  switch (r1) {
    case FAMILY_BASE:
      return "base type";
    case FAMILY_CM:
      return "CM";
    case FAMILY_INDEXED:
      return "indexed family";
    case FAMILY_RECORD:
      return "record";
  }
  return NULL;
}

/* The R1 class of the family NAME of M, or NULL when M has no family
   NAME. */
static const char *class_of(const Machine *m, const char *name) {
  for (uint32_t i = 0; i < m->family_count; i++) {
    if (strcmp(m->families[i].name, name) == 0) return class_name(m->families[i].r1);
  }
  return NULL;
}

/* `langc list-base`: the PLAN sec 3 names, one on each line (O120). */
static int list_base(FILE *out) {
  for (size_t i = 0; i < BASE_NAME_COUNT; i++) fprintf(out, "%s\n", BASE_NAMES[i].name);
  return fflush(out) == 0 ? 0 : 2;
}

static void json_or_null(const char *text, FILE *out) {
  if (text != NULL) json_string(text, out);
  else fputs("null", out);
}

/* `langc explain [--json] NAME` (O119): the kind and the slice of a PLAN
   sec 3 name, and its type and R1 class in the environment of the domain
   file and lib/prelude.lang. The type and the class are null when that
   environment has no global NAME. It writes on OUT. */
static int run_explain(const Options *opt, Arena *arena, Diag *diag, FILE *out) {
  const BaseName *base = base_name_find(opt->name);
  if (base == NULL) {
    return diag_fail(diag, "NAME_UNKNOWN", NULL, "unknown name %s; langc list-base prints the names", opt->name) + 1;
  }
  DeclList decls;
  Machine machine;
  Printed type;
  if (!front_load(arena, "lib/prelude.lang", (const char *)prelude_source, prelude_source_len, &decls, diag)) return 1;
  if (!check_program(arena, &decls, &machine, diag)) return 1;
  if (!print_global_type(arena, &decls, opt->name, &type, diag)) return 1;
  const char *r1 = type.text != NULL ? class_of(&machine, opt->name) : NULL;
  if (opt->json) {
    fputs("{\"name\":", out);
    json_string(base->name, out);
    fputs(",\"kind\":", out);
    json_string(base->kind, out);
    fputs(",\"type\":", out);
    json_or_null(type.text, out);
    fputs(",\"class\":", out);
    json_or_null(r1, out);
    fputs(",\"slice\":", out);
    json_string(base->slice, out);
    fputs("}\n", out);
  } else {
    fprintf(out, "%s%s%s\n", base->name, type.text != NULL ? " : " : "", type.text != NULL ? type.text : "");
    fprintf(out, "kind: %s; class: %s; slice: %s\n", base->kind, r1 != NULL ? r1 : "-", base->slice);
  }
  return fflush(out) == 0 ? 0 : 2;
}

/* `check --json` writes JSON lines on OUT: the first failure, the
   warning, then the summary. */
static void report_json(int status, const Diag *diag, const Report *rep, FILE *out) {
  if (status != 0 && diag->set) json_diag(diag, out);
  if (rep->warn.set) json_diag(&rep->warn, out);
  json_summary(&rep->counts, out);
}

/* The text mode writes the first failure, then the warning, on stderr. */
static void report_text(int status, const Diag *diag, const Report *rep) {
  if (status != 0 && diag->set) diag_print(diag, stderr);
  if (rep->warn.set) diag_print(&rep->warn, stderr);
}

/* JSON-RPC 2.0 error codes (O121). */
enum {
  RPC_PARSE = -32700,
  RPC_BAD_REQUEST = -32600,
  RPC_UNKNOWN_METHOD = -32601,
  RPC_BAD_PARAMS = -32602,
  RPC_INTERNAL = -32603
};

/* The tools/list result (O122). */
static const char MCP_TOOLS[] =
  "{\"tools\":["
  "{\"name\":\"check\",\"description\":\"Checks the quorum-lang program at path. The text is the langc check --json lines.\","
  "\"inputSchema\":{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\"}},\"required\":[\"path\"]}},"
  "{\"name\":\"explain\",\"description\":\"Gives the kind, the type, the R1 class and the slice of a PLAN sec 3 name as one JSON line.\","
  "\"inputSchema\":{\"type\":\"object\",\"properties\":{\"name\":{\"type\":\"string\"}},\"required\":[\"name\"]}},"
  "{\"name\":\"list-base\",\"description\":\"Gives the PLAN sec 3 names, one on each line.\","
  "\"inputSchema\":{\"type\":\"object\",\"properties\":{}}},"
  "{\"name\":\"show-law\",\"description\":\"Gives the canonical text of the law name of the program at path, then discharged or open.\","
  "\"inputSchema\":{\"type\":\"object\",\"properties\":{\"path\":{\"type\":\"string\"},\"name\":{\"type\":\"string\"}},"
  "\"required\":[\"path\",\"name\"]}}"
  "]}";

/* Writes the id of a request: a string, a number or null. */
static void put_id(const JsonValue *id, FILE *out) {
  if (id != NULL && id->kind == JSON_STRING) {
    json_string_n(id->text, id->len, out);
    return;
  }
  fputs(id != NULL && id->kind == JSON_NUMBER ? id->text : "null", out);
}

static void rpc_head(const JsonValue *id, FILE *out) {
  fputs("{\"jsonrpc\":\"2.0\",\"id\":", out);
  put_id(id, out);
}

static void rpc_error(const JsonValue *id, int code, const char *message, FILE *out) {
  rpc_head(id, out);
  fprintf(out, ",\"error\":{\"code\":%d,\"message\":", code);
  json_string(message, out);
  fputs("}}\n", out);
}

/* `initialize` echoes the protocolVersion of the client. */
static void mcp_initialize(const JsonValue *id, const JsonValue *params, FILE *out) {
  const char *version = json_get_string(json_member(params, "protocolVersion"));
  if (version == NULL) {
    rpc_error(id, RPC_BAD_PARAMS, "Invalid params", out);
    return;
  }
  rpc_head(id, out);
  fputs(",\"result\":{\"protocolVersion\":", out);
  json_string(version, out);
  fputs(",\"capabilities\":{\"tools\":{}},\"serverInfo\":{\"name\":\"quorum-lang\",\"version\":\"S9\"}}}\n", out);
}

static void mcp_ping(const JsonValue *id, const JsonValue *params, FILE *out) {
  (void)params;
  rpc_head(id, out);
  fputs(",\"result\":{}}\n", out);
}

static void mcp_tools_list(const JsonValue *id, const JsonValue *params, FILE *out) {
  (void)params;
  rpc_head(id, out);
  fputs(",\"result\":", out);
  fputs(MCP_TOOLS, out);
  fputs("}\n", out);
}

/* The `check` tool: the `check --json` lines of PATH. */
static int tool_check(const char *path, FILE *out) {
  Options opt;
  Report rep;
  Diag diag;
  Arena arena;
  memset(&opt, 0, sizeof opt);
  memset(&rep, 0, sizeof rep);
  opt.command = CMD_CHECK;
  opt.prog_path = path;
  opt.json = 1;
  diag_init(&diag);
  diag_init(&rep.warn);
  arena_init(&arena, ARENA_LIMIT_BYTES);
  int status = run(&opt, &arena, &diag, &rep);
  report_json(status, &diag, &rep, out);
  arena_release(&arena);
  return status != 0;
}

/* The `explain` tool: the `explain --json` line of NAME, or the
   diagnostic. */
static int tool_explain(const char *name, FILE *out) {
  Options opt;
  Diag diag;
  Arena arena;
  memset(&opt, 0, sizeof opt);
  opt.command = CMD_EXPLAIN;
  opt.name = name;
  opt.json = 1;
  diag_init(&diag);
  arena_init(&arena, ARENA_LIMIT_BYTES);
  int status = run_explain(&opt, &arena, &diag, out);
  if (status != 0 && diag.set) diag_print(&diag, out);
  arena_release(&arena);
  return status != 0;
}

/* The canonical text of the program law NAME of PATH, then `discharged`
   or `open` by the rule of print_laws. A check failure leaves the laws
   after it open. */
static int show_law(Arena *arena, const char *path, const char *name, FILE *out, Diag *diag) {
  char *text = NULL;
  size_t len = 0;
  DeclList decls;
  Machine machine;
  Printed printed;
  TokenList toks = {0};
  if (!read_source(arena, path, &text, &len, diag)) return 2;
  if (!front_load(arena, path, text, len, &decls, diag)) return 1;
  size_t k = 0;
  size_t at = decls.count;
  for (size_t i = 0; i < decls.count; i++) {
    const Decl *d = &decls.items[i];
    int hit = at == decls.count && d->origin == ORIGIN_PROGRAM && d->is_law && strcmp(d->name, name) == 0;
    at = hit ? i : at;
    k += at == decls.count && d->origin == ORIGIN_PROGRAM;
  }
  if (at == decls.count) {
    return diag_fail(diag, "NAME_UNKNOWN", NULL, "%s has no law %s; langc laws %s prints the laws", path, name, path) + 1;
  }
  Diag scratch;
  diag_init(&scratch);
  machine.typed = 0;
  check_program(arena, &decls, &machine, &scratch);
  DeclList one = decls;
  one.items = decls.items + at;
  one.count = 1;
  if (!print_source(arena, &toks, &one, &printed, diag)) return 1;
  fputs(printed.text, out);
  if (printed.len == 0 || printed.text[printed.len - 1] != '\n') fputc('\n', out);
  fprintf(out, "%s\n", k < machine.typed ? "discharged" : "open");
  return fflush(out) == 0 ? 0 : 2;
}

/* The `show-law` tool. */
static int tool_show_law(const char *path, const char *name, FILE *out) {
  Diag diag;
  Arena arena;
  diag_init(&diag);
  arena_init(&arena, ARENA_LIMIT_BYTES);
  int status = show_law(&arena, path, name, out, &diag);
  if (status != 0 && diag.set) diag_print(&diag, out);
  arena_release(&arena);
  return status != 0;
}

/* Runs the tool NAME with ARGS and writes its text on OUT. Returns 0, 1
   for isError true, or -1 for bad params. */
static int call_tool(const char *name, const JsonValue *args, FILE *out) {
  const char *path = json_get_string(json_member(args, "path"));
  const char *word = json_get_string(json_member(args, "name"));
  if (strcmp(name, "check") == 0) return path != NULL ? tool_check(path, out) : -1;
  if (strcmp(name, "explain") == 0) return word != NULL ? tool_explain(word, out) : -1;
  if (strcmp(name, "list-base") == 0) return list_base(out) != 0;
  if (strcmp(name, "show-law") == 0) return path != NULL && word != NULL ? tool_show_law(path, word, out) : -1;
  return -1;
}

/* `tools/call` gives one text item with the text of the tool (R-H3-1). */
static void mcp_call(const JsonValue *id, const JsonValue *params, FILE *out) {
  const char *name = json_get_string(json_member(params, "name"));
  const JsonValue *args = json_member(params, "arguments");
  if (name == NULL || (args != NULL && args->kind != JSON_OBJECT)) {
    rpc_error(id, RPC_BAD_PARAMS, "Invalid params", out);
    return;
  }
  char *text = NULL;
  size_t len = 0;
  FILE *capture = open_memstream(&text, &len);
  if (capture == NULL) {
    rpc_error(id, RPC_INTERNAL, "Internal error", out);
    return;
  }
  int status = call_tool(name, args, capture);
  int closed = fclose(capture) == 0;
  if (status < 0 || !closed) {
    rpc_error(id, closed ? RPC_BAD_PARAMS : RPC_INTERNAL, closed ? "Invalid params" : "Internal error", out);
    free(text);
    return;
  }
  rpc_head(id, out);
  fputs(",\"result\":{\"content\":[{\"type\":\"text\",\"text\":", out);
  json_string(text != NULL ? text : "", out);
  fprintf(out, "}],\"isError\":%s}}\n", status != 0 ? "true" : "false");
  free(text);
}

typedef void (*McpMethod)(const JsonValue *id, const JsonValue *params, FILE *out);

static const struct {
  const char *name;
  McpMethod run;
} MCP_METHODS[] = {
  {"initialize", mcp_initialize},
  {"ping", mcp_ping},
  {"tools/list", mcp_tools_list},
  {"tools/call", mcp_call},
};

/* An id is absent, a string, a number or null. */
static int id_ok(const JsonValue *id) {
  return id == NULL || id->kind == JSON_NUMBER || id->kind == JSON_NULL || id->kind == JSON_STRING;
}

/* Answers the message in the LEN bytes of LINE on OUT. A notification (a
   request without an id) gets no reply. */
static void mcp_message(Arena *arena, const char *line, size_t len, FILE *out) {
  JsonValue msg;
  Diag diag;
  diag_init(&diag);
  if (!json_parse(arena, line, len, &msg, &diag)) {
    rpc_error(NULL, RPC_PARSE, "Parse error", out);
    return;
  }
  const JsonValue *id = json_member(&msg, "id");
  const JsonValue *params = json_member(&msg, "params");
  const char *version = json_get_string(json_member(&msg, "jsonrpc"));
  const JsonValue *method = json_member(&msg, "method");
  int valid = version != NULL && strcmp(version, "2.0") == 0
    && method != NULL && method->kind == JSON_STRING && id_ok(id)
    && (params == NULL || params->kind == JSON_OBJECT || params->kind == JSON_ARRAY);
  if (!valid) {
    rpc_error(id_ok(id) ? id : NULL, RPC_BAD_REQUEST, "Invalid Request", out);
    return;
  }
  if (id == NULL) return;
  for (size_t i = 0; i < sizeof MCP_METHODS / sizeof MCP_METHODS[0]; i++) {
    if (strlen(MCP_METHODS[i].name) == method->len
        && memcmp(MCP_METHODS[i].name, method->text, method->len) == 0) {
      MCP_METHODS[i].run(id, params, out);
      return;
    }
  }
  rpc_error(id, RPC_UNKNOWN_METHOD, "Method not found", out);
}

/* `langc mcp` (O121): the MCP stdio transport. One JSON-RPC 2.0 message on
   each stdin line, one reply line on stdout, no Content-Length frame. An
   empty line gets no reply. EOF gives exit 0. */
static int run_mcp(void) {
  char *line = NULL;
  size_t cap = 0;
  ssize_t got;
  int ok = 1;
  while (ok && (got = getline(&line, &cap, stdin)) >= 0) {
    size_t len = (size_t)got;
    len -= len > 0 && line[len - 1] == '\n';
    len -= len > 0 && line[len - 1] == '\r';
    Arena arena;
    arena_init(&arena, ARENA_LIMIT_BYTES);
    if (len > 0) mcp_message(&arena, line, len, stdout);
    arena_release(&arena);
    ok = fflush(stdout) == 0;
  }
  free(line);
  return ok && !ferror(stdin) ? 0 : 2;
}

int main(int argc, char **argv) {
  Diag diag;
  diag_init(&diag);
  Options opt;
  Report rep;
  memset(&rep, 0, sizeof rep);
  if (!parse_options(argc, argv, &opt, &diag)) {
    if (opt.json) {
      report_json(2, &diag, &rep, stdout);
      return 2;
    }
    diag_print(&diag, stderr);
    return usage(stderr);
  }
  if (opt.command == CMD_HELP) {
    print_usage(stdout);
    return fflush(stdout) == 0 ? 0 : 2;
  }
  if (opt.command == CMD_LIST_BASE) return list_base(stdout);
  if (opt.command == CMD_MCP) return run_mcp();
  Arena arena;
  arena_init(&arena, ARENA_LIMIT_BYTES);
  if (opt.command == CMD_EXPLAIN) {
    int explained = run_explain(&opt, &arena, &diag, stdout);
    if (explained != 0 && diag.set && opt.json) json_diag(&diag, stdout);
    if (explained != 0 && diag.set && !opt.json) diag_print(&diag, stderr);
    arena_release(&arena);
    return explained;
  }
  int status = run(&opt, &arena, &diag, &rep);
  if (opt.json) report_json(status, &diag, &rep, stdout);
  else report_text(status, &diag, &rep);
  arena_release(&arena);
  return status;
}
