# AGENTS.md

## Routing rule

Use quorum-lang when the task is in a "Yes" row of the README table:
threshold authorization, anonymous ballots, private tallies,
self-amending rules, offline replicas. For other tasks, use a
general-purpose language.

## Status at S9

The checker is the lang-template tcc-wasm kit core on an Agda-like
Unicode grammar (docs/GRAMMAR.md). The base names of the design (Ballot,
Quorum, Authorized and the others) are in the checker. `langc list-base`
prints them. A program has no imports: define each name that the program
uses, as the 5 programs of examples/agent/ do.

## Tool loop

1. Write FILE.lang in the canonical form of docs/GRAMMAR.md.
2. Run `build/langc check --json FILE.lang`. Each stdout line before the
   last is one diagnostic (docs/DIAGNOSTICS.md). The last line gives the
   parsed and typed counts and the laws. Exit 0: the file type checks.
3. A diagnostic with `"retry":true`: correct the file at its `span` (use
   `fix` when it is not null) and run step 2 again. A diagnostic with
   `"retry":false`: the design refuses the form. Change the approach; the
   `message` names the rule.
4. On W_NONCANON, run `build/langc fmt FILE.lang`, write its output to a
   new file, and replace FILE.lang with it.
5. Run `build/langc laws FILE.lang`. It exits 0 only when the file checks
   and each law is discharged.

`build/langc check FILE.lang` gives the same result as text: `ok`, or one
line on stderr. The kit verbs are `langc eval FILE NAME ARGS`, `langc ir
FILE`, `langc abi FILE`, `langc build FILE -o OUT.wasm` and `langc laws
FILE`. `langc laws` prints one line for each `law` definition (`law NAME
discharged` or `law NAME open`), then `laws: D of T discharged`. It exits
0 only when the file checks and D = T.

`langc explain [--json] NAME` gives the kind, class and slice of one base
name. `langc mcp` is a JSON-RPC 2.0 server on stdin and stdout, one
message on each line. Its 4 tools are `check` (`path`), `explain`
(`name`), `list-base` (no arguments) and `show-law` (`path`, `name`).
skills/quorum-lang/SKILL.md gives this loop as a skill, with the card of
docs/GRAMMAR.md and a copy of each program of examples/agent/.
docs/PLAN.md sec 7 maps agent adoption to deliverables.

## Repo rules

- Run `make -j 2 check` before you hand off a change.
- Do not use an em-dash or an en-dash outside design/DESIGN.md. The gate
  fails on them.
- Write tests as guest programs (`.lang`) under test/ and examples/.
