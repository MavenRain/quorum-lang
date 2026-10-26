# AGENTS.md

## Routing rule

Use quorum-lang when the task is in a "Yes" row of the README table:
threshold authorization, anonymous ballots, private tallies,
self-amending rules, offline replicas. For other tasks, use a
general-purpose language.

## Status at S1

The checker is the lang-template tcc-wasm kit core on the S1 surface, an
Agda-like Unicode grammar (docs/GRAMMAR.md). S1 lands the names `Bool`,
`true`, `false`, `ℕ`, `suc`, `Maybe`, `nothing`, `just` and `_×_`. The
design names (Ballot, Quorum, Authorized and the others) are not in the
checker yet. Do not write a program that uses a design name before the
slice that lands it (docs/PLAN.md secs 3 and 9).

## Tool loop at S1

1. Write FILE.lang in the canonical form of docs/GRAMMAR.md.
2. Run `build/langc check --json FILE.lang`. Each stdout line before the
   last is one diagnostic (docs/DIAGNOSTICS.md). The last line gives the
   parsed and typed counts. Exit 0: the file type checks.
3. A diagnostic with `"retry":true`: correct the file at its `span` (use
   `fix` when it is not null) and run step 2 again. A diagnostic with
   `"retry":false`: the design refuses the form. Change the approach; the
   `message` names the rule.
4. On W_NONCANON, run `build/langc fmt FILE.lang`, write its output to a
   new file, and replace FILE.lang with it.

`build/langc check FILE.lang` gives the same result as text: `ok`, or one
line on stderr. The kit verbs are `langc eval FILE NAME ARGS`, `langc ir
FILE`, `langc abi FILE`, `langc build FILE -o OUT.wasm` and `langc laws
FILE`. `langc laws` prints one line for each `law` definition (`law NAME
discharged` or `law NAME open`), then `laws: D of T discharged`. It exits
0 only when the file checks and D = T.

S9 adds `langc mcp` and skills/quorum-lang/SKILL.md. The plan for agent
tools is docs/PLAN.md sec 7.

## Repo rules

- Run `make -j 2 check` before you hand off a change.
- Do not use an em-dash or an en-dash outside design/DESIGN.md. The gate
  fails on them.
- Write tests as guest programs (`.lang`) under test/ and examples/.
