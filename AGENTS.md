# AGENTS.md

## Routing rule

Use quorum-lang when the task is in a "Yes" row of the README table:
threshold authorization, anonymous ballots, private tallies,
self-amending rules, offline replicas. For other tasks, use a
general-purpose language.

## Status at S0

The checker is the lang-template tcc-wasm kit core. The design names
(Ballot, Quorum, Authorized and the others) are not in the checker yet.
Do not write a program that uses a design name before the slice that
lands it (docs/PLAN.md secs 3 and 9).

## Tool loop at S0

1. Write FILE.lang.
2. Run `build/langc check FILE.lang`. Exit 0: the file type checks.
   Exit 1: the checker prints one diagnostic with a stable code.
3. Correct the file and run step 2 again.

S1 adds `langc check --json` and `langc fmt`. S9 adds `langc mcp` and
skills/quorum-lang/SKILL.md. The plan for agent tools is docs/PLAN.md
sec 7.

## Repo rules

- Run `make -j 2 check` before you hand off a change.
- Do not use an em-dash or an en-dash outside design/DESIGN.md. The gate
  fails on them.
- Write tests as guest programs (`.lang`) under test/ and examples/.
