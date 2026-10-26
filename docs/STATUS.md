# quorum-lang status

The build implements slice S1 of `docs/PLAN.md` sec 9: the Agda-like
Unicode surface, `langc fmt`, `langc check --json` with the progress
counts, and the kit formers under rules R1 and R2. Slices S2 to S12 are
not started. The next slice is S2, the kernel.

## Implemented

- S0 kit: one C99 program, `build/langc`, holds the parser, the checker,
  the evaluator, the lowering to a first-order IR and the Wasm writer.
- Surface (Q13 (b)): UTF-8 names and symbols, `data X : Type where`,
  `f : A → B` with clauses, `λ x → t`. `docs/GRAMMAR.md` gives the
  grammar and the canonical form.
- Formers: F1 `_×_`, F3 `Maybe` (`nothing`, `just`), F5 `pure`, `map`,
  `bind`, F6 `fold`, F9 to F11 (functions and `Σ`), F12 and F13 (`Eq`),
  F14 universes. Core types: `Bool` (`true`, `false`) and `ℕ` (`suc`).
- Refusals: `List`, `cons`, `nil` and `unfold` give `REFUSE_CELL` (R1).
  `Sum`, `inl`, `inr`, `either` and `filter` give `REFUSE_BASE` (R2).
- `langc fmt FILE`: the canonical printer. A non-canonical spelling gives
  `W_NONCANON` with the canonical text as `fix`.
- `langc check --json`: one JSON object for each diagnostic (`code`,
  `span`, `expected`, `found`, `fix`, `retry`), then a last line with the
  parsed and typed counts. `docs/DIAGNOSTICS.md` gives each code.
- Gate counts at S1: 56 files canonical under `fmt`, 19 JSON fixtures,
  30 codes with a fixture or a gate line, 745 differential cases with 0
  mismatches, 13 Wasm modules valid.
- Mutants at S1 (3 of 3 killed): `fmt` prints `Type₀` for level 0 (the
  `fmt` loop fails), the `retry` key dropped from the JSON line (each
  test/json fixture fails), the typed count starts at 1 (the
  partial-program fixture fails).

## Remaining work

1. S2, the kernel: Path, PathP, I, transp, hcomp, Π, Σ, U and levels;
   `REFUSE_CELL` for CMs only (Q1 (b)). It needs the S1 commit first.
2. S3 to S12: see `docs/PLAN.md` sec 9. Q7 must be ruled before S6, Q14
   before S10 and Q15 before S11.

## Known limits

- Fuel: an evaluation stops after 20000000 steps with `EVAL_FUEL`
  (`EVAL_FUEL_STEPS`, src/front/core.h).
- Depth: an evaluation deeper than 2000 frames stops with `EVAL_DEPTH`
  (`EVAL_DEPTH_LIMIT`, src/front/core.h). The cause is the C stack.
- Memory: the arena limit is 1 GiB (`ARENA_LIMIT_BYTES`, src/main.c). A
  program that fills it gives `OOM`.
- Input: a source file larger than 1 MiB gives `IO_SIZE`.
- Laws: the `laws` counts in `check --json` stay 0 of 0 until S4.
- Data: only `domain/domain.lang` can declare a data type
  (`REFUSE_DATA`).

## Internal boundaries

The front end is in src/front: the lexer (lexer.c), the parser
(parser.c), the canonical printer for `fmt` (print.c), the JSON
diagnostic printer (json.c), the checker (check.c), the evaluator and
the conversion test (eval.c), and the lowering to the first-order IR
(lower.c). base.c holds the arena. src/main.c holds the verbs. src/wasm.c
writes the Wasm 1.0 module.

test/gate.sh holds the gate lines: the examples, the `fmt` loop over each
committed `.lang` file, the test/fmt and test/json fixtures, the code
check against the table in `docs/DIAGNOSTICS.md`, and the Wasm
differential. test/review.sh holds the review regressions.

A program cannot use the refused names above. Only `domain/domain.lang`
declares data types.
