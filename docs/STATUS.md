# quorum-lang status

The build implements slices S1 and S2 of `docs/PLAN.md` sec 9. S1 is the
Agda-like Unicode surface, `langc fmt`, `langc check --json` with the
progress counts, and the kit formers under rules R1 and R2. S2 is the
cubical kernel and `REFUSE_CELL` for cell monads (CMs) only (Q1 (b)).
Slices S3 to S12 are not started. The next slice is S3.

## Implemented

- S0 kit: one C99 program, `build/langc`, holds the parser, the checker,
  the evaluator, the lowering to a first-order IR and the Wasm writer.
- Surface (Q13 (b)): UTF-8 names and symbols, `data X : Type where`,
  `f : A → B` with clauses, `λ x → t`. S2 adds `record`, `module`,
  `let x = t in u`, indexed family heads and path constructor results.
  `docs/GRAMMAR.md` gives the grammar and the canonical form.
- Kernel (S2): Pi; `Σ` with `_,_`, `fst` and `snd`, and `A × B` as the
  non-dependent `Σ`; `PathP L a b` and `a ≡ b`; the interval `I`, `i0`,
  `i1`, `~`, `∧`, `∨`; `primTransp`; `primHComp` with systems; `Type`,
  `Type₁` and closed levels (`Level`, `lzero`, `lsuc`, `ℓ-max`). `refl`
  is a builtin. examples/paths.lang defines `sym`, `cong`, `trans` and
  `transport` as guest terms.
- Data (S2): a program `data` declaration is a CM (a type parameter and
  a cell signature, with point, 1-cell and 2-cell constructors) or an
  indexed family (value parameters or indices). A `record` is a
  transparent named `Σ`. A `module` is a parameter section.
- Formers: F1 `_×_` (in S2 the non-dependent `Σ`), F3 `Maybe`
  (`nothing`, `just`), F5 `pure`, `map`, `bind`, F6 `fold`, F9 to F11
  (functions and `Σ`), F12 and F13 (`a ≡ b`, in S2 a `PathP`), F14
  universes. Core types: `Bool` (`true`, `false`) and `ℕ` (`suc`).
- S2 removes the kit builtins `Eq`, `symm`, `trans`, `cong`,
  `transport`, `pair`, `first`, `second`, `pack`, `witness` and
  `payload` ("S2 renames" in `docs/GRAMMAR.md`).
- Refusals: `List`, `cons`, `nil` and `unfold` give `REFUSE_CELL` (R1).
  A parameterized declaration that is not a cell signature, a type
  index, a record field of a type-constructor type and a coinductive
  record also give `REFUSE_CELL`. Closed data in a program gives
  `REFUSE_DATA`. `Sum`, `inl`, `inr`, `either` and `filter` give
  `REFUSE_BASE` (R2).
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
- Gate counts at S2: 74 files canonical under `fmt`, 22 JSON fixtures,
  33 codes with a fixture or a row, 38 check refusals, 9 parse
  refusals, 41 evaluations, 767 differential cases with 0 mismatches,
  16 Wasm modules valid.
- Mutants at S2 (3 of 3 killed): the generator count test skipped
  (`cell-ghost.lang` fails), the CC refusal skipped (`cell-cc.lang`
  fails), the type index check skipped (`cell-type-index.lang` fails).

## Remaining work

1. S3 to S12: see `docs/PLAN.md` sec 9. Q7 must be ruled before S6, Q14
   before S10 and Q15 before S11.
2. The O items O14 to O36 (`docs/PLAN.md` sec 10) are Claude readings.
   The USER can rule each one.

## Known limits

- Fuel: an evaluation stops after 20000000 steps with `EVAL_FUEL`
  (`EVAL_FUEL_STEPS`, src/front/core.h).
- Depth: an evaluation deeper than 2000 frames stops with `EVAL_DEPTH`
  (`EVAL_DEPTH_LIMIT`, src/front/core.h). The cause is the C stack.
- Memory: the arena limit is 1 GiB (`ARENA_LIMIT_BYTES`, src/main.c). A
  program that fills it gives `OOM`.
- Input: a source file larger than 1 MiB gives `IO_SIZE`.
- Laws: the `laws` counts in `check --json` stay 0 of 0 until S4.
- Data: closed data (no parameters and no indices) comes only from
  `domain/domain.lang` (`REFUSE_DATA`).
- Levels: closed levels only. S2 has no level variables (O18).
- Kan computation: `primHComp` reduces only on a face that holds.
  `primTransp` also computes for universe, `ℕ`, `Bool` and `Unit` lines.
  Other cases can remain stuck and cannot lower to Wasm (O27).
- Eliminators: S2 has no eliminator for an indexed family or a higher
  inductive family. A `fold` over one gives `DOMAIN_FAMILY` (O31).
- Names: S2 has no qualified names. A module name is not a global name
  (O35).

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
declares closed data types.
