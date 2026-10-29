# quorum-lang status

The build implements slices S1 to S9 of `docs/PLAN.md` sec 9. S1 is the
Agda-like Unicode surface, `langc fmt`, `langc check --json` with the
progress counts, and the kit formers under rules R1 and R2. S2 is the
cubical kernel and `REFUSE_CELL` for cell monads (CMs) only (Q1 (b)).
S3 is the eliminators for ℕ, Bool, higher inductive types and bags,
and the guest Prelude (sec 3.1). S4 is design secs 1 to 6 at the
denotation in examples/threshold.lang, a closed toy instance, the `law`
form and `langc laws`. S5 is the `Circuit` fragment with its guest
evaluator `run`, the seal (`Hidden`), design secs 7 to 10 at the
denotation and the denotational instances. S6 is the cryptography of sec
4.2 in src/crypto (BN254 ElGamal, the Pedersen DKG, the ballot proofs
and threshold decryption) and the C tool test/tallytool.c. S7 is the
cryptography of sec 4.3 and 4.4 in src/crypto (SHA-256,
expand_message_xmd, secp256k1, FROST, one DKG for both curves and the
reshare) and the C tool test/frosttool.c. S8 is the Wasm replica of sec
5 and the `amend_accept` check of sec 6 in replica/replica.lang, with
the host-import ABI and the C host test/replicatool.c. S9 is the agent
kit: `langc explain --json`, `langc mcp`, skills/quorum-lang/SKILL.md,
the grammar card in docs/GRAMMAR.md, the 5 programs of examples/agent/,
docs/TOKEN-BASELINE.md, corpus/INDEX.md and the AGENTS.md refresh.
Slices S10 to S12 are not started. The next slice is S10.

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
- Eliminators (S3): `elim` is the dependent eliminator for `ℕ` and
  `Bool` (large elimination to `Type₁`). A `fold` over a CM with path
  constructors takes one case for each constructor, and a path case
  is a path over the result type. `foldᴮ f swap st b xs` folds a bag
  with the swap obligation and `isSet` of the result type (O40).
- Prelude (S3): lib/prelude.lang holds the sec 3.1 definitions
  (`_∘_`, `sym`, `cong`, `_∙_`, `isProp`, `isSet`, `∥_∥₁`, `rec₁`,
  `∃`) and `isSetℕ` and `isSetBool` by a guest Hedberg proof (Q16
  (b)). examples/bag.lang holds `FMSet`, `_∷_`, `_++_`, `comm` and
  the union laws.
- Operators (S3): infix `∷`, `++`, `∘` and `∙`, and the notations
  `∥ A ∥₁` and `∃[ x ꞉ A ] B` (O41).
- Design (S4): examples/threshold.lang holds design secs 1 to 6:
  `record Step`, `module Design` (secs 1 to 4), `record Replica`,
  `module Authority` (secs 5 and 6, O58) and a closed toy instance
  (O65). The 7 laws `reach-core`, `legit-core`, `honest-in`, `sound`,
  `no-fork`, `certified-legit` and `certified-core` check, and
  `tip-order` proves the tip order (O3).
- Laws (S4): `law NAME : TYPE` marks a definition as a law (O64).
  `langc laws FILE` prints `law NAME discharged` or `law NAME open`
  for each law, then `laws: D of T discharged`. It exits 0 only when
  the file checks and D = T. The last line of `check --json` has
  `"laws":{"discharged":D,"total":T}`.
- Circuits (S5): `Code` is domain data (`bitC`, `natC`, `optC`,
  `pairC`, `bagC`; O68). examples/circuit.lang declares `data Circuit :
  Code → Code → Type` and its guest evaluator `run`, a `foldᴵ` over
  `Circuit` (O69, O70). A circuit family is first order: a field that is
  not a `Code`, a `ℕ`, a `Bool` or the family gives `REFUSE_CIRCUIT`
  (O71). `agree a b c` compares `run` with direct evaluation (O76).
- Seal (S5): the keyword `sealed` is domain-only (a program gets
  `REFUSE_DATA`). domain/domain.lang declares `sealed data Hidden` and
  `law unseal`. A definition that opens the seal, is not a `law` and has
  a type that does not end in a Path or a universe gets `REFUSE_LAW`
  (O72).
- Design (S5): examples/threshold.lang holds design secs 7 to 10:
  `record Private`, `_≼_`, `module Round`, `module Aggregate`, `record
  ZK`, `record IVC` and `record Sharing` (O74). The 12 laws check, with
  the 5 new laws `app-cons`, `ivc-prove`, `tallyᴹ-correct`,
  `tallyᶠ-correct` and `mpc≼fhe` (O73). examples/denote.lang holds the
  denotational instances and `law den-private` (O75).
- Cryptography (S6): src/crypto holds BN254 G1, exponential ElGamal, the
  ballot proofs (`sig_or_*`, `sig_onehot_*`), threshold decryption with
  DLEQ proofs (`thr_open`) and the Pedersen DKG (`dkg_*`, new C, O79).
  build/tallytool runs the known-answer, invalid-proof and DKG rows
  (`tally regressions: passed`). `build/tallytool rep` casts, adds
  (`tally_add`) and opens the ballot lists of the entries denCount1 to
  denCount3 (examples/denote.lang), and the gate compares each count
  with `langc eval` (O80, O81, O87).
- Cryptography (S7): src/crypto adds SHA-256 (`sha256`),
  expand_message_xmd and hash_to_field (`xmd_expand`, `xmd_to_scalar`),
  secp256k1 with SEC1 encodings (`secp_*`, `scalar_*`) and
  FROST(secp256k1, SHA-256) after RFC 9591 (`frost_*`). The DKG takes a
  curve (`DKG_BN254`, `DKG_SECP256K1`, O96) and has the reshare
  (`dkg_reshare_deal`, DKG_BAD_RESHARE, O97). build/frosttool runs the
  FIPS 180-4, RFC 9380, secp256k1, RFC 9591 App. E.5, DKG and reshare
  rows (`frost regressions: passed`). `build/frosttool rep` signs with
  each signer set of the DKG committee and of the reshared committee,
  and the gate compares each verify result with `langc eval` on denAuth3
  and denAuth4 of examples/denote.lang (O98, O102). build/tallytool has
  the BN254 reshare row (O97): Q = {1, 3} of the S6 good dealing
  reshares the ElGamal key to (t' 3, n' 4), and the new {2, 3, 4} open
  an S6 cast under the old PK.
- Replica (S8): replica/replica.lang is the Wasm replica (`docs/PLAN.md`
  sec 5 and sec 6). build/replicatool runs build/replica.wasm through
  wasm2c and gives the host imports of module "q" from src/crypto
  (O105). `langc eval` links the same code. The exports check a
  certificate chain (`cert_verify`, `rep_tip`), merge two chains
  (`rep_merge`, `merge_tip`), apply a step (`step_apply`), run the FHE
  tally route (`ballot_verify`, `tally_sum`, `partial_verify`,
  `combine`) and check an amendment (`amend_accept`). The gate compares
  `langc eval` with build/replicatool on the fixtures of test/replica/
  (O113, O114).
- Agent kit (S9): `langc explain --json NAME` prints one JSON line for a
  name (O119). `langc mcp` is an MCP stdio server (JSON-RPC 2.0, O121,
  O122): its tools include `check`, `explain` and `list-base` (the names
  of src/front/basenames.c), and src/front/jsonin.c reads the requests
  (O123). skills/quorum-lang/SKILL.md is the agent skill (O124): it has
  6 byte copies of repo files, and the gate compares each copy with its
  source. docs/GRAMMAR.md has the grammar card (`## Card`, O125).
  examples/agent/ has 5 programs, graded 1 to 5 (O126).
  docs/TOKEN-BASELINE.md gives the token cost of 3 tasks (O127;
  test/tokproxy.c, test/baseline/). corpus/INDEX.md gives the labels of
  each `.lang` file in examples/ and test/ (O128). AGENTS.md and
  README.md have the S9 text (O129).
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
- Gate counts at S3: 83 files canonical under `fmt`, 23 JSON fixtures,
  34 codes with a fixture or a row, 43 check refusals, 9 parse
  refusals, 56 evaluations, 4007 differential cases with 0
  mismatches, 18 Wasm modules valid.
- Mutants at S3 (3 of 3 killed): the comm cell dropped from the bag
  shape (`bag-no-comm.lang` fails), the swap obligation not checked
  (`bag-bad-swap.lang` fails), the set truncation cell dropped from
  the bag shape (`bag-no-trunc.lang` fails).
- Gate counts at S4: 86 files canonical under `fmt`, 24 JSON fixtures,
  34 codes with a fixture or a row, 43 check refusals, 9 parse
  refusals, 61 evaluations, 4074 differential cases with 0
  mismatches, 20 Wasm modules valid, 7 of 7 laws discharged.
- Mutants at S4 (3 of 3 killed): the `keeps` field of `Step` not
  checked (`keeps : Core σ → Core σ`: `step` fails, 0 of 7 laws), the
  quorum index ignored (`Authorized` at the committee of `genesis`:
  `Authorized` fails, 2 of 7 laws), the `single` parameter dropped
  from module `Authority` (`fork-meet` fails, so `no-fork` and
  `tip-order` fail, 4 of 7 laws). The examples loop and the laws line
  kill each one.
- Gate counts at S5: 95 files canonical under `fmt`, 27 JSON fixtures,
  36 codes with a fixture or a row, 48 check refusals, 9 parse
  refusals, 72 evaluations, 5246 differential cases with 0
  mismatches, 22 Wasm modules valid, 12 of 12 laws discharged
  (examples/threshold.lang) and 1 of 1 (examples/denote.lang).
- Mutants at S5 (3 of 3 killed): the O71 first order check off
  (`circuit-ho.lang` and the `REFUSE_CIRCUIT` JSON fixture fail),
  `REFUSE_LAW` off (`seal-fold.lang`, `seal-unseal.lang`,
  `seal-relay.lang` and the `REFUSE_LAW` JSON fixture fail), `factors`
  not checked (its right side becomes its left side: `tallyᶠ-correct`
  fails, 10 of 12 laws). The fixtures, the examples loop and the laws
  line kill them.
- Gate counts at S6: 103 files canonical under `fmt`, 29 JSON fixtures,
  36 codes with a fixture or a row, 54 check refusals, 9 parse refusals,
  75 evaluations, 14 tally cases with 28 counts and 0 mismatches, 5274
  differential cases with 0 mismatches, 22 Wasm modules valid, 12 of 12
  laws discharged (examples/threshold.lang) and 1 of 1
  (examples/denote.lang).
- Mutants at S6 (3 of 3 killed): one slot of `⊕` skipped (`tally_add`
  stops before the last slot: 10 of the 28 `rep` counts differ and the
  row `tally k 2 slot 1` fails), the DLEQ check skipped (`thr_open`
  takes a bad partial: the rows `part D + G` and `part z + 1` fail), the
  Lagrange sign flipped (each `rep` slot gives `open-1` and 8 open rows
  fail). The `rep` lines and the tallytool rows kill them.
- Gate counts at S7: 103 files canonical under `fmt`, 29 JSON fixtures,
  36 codes with a fixture or a row, 54 check refusals, 9 parse refusals,
  77 evaluations, 14 tally cases with 28 counts and 0 mismatches, 24
  auth cases with 0 mismatches, 5318 differential cases with 0
  mismatches, 19 IR lowerings, 22 Wasm modules valid, 12 of 12 laws
  discharged (examples/threshold.lang) and 1 of 1
  (examples/denote.lang).
- Mutants at S7 (3 of 3 killed): the binding factor dropped
  (`frost_group_commitment` takes R_i = D_i: none of the 9 V-1 `rep`
  lines gives 1, and the rows `e5 P1 sig_share`, `e5 P3 sig_share` and
  `e5 sig` fail), one SHA-256 round skipped (36 FAIL lines: the FIPS,
  xmd and E.5 rows), the reshare coefficient wrong (g_i(0) = (λ + 1)
  s_i: the 5 V-1 denAuth4 `rep` lines give 0, and `reshare good` gives
  DKG_BAD_RESHARE). The `rep` lines and the frosttool rows kill them.
- Gate counts at S8: 104 files canonical under `fmt`, 29 JSON fixtures,
  36 codes with a fixture or a row, 54 check refusals, 9 parse refusals,
  77 evaluations, 14 tally cases with 28 counts and 0 mismatches, 24
  auth cases with 0 mismatches, 2 host rows, 4 input rows, 25 replica
  cases with 0 mismatches (a history of 4 steps with tip 4, 3 merge rows
  with tip 4, 3 apply rows with state 4), 19 route cases with 0
  mismatches, 14 replica tally cases with 0 mismatches, 1 of 1 accepted,
  8 of 8 refusals, 5318 differential cases with 0 mismatches, 19 IR
  lowerings, 22 Wasm modules valid, 12 of 12 laws discharged
  (examples/threshold.lang) and 1 of 1 (examples/denote.lang).
- Mutants at S8 (3 of 3 killed): the fork check skipped (`mergeCode`
  without the digest compare: the fork row gives 0, not REP_FORK), the
  `Core` check skipped (`amendCore` gives 0: the corebrk row gives 0,
  not AMEND_CORE), the fragment check skipped (the fragment fold
  replaced by 0: the ill row gives AMEND_CORE, not AMEND_ILL_TYPED). The
  history and amend loops of test/gate.sh kill them.
- Gate counts at S9: 110 files canonical under `fmt`, 29 JSON fixtures,
  36 codes with a fixture or a row, 54 check refusals, 9 parse refusals,
  77 evaluations, 19 examples checked with 0 failed, 10 agent verbs with
  0 missing, 13 explain fixtures, 152 base names with 0 missing, 15 MCP
  requests with 0 mismatches, 6 SKILL.md copies with 0 drift, 5 agent
  examples with 13 of 13 laws, 3 token tasks with 12 cells, 135 corpus
  files with 0 mismatches, 5 README yes rows with 0 without a slice, the
  S8 tally, auth, host, input and replica counts (unchanged), 5318
  differential cases with 0 mismatches, 19 IR lowerings, 22 Wasm modules
  valid, 12 of 12 laws discharged (examples/threshold.lang) and 1 of 1
  (examples/denote.lang).
- Mutants at S9 (3 of 3 killed). Each restore gives cmp rc 0 and the
  same sha.
  - M1: the explain printer drops `"type"` (src/main.c). The mcp block
    of test/gate.sh gives `mcp: 15 requests, 1 mismatches`.
  - M2: one line of the SKILL.md copy of
    examples/agent/03-threshold-reveal.lang changes. The skill block
    gives `skill: 6 copies, 1 drift`.
  - M3: the list-base table (src/front/basenames.c) loses the row `Set`.
    The base block gives `base: 152 names, 1 missing`.
- Speed at S9 (O132): in the CLEAN run of the S9 mutant script
  (W/mut-s9.py), the mcp block took 0.05 s (target less than 1 s), the
  explain block 0.27 s (target less than 1 s) and the 9 S9 blocks
  (test/gate.sh :228 to :419) 2.76 s (target less than 10 s). Each
  target is met.

## Remaining work

1. S10 to S12: see `docs/PLAN.md` sec 9. Q7 is ruled (a) (2026-10-26).
   Q14 must be ruled before S10 and Q15 before S11.
2. The O items O14 to O134 (`docs/PLAN.md` sec 10) are Claude readings,
   but the USER ruled O109 (i). The USER can rule each one.
   `docs/PLAN.md` sec 5 (S8 readings) and sec 7 (S9 readings) name the
   session readings that are NOT ruled.

## Known limits

- Fuel: an evaluation stops after 20000000 steps with `EVAL_FUEL`
  (`EVAL_FUEL_STEPS`, src/front/core.h).
- Depth: an evaluation deeper than 2000 frames stops with `EVAL_DEPTH`
  (`EVAL_DEPTH_LIMIT`, src/front/core.h). The cause is the C stack.
- Memory: the arena limit is 1 GiB (`ARENA_LIMIT_BYTES`, src/main.c). A
  program that fills it gives `OOM`.
- Input: a source file larger than 1 MiB gives `IO_SIZE`.
- Laws: `langc laws` counts only the `law` definitions of the program
  file. A law is discharged when its definition checks.
- Data: closed data (no parameters and no indices) comes only from
  `domain/domain.lang` (`REFUSE_DATA`).
- Levels: closed levels only. S2 has no level variables (O18).
- Kan computation: `primHComp` reduces only on a face that holds.
  `primTransp` also computes for universe, `ℕ`, `Bool` and `Unit` lines.
  Other cases can remain stuck and cannot lower to Wasm (O27).
- Eliminators: `foldᴵ` (S5, O70) is the recursor for an indexed family
  with no parameters. A `fold` or an `elim` over an indexed family
  gives `DOMAIN_FAMILY` (O31). `elim` takes ℕ and Bool only (O75a). A
  `fold` at a 2-cell stays stuck (O52). In a Wasm entry, an `elim` over
  a run-time `ℕ` or a `foldᴮ` over a bag of run-time shape gives
  `REFUSE_RUNTIME_TREE` (O46, O50). An entry cannot take a circuit, so
  a run-time `foldᴵ` does not occur (O70a).
- Chains (S4): `Reach` and `_⊑_` are chains of ℕ length by `elim` on
  the length, not data types (O57). A section holds no `data`, `record`
  or `module` (O35), so `Step` and `Replica` are top-level records
  (O59).
- Seal (S5): a fold of a free `Hidden` value does not reduce, and
  `elim` cannot open it. A denotational instance opens the seal inside
  a `law` (O75a).
- S5 review regressions cover seal extraction through Path endpoints
  (including local and record proofs), safe resealing, and refusal of
  `foldᴵ` when later types depend on a recursive field's original value.
- Crypto (S6): langc does not link src/crypto. The host import ABI comes
  in S8 (Q9 (a)). The field and curve code is not constant time.
  `thr_open` gets a count by baby-step giant-step below 2^bits
  (`OPEN_BITS` 8 in build/tallytool, so a count below 256); a larger
  count gives THR_NOT_FOUND (`open-1`). The DKG is t of n with n at most
  8 (`THR_N_MAX`).
- Crypto (S7): the SHA-256, secp256k1 and FROST code is not constant
  time. build/frosttool uses fixed nonce randomness (the RFC 9591 E.5
  values in the rows, fixed bytes from each identifier in `rep`), so it
  is a test tool, not a signer. The DKG and the reshare are t of n with
  n at most 8 (`THR_N_MAX`). frost_aggregate does not check t: the
  coordinator must check it (O94).
- Replica (S8): build/replicatool needs wasm2c (WABT) and TCC, and the
  wasm2c translation needs the shim src/w2c-tcc.h (TCC has no
  `__builtin_add_overflow`). `make check-clang` does not compile
  test/replicatool.c. The fragment check of `amend_accept` keeps at most
  4 code pairs on its stack: a deeper term gives AMEND_ILL_TYPED (O111).
  One frost_verify takes about 0.1 s. A tally combine row takes about 3
  s of user time on each side (O116; the USER ruling R-E37 (a) accepts
  the time).
- Names: S2 has no qualified names. A module name is not a global name
  (O35).
- Tokens (S9, A13): in each task of docs/TOKEN-BASELINE.md, the
  quorum-lang file costs more tokens than the Python and the Rust
  samples (T1 527 / 505 / 253 / 367, T2 435 / 419 / 327 / 413, T3 688 /
  649 / 274 / 339; quorum-lang / ASCII / Python / Rust). The cause is
  the helpers by `elim` (no imports) and the proof terms. A13 measures
  the cost; it does not promise a lower cost.

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
