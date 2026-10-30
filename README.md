# quorum-lang

quorum-lang is a typed language for rules that a committee authorizes by
threshold signature and that change by their own vote. Its base types and
operations come from one denotational design, ThresholdVC
(design/ThresholdVC/Design.agda). Its type constructors are cell monads and
their duals, as Cubical type theory realizes them. The host is TinyCC. The
run target is a Wasm replica. Each design law is a guest theorem that
`langc check` checks.

## When to reach for quorum-lang

| Task | Use quorum-lang? | Why | Lands in |
|---|---|---|---|
| A committee must authorize a state change with a threshold signature | Yes | `Authorized`, `sound` and `no-fork` are guest laws; certificates are FROST(secp256k1, SHA-256) | S4, S7 |
| Members vote and no party may see one ballot or link it to a voter | Yes | ballots go into a bag (`FMSet`), so the type removes order and identity | S3, S6 |
| A tally must stay private until a quorum opens it | Yes | exponential ElGamal on BN254 with threshold decryption | S6 |
| The rules must change by their own vote and keep one entrenched property | Yes | a constitution is a quorum-lang program; the replica refuses an edit that breaks `Core` | S8 |
| Offline replicas must agree on the current version by gossip | Yes | `merge` is the join of certified tips | S8 |
| General-purpose code: I/O, strings, floating point, services | No | the design admits none of these; use a general-purpose language | none |
| A blockchain contract or an EVM target | No | the only target is the Wasm replica | none |

## Status

S1 to S10 are done. The checker has the Agda-like Unicode surface
(docs/GRAMMAR.md), `langc fmt`, `langc check --json` and stable
diagnostic codes (docs/DIAGNOSTICS.md). The base names of the design
(Ballot, Quorum, Authorized and the others) are in the checker, and the
design laws are guest theorems. S6 and S7 add the cryptography
(src/crypto/). S8 adds the Wasm replica and self-amendment. S9 adds the
agent kit: `langc explain`, `langc mcp`, skills/quorum-lang/SKILL.md, the
5 programs of examples/agent/, docs/TOKEN-BASELINE.md and
corpus/INDEX.md. S10 adds the MPC tally route to the replica:
a BGW arithmetic model (src/crypto/bgw.c). docs/PLAN.md sec 9 lists the
slices, and docs/PLAN.md sec 7 maps agent adoption to deliverables.
S11 and S12 are not started. The next slice is S11.

## MPC security scope

S10 is a BGW arithmetic transcript validation model, not a private ballot
protocol. Its Feldman commitment `C[0] = b G` reveals a ballot bit: the
identity point means 0 and the generator means 1. The transcript also
contains all committee shares, so the host can reconstruct every input
and intermediate value. Returning only the outcome does not hide them.
Use the S6 threshold ElGamal route for encrypted ballots. A private MPC
deployment needs hiding commitments and proofs plus separate member
execution with private authenticated channels; S10 does not implement
those requirements.

## Tool loop

- `build/langc check FILE.lang`: type check. It prints `ok` (exit 0) or
  one diagnostic with a stable code.
- `build/langc check --json FILE.lang`: one JSON line for each
  diagnostic, then the parsed and typed counts.
- `build/langc fmt FILE.lang`: print the canonical text.
- `build/langc laws FILE.lang`: one line for each law, then `laws: D of
  T discharged`.
- `build/langc explain [--json] NAME` and `build/langc list-base`: the
  base names.
- `build/langc mcp`: the tools of the loop as a JSON-RPC 2.0 server on
  stdin and stdout.
- The kit verbs: `eval`, `ir`, `abi` and `build`.

AGENTS.md gives the loop for an agent. skills/quorum-lang/SKILL.md gives
the same loop as a skill.

## Build and test

```sh
make -j 2 check
```

The gate needs tcc, clang, node, wasm-validate, wasm-objdump and wasm2c
(WABT; `make WABT=PREFIX` when WABT is not in /opt/homebrew).

## Layout

- design/: the USER ask and rulings (DESIGN.md) and the base design (ThresholdVC/*.agda, reference only; no build step runs Agda).
- docs/PLAN.md: the plan of record. docs/GRAMMAR.md: the surface.
  docs/DIAGNOSTICS.md: the diagnostic codes.
- src/front/: lexer, parser, checker, evaluator and lowering. src/wasm.c: the Wasm emitter.
- src/crypto/: BN254 G1, ElGamal, the ballot proofs, threshold decryption and the DKG (S6). test/tallytool.c: their C rows and the `rep` mode.
- src/crypto/sha256.c, xmd.c, secp256k1.c and frost.c: SHA-256, expand_message_xmd, secp256k1 and FROST(secp256k1, SHA-256) (S7); dkg.c also reshares. test/frosttool.c: their C rows and the `rep` mode.
- replica/replica.lang: the Wasm replica (S8): the certificate chain check, merge and tip, the FHE tally route and `amend_accept`. test/replicatool.c: the C host that runs build/replica.wasm through wasm2c with the src/crypto host imports; src/w2c-tcc.h is the TCC shim for the translation. test/replica/history.txt, tally.txt and amend.txt: the replica fixtures.
- examples/, test/: guest programs and gate fixtures.
- examples/agent/: the 5 programs for an agent (S9). skills/quorum-lang/SKILL.md: the agent skill (S9).
- docs/TOKEN-BASELINE.md: the token baseline (S9), with test/tokproxy.c (the token proxy) and test/baseline/ (the samples).
- corpus/INDEX.md: the labels of each `.lang` file in examples/ and test/ (S9).

## License

MIT OR Apache-2.0.
