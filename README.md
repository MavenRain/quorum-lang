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

S1: the kit core on an Agda-like Unicode surface (docs/GRAMMAR.md), with
`langc fmt`, `langc check --json` and stable diagnostic codes
(docs/DIAGNOSTICS.md). No design name (Ballot, Quorum, Authorized and
the others) is in the checker yet. docs/PLAN.md sec 9 lists the slices,
and docs/PLAN.md sec 7 maps agent adoption to deliverables.

## Tool loop

- `build/langc check FILE.lang`: type check. It prints `ok` (exit 0) or
  one diagnostic with a stable code.
- `build/langc check --json FILE.lang`: one JSON line for each
  diagnostic, then the parsed and typed counts.
- `build/langc fmt FILE.lang`: print the canonical text.
- The kit verbs: `eval`, `ir`, `abi` and `build`.

AGENTS.md gives the loop for an agent.

## Build and test

```sh
make -j 2 check
```

The gate needs tcc, clang, node, wasm-validate and wasm-objdump.

## Layout

- design/: the USER ask and rulings (DESIGN.md) and the base design (ThresholdVC/*.agda, reference only; no build step runs Agda).
- docs/PLAN.md: the plan of record. docs/GRAMMAR.md: the surface.
  docs/DIAGNOSTICS.md: the diagnostic codes.
- src/front/: lexer, parser, checker, evaluator and lowering. src/wasm.c: the Wasm emitter.
- src/crypto/: BN254 G1, ElGamal, the ballot proofs, threshold decryption and the DKG (S6). test/tallytool.c: their C rows and the `rep` mode.
- src/crypto/sha256.c, xmd.c, secp256k1.c and frost.c: SHA-256, expand_message_xmd, secp256k1 and FROST(secp256k1, SHA-256) (S7); dkg.c also reshares. test/frosttool.c: their C rows and the `rep` mode.
- examples/, test/: guest programs and gate fixtures.

## License

MIT OR Apache-2.0.
