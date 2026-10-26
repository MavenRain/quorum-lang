# quorum-lang: plan

Status: S0 (seed). This file is the plan of record. It uses ASD-STE100
style. design/DESIGN.md keeps the USER text verbatim.

Sections: 1 Rulings and readings. 2 R1: type constructors. 3 R2: base
types and operations. 4 Cryptography. 5 Wasm replica. 6 Self-amendment.
7 Agent adoption. 8 Port sources. 9 Slices. 10 O items. 11 Q items.

## 1. Rulings and readings

### 1.1 USER requirements (2026-10-25)

- R1. Type constructors and higher-kinded types: only cell monads and
  their duals in a locally presentable, locally cartesian closed
  (infinity,1)-category, as Cubical type theory realizes it. These are the
  same words as intent-lang, bridge-lang, mandate-lang, resolve-lang,
  restrict-lang and virtu-lang.
- R2. Base types and operations: only what the ThresholdVC design
  contains (design/ThresholdVC/Design.agda, 288 lines, and
  design/ThresholdVC/Prelude.agda, 79 lines).
- Host: TinyCC.
- Agent adoption: shape the repo so that agents reach for quorum-lang
  where it fits (sec 7).

### 1.2 Rulings (USER, 2026-10-25, AskUserQuestion)

| No. | Question | Answer (verbatim) | Effect |
|---|---|---|---|
| 1 | Execution target | "Wasm replica (Recommended)" | Kit = lang-template hosts/tcc-wasm. One target. |
| 2 | Proof or certificate target | "All proofs should be expressible within the guest language itself that we create." | No Agda, Lean or circuit export. Each design law is a guest term. `langc check` checks it. |
| 3 | Cryptography in v1 | "ElGamal + FROST certs" | Exponential ElGamal on BN254 with threshold decryption for `Private`. FROST (RFC 9591, FROST(secp256k1, SHA-256)) for `Authority` certificates. |

USER rulings on the sec 11 Q items, 2026-10-25 (after S0), verbatim:
"Rulings: Q1=b, Q2=a, Q3=a, Q4=a, Q5=a, Q6=b, Q8=b, Q9=a, Q10=a, Q11=b, Q12=a, Q13=b."
Q7 is not ruled. It blocks S6 only. Claude asks it at the S5 close.

| Q | Ruling | Effect |
|---|---|---|
| Q1 | (b) | R1 admits CMs only. A CC is refused with `REFUSE_CELL` (secs 2.1, 2.3, 2.4). S2 has no cocell branch (O9). |
| Q2 | (a) | A record is a named iterated Sigma, ambient, with type parameters (sec 2.2). |
| Q3 | (a) | `Circuit` is the codes-indexed closed first-order fragment (sec 2.3, S5). |
| Q4 | (a) | `Hidden` is the sealed identity CM. `⟦_⟧` is law-only (sec 2.3, S5). |
| Q5 | (a) | The guest checks each law at the denotation. Kit differential tests check the representation map (S6, S7). |
| Q6 | (b) | The MPC route stays law-only until the MPC slice S10 (sec 5, Q14). |
| Q8 | (b) | A Pedersen DKG makes the FROST key and the ElGamal key (secs 4.2 to 4.4, S6, S7). |
| Q9 | (a) | Cryptography in Wasm uses a fixed host-import ABI (sec 5, S8). |
| Q10 | (a) | The module carries the fragment checker (sec 6, S8). |
| Q11 | (b) | v1 keeps the certificate chain. The slice S11 adds a constant-size proof (sec 5, Q15, O13). |
| Q12 | (a) | One fixed offline proxy gives the token counts (A13, S9). |
| Q13 | (b) | The surface is Agda-like Unicode with the design names (sec 3, A1, docs/GRAMMAR.md, S1). |

### 1.3 Readings (Claude, NOT ruled)

- D1. The design parameter `Circuit A B` with `run` is where the language
  plugs in. A constitution IS a quorum-lang program. The replica embeds
  the evaluator (sec 6).
- D2. Ruling 2 makes the guest checker the verifier. A law is a guest
  definition whose type is the law statement. `langc check` type checks
  the proof term.
- D3. Ruling 3: ElGamal ciphertexts and FROST signatures are
  representations in the design's sense. Each must map onto its meaning
  by the homomorphism laws (the fields named `⟦…⟧`).
- D4. Boundary exclusion: the replica accepts an Edit only when the new
  constitution type checks and its laws check (sec 6). This is the "fixed
  point" incentive of the brief (sec 7, A10 and A11).
- D5. The name quorum-lang is Claude's call (precedent: zkpolicy-lang P0).

## 2. R1: type constructors

### 2.1 The reading (same as intent-lang docs/PLAN.md 2.2 at 79e1898)

A type constructor is a declaration with a type parameter, or any map
`U -> U`. R1 admits one class and no other (Q1 (b), CM only):

- CM, cell monad. The free algebra monad of a cell signature. The type
  parameter `A` occurs in one constructor only, the generator
  `eta : A -> T A`. Each other constructor (a point, a path or a higher
  cell) takes closed base data and arguments of type `T A` only. Unit is
  `eta`. Bind is the recursor. The monad laws are paths by the induction
  principle.

R1 refuses each other type constructor. This includes a CC (cocell
comonad, the dual class of the Q1 (a) reading): a coinductive record with
a type parameter gives `REFUSE_CELL`.

Why the two adjectives matter. Locally presentable: the small object
argument gives the free algebra of each set of cells, so each cell
signature has its monad. Locally cartesian closed: base change gives Pi
and Sigma, and `Path A a b` is the fiber of `I -> A` over its end points.

### 2.2 Ambient structure and indexed families

Ambient structure is not a type constructor. It is Pi, Sigma, Path,
PathP, the interval `I` with `i0`, `i1` and `~`, `transp`, `hcomp`, the
universes `U` and the levels. A definition built only from these is
ambient too (for example `_×_`, `isProp`, `isSet`, `_≼_`). A record is a
named iterated Sigma type (Q2).

An indexed family over data with no type parameter is not a type
constructor. The checker admits it as a family, as intent-lang does.
Examples: `Quorum c`, `_∈_`, `Reach σ`, `_⊑_`, `Step σ σ'`, `Shares c`,
IVC `Proof σ`.

### 2.3 Each type former of the design

| Former | Design site | R1 class | Reason |
|---|---|---|---|
| Pi, `A → B` | everywhere | ambient | LCC: right adjoint of base change |
| `Σ`, `_×_`, `Tip`, `_≼_` | Prelude, secs 6, 8 | ambient | LCC: left adjoint of base change |
| records `Step`, `Replica`, `Private`, `ZK`, `IVC`, `Sharing` | secs 3, 6, 7, 9, 10 | ambient | named iterated Sigma (Q2 (a)) |
| `_≡_`, `I`, `transp`, `hcomp` | Prelude | ambient | the Cubical realization of identity types |
| `Type`, `Type₁`, `Level` | Prelude, records | ambient | universes |
| `isProp`, `isSet`, `∃`, `Policy`, `Legit`, `Authorized` | Prelude, secs 1, 4, 5 | defined | built from ambient formers and CMs; no new former |
| `Maybe` | sec 2 (`constitution`), Policy | CM | generator `just`, one 0-cell `nothing` |
| `∥_∥₁` | Prelude, `Legit`, `∃` | CM | generator `∣_∣₁`, one 1-cell `squash₁` on `T A` only |
| `FMSet` (generator form) | Prelude, ballots | CM | the free commutative monoid QIT: `eta`, `e`, `m`, unit, associativity and commutativity paths, set truncation cell |
| `FMSet` (cons form, as Prelude declares it) | Prelude | REFUSED (`REFUSE_CELL`) | `_∷_ : A → FMSet A → FMSet A` uses `A` outside the generator. The kernel gives `_∷_` as a derived view: `x ∷ xs = m (eta x) xs`. |
| `Bool`, `ℕ` | Prelude | base type (R2) | closed data with no type parameter |
| `Reach`, `_⊑_`, `Quorum`, `_∈_`, `Step σ σ'`, `Shares c`, IVC `Proof σ`, ZK `Proof x` | secs 1, 3, 4, 6, 9, 10 | indexed family | indexed over data, no type parameter |
| `Circuit A B` as an abstract `Type → Type → Type` | sec 1 | REFUSED in that form | an arbitrary map `U -> U -> U` has no cell signature |
| `Circuit a b` over codes | sec 1 (Q3 (a)) | indexed family | indexed over closed first-order codes `a b : Code`, with `El : Code -> U` |
| `Hidden : Type → Type` | sec 7 | CM (identity, sealed) | the identity monad with a sealed eliminator; `⟦_⟧` is law-only (Q4 (a), intent-lang Enc precedent) |
| `ZK {X} W` | sec 9 | ambient | a record with a type parameter is a named Sigma under Q2 (a) |
| CC (a coinductive record with a type parameter) | none | REFUSED (`REFUSE_CELL`) | Q1 (b): R1 admits CMs only; the design uses no comonad (O9) |

### 2.4 Enforcement

- `REFUSE_CELL` (S2) refuses a parameterized declaration that is not a
  cell signature (Q1 (b): no cocell signature). Ports: the CM branch of
  intent-lang check.c and resolve-lang check.c (sec 8).
- Refuse fixtures: `data Pair (A : U) := mk A A`, the cons form of
  `List`, the cons form of `FMSet`, a record field of type `U -> U`, a
  coinductive record with a type parameter (a CC, Q1 (b)).
- Admit fixtures: `Maybe`, `Trunc`, `Bag` in generator form.
- A record field cannot range over `U -> U`. So `Private` fixes `Hidden`
  to the sealed identity CM, and `Circuit` is the codes family (Q3, Q4).

## 3. R2: base types and operations

Kinds:

- ambient: sec 2.2 structure.
- base type, base op: the only primitive types and operations.
- CM former: an admitted type constructor (sec 2.3).
- slot: a parameter of the design telescope. An instance gives it.
- obligation: a field or parameter that the instance must prove.
- assumption: a trust-model parameter. It stays a parameter. No guest
  proof exists for it.
- defined: a guest definition.
- law: a guest theorem. `langc check` checks its proof term.
- rep interface: the carriers and operations of a representation record.
  Kit primitives give them in a real instance.

Guest names are the design names (Q13 (b), Agda-like Unicode surface).
The tables give the design name only. docs/GRAMMAR.md gives the surface.

### 3.1 Prelude.agda

| Design name | Kind | Slice |
|---|---|---|
| `Level`, `lzero`, `lsuc`, `ℓ-max` | ambient | S2 |
| `Type` (`Set`), `Type₁` | ambient | S2 |
| `I`, `i0`, `i1`, `~_` | ambient | S2 |
| `primHComp`, `primTransp` | ambient | S2 |
| `_≡_` | ambient | S2 |
| `Σ`, `_,_`, `fst`, `snd` | ambient | S2 |
| `Bool` | base type | S1 |
| `true`, `false` | base op | S1 |
| `ℕ` | base type | S1 |
| `suc` | base op (`zero`: O2) | S1 |
| `Maybe`, `nothing`, `just` | CM former | S1 |
| `_∘_` | defined | S3 |
| `sym`, `cong`, `_∙_` | defined | S3 |
| `isProp`, `isSet` | defined | S3 |
| `_×_` | defined (non-dependent Sigma) | S2 |
| `∥_∥₁`, `∣_∣₁`, `squash₁` | CM former | S3 |
| `rec₁` | defined (the CM recursor into a proposition) | S3 |
| `∃`, `∃[ x ꞉ A ] B` | defined | S3 |
| `FMSet`, `[]` | CM former (generator form) | S3 |
| `_∷_`, `comm` | defined (derived view, sec 2.3) | S3 |
| `trunc` | CM former (set truncation cell) | S3 |
| `foldᴮ` | kernel eliminator with the swap obligation (O1) | S3 |
| `_++_` | defined (`m` of the generator form); the Prelude equation is a law | S3 |

### 3.2 Design.agda, secs 1 to 4

| Design name | Kind | Slice |
|---|---|---|
| `Artifact`, `Ballot`, `Agenda`, `Edit`, `Member`, `Committee` | slot | S4 |
| `Quorum` | slot (indexed family) | S4 |
| `_∈_` | slot (indexed family) | S4 |
| `Circuit`, `run` | slot filled by the language (sec 6, Q3) | S5 |
| `State` | slot | S4 |
| `isSetState` | obligation | S4 |
| `height`, `artifact`, `committee`, `constitution` | slot | S4 |
| `⟦_⟧ᵉ` | slot | S4 |
| `advance` | obligation | S4 |
| `genesis`, `Core` | slot | S4 |
| `isPropCore`, `core₀` | obligation | S4 |
| `Policy`, `rules` | defined | S4 |
| `Step`, `step`, `agenda`, `bag`, `edit`, `chosen`, `lands`, `keeps` | defined (record, Q2) | S4 |
| `Reach`, `root`, `_▸_` | defined (indexed family) | S4 |
| `Legit` | defined | S4 |
| `reach→core`, `legit→core` | law | S4 |

### 3.3 Design.agda, secs 5 and 6 (module `Authority`)

| Design name | Kind | Slice |
|---|---|---|
| `Authority` | parameter section (O8) | S4 |
| `Honest`, `Endorses` | assumption | S4 |
| `honest-meet`, `faithful`, `single` | assumption | S4 |
| `Authorized` | defined | S4 |
| `honest-in`, `sound`, `no-fork` | law | S4 |
| `_⊑_`, `here`, `_⊳_` | defined (indexed family) | S4 |
| `certified→legit`, `certified→core` | law | S4 |
| `Tip` | defined | S4 |
| `Replica`: `Rep`, `none`, `merge`, `⟦_⟧` | rep interface | S4 (denotational instance), S8 (Wasm) |
| `⟦none⟧`, `⟦merge⟧ˡ`, `⟦merge⟧ʳ`, `⟦merge⟧ᵘ` | obligation | S4, S8 |
| `current`, `Agree` | defined | S4 |

### 3.4 Design.agda, secs 7 to 10

| Design name | Kind | Slice |
|---|---|---|
| `Private`: `Hidden` | CM former (sealed identity, Q4) | S5 |
| `Private`: `⟦_⟧` | law-only eliminator (Q4) | S5 |
| `cast`, `∅`, `_⊕_`, `eval`, `reveal` | rep interface | S5, S6 |
| `⟦cast⟧`, `⟦∅⟧`, `⟦⊕⟧`, `⟦eval⟧`, `⟦reveal⟧` | obligation | S5, S6 |
| `_≼_` | defined | S5 |
| `Round`, `Aggregate` | parameter section (O8) | S5 |
| `tallyᴹ` | defined | S5 |
| `tallyᴹ-correct` | law | S5 |
| `M`, `agg`, `decide` | slot | S5 |
| `factors` | obligation | S5 |
| `tallyᶠ` | defined | S5 |
| `tallyᶠ-correct`, `mpc≼fhe` | law | S5 |
| `ZK`: `Proof`, `verify`, `prove` | rep interface | S5, S6 |
| `ZK`: `complete` | obligation | S5 |
| `ZK`: `⟦_⟧` | assumption for a real scheme (sec 4.1); obligation for the denotational instance | S5 |
| `IVC`: `Proof`, `verify`, `start`, `extend` | rep interface | S5; S8 (certificate chain, Q11 (b)); S11 (constant-size proof, Q15) |
| `start✓`, `extend✓`, `IVC.⟦_⟧` | obligation | S5 |
| `IVC.prove` | law | S5 |
| `Sharing`: `Secret`, `Shares`, `⟦_⟧`, `reshare` | rep interface | S5, S7 |
| `⟦reshare⟧` | obligation | S5, S7 |

Law count for the design file: 12 (`_++_` equation, `reach→core`,
`legit→core`, `honest-in`, `sound`, `no-fork`, `certified→legit`,
`certified→core`, `tallyᴹ-correct`, `tallyᶠ-correct`, `mpc≼fhe`,
`IVC.prove`). The S5 gate requires 12 of 12.

## 4. Cryptography (ruling 3)

### 4.1 What the design leaves outside the denotation

The design says (verbatim, section "What this design does not cover" of
the ThresholdVC artifact):

> Computational security. Unforgeability, IND-CPA and simulation-based
> zero knowledge are not denotational properties. They enter as exact
> soundness fields, but real schemes meet them only up to negligible
> error. The types fix what each step reveals; they do not prove that
> nothing else leaks.
>
> Liveness. No step is guaranteed to happen, and the design does not
> model coercion resistance.
>
> Tip ordering is assumed. The replica laws assume certified states are
> totally ordered. That follows from no-fork by induction on height, but
> the file does not mechanize it.
>
> Forks are not attributable. If honest-meet fails, a fork shows up as
> two certificates on one σ. Signatures that hide the signer set cannot
> identify who signed twice.
>
> The bag forgets order only. Ballot must carry no identity, and a rare
> weight value can still identify a voter.
>
> Differential-privacy noise for architecture 4 would move the codomain
> of Policy into a distribution monad. The laws would then be equalities
> of distributions.
>
> Rebasing a losing proposal onto a new tip is the place to add patch
> commutation. Angiuli, Morehouse, Licata and Harper, "Homotopical Patch
> Theory" (ICFP 2014), models patches as paths and fits there.

Consequence for quorum-lang: the guest checks the exact laws. DDH,
discrete log, the random oracle model, the threshold condition
2t > n + f and honest behavior stay assumptions. They are never guest
theorems.

### 4.2 Private ballots: exponential ElGamal on BN254

- Group: BN254 G1, prime order r, generator G. Ports: intent-lang
  src/front/{u256,bn254,elgamal}.c.
- Ballot: one of k choices with unit weight (Q7 (a)). The instance type
  is a closed admitted type, for example `Bool` (k = 2) or
  `Maybe (Maybe Bool)` (k = 4).
- Counting reading: a bag over k choices is its count per choice. Bag
  union is componentwise addition of the counts.
- The representation of `Hidden (FMSet Ballot)` is k ciphertexts. Slot j
  holds Enc(n_j) = (sG, n_j G + s PK) for a random s.
- `cast b`: Enc(1) at the slot of b, Enc(0) at each other slot.
- `∅`: k identity ciphertexts (the point at infinity twice).
- `x ⊕ y`: componentwise point addition.
- Exact laws: `⟦cast⟧`, `⟦∅⟧` and `⟦⊕⟧` hold exactly under the counting
  reading while each count stays below r.
- Ballot validity: a disjunctive Chaum-Pedersen proof per slot (the
  plaintext is 0 or 1) and a Chaum-Pedersen proof that the slot sum
  decrypts to 1. Port: intent-lang sigma.c (`sig_or_*`). This is the v1
  `ZK` instance: X = the k ciphertexts, Witness = the ballot and the
  randomness.
- Key generation (Q8 (b)): a Pedersen DKG, as in the FROST paper
  (Komlo and Goldberg, 2020, Figure 1). Each member i deals a random
  polynomial f_i of degree t - 1 with Feldman commitments to its
  coefficients and a Schnorr proof of knowledge of f_i(0). Each member
  checks each dealing. Member j keeps sk_j = sum of f_i(j) over the
  dealers whose dealing verifies. PK = sum of the commitments to f_i(0).
  No member learns sk. The DKG has its own fixtures (S6).
- Threshold decryption (`reveal q`): member i holds the DKG share sk_i
  of sk and the commitment PK_i = sk_i G. Member i sends
  d_i = sk_i c1 and a DLEQ proof that log_G PK_i = log_c1 d_i. Combine:
  Lagrange coefficients at 0 over the quorum, M = c2 - sum(λ_i d_i), then
  n = dlog_G M by bounded baby-step giant-step (n is at most the ballot
  count). Port: intent-lang threshold.c.
- Exact: Lagrange interpolation and `⟦reveal⟧` for an honest combine.
  Assumed: DDH (privacy) and DLEQ soundness in the random oracle model.

### 4.3 Certificates: FROST(secp256k1, SHA-256)

- RFC 9591, context string "FROST-secp256k1-SHA256-v1".
- NEW C code: SHA-256 (FIPS 180-4) and expand_message_xmd (RFC 9380) for
  H1 to H5. No *-lang repo has SHA-256 in C. mandate-lang secp256k1.c
  has `secp_recover` only; S7 adds the point operations and encodings
  that FROST needs.
- Key generation: the Pedersen DKG of sec 4.2 (Q8 (b)) over secp256k1.
  Each dealing has Feldman commitments and a Schnorr proof of knowledge
  of its constant term (FROST paper, Figure 1). The DKG has its own
  fixtures (S7).
- Round 1: each signer commits to a hiding nonce and a binding nonce.
  Round 2: each signer gives a signature share z_i. Aggregate: (R, z).
  Verify: zG = R + cPK, with c = H2(R, PK, msg).
- Meaning: `Endorses i σ σ'` = member i released a valid signature share
  on msg(σ, σ'). The rep of `Authorized σ σ'` is one aggregate signature
  on msg(σ, σ') = SHA-256(enc σ || enc σ') under the group key of
  `committee σ`. The signature does not depend on the signing set. That
  is why `Authorized` truncates the quorum.
- Test vectors: RFC 9591 Appendix E (secp256k1) as guest tests (O4).
  They fix the key shares, so they test signing only.
- Exact: FROST correctness (an honest aggregate verifies). Assumed:
  unforgeability (DL, random oracle model), `honest-meet`, `faithful`,
  `single`.

### 4.4 Resharing (`Sharing`)

- `Secret` = the group signing key and the ElGamal key. `Shares c` = the
  share vector of committee c.
- `reshare q c'`: each member i of q deals a sub-sharing of λ_i s_i to
  c' with the dealing of the DKG (Feldman commitments and a Schnorr proof
  of knowledge, Q8 (b)). Each new member adds its sub-shares. The group public key does not
  change, so clients keep the key that they pin.
- Exact: `⟦reshare⟧` (Lagrange). Assumed: honest dealing. Feldman
  commitments make each dealing checkable.

### 4.5 Summary

| Item | Exact law (guest or kit test) | Assumption (parameter) |
|---|---|---|
| ElGamal tally | `⟦cast⟧`, `⟦∅⟧`, `⟦⊕⟧` | DDH |
| Threshold decrypt | `⟦reveal⟧`, Lagrange | DLEQ soundness, honest combine |
| Ballot validity | `complete` | `ZK.⟦_⟧` (special soundness, random oracle model) |
| FROST | correctness | unforgeability, `honest-meet`, `faithful`, `single` |
| DKG (Q8 (b)) | each dealing verifies against its Feldman commitments; PK = sum of the constant-term commitments | DL; Schnorr proof of knowledge soundness (random oracle model) |
| Reshare | `⟦reshare⟧` | honest dealing |

## 5. Wasm replica (ruling 1)

The replica is one Wasm module. `langc` emits it from a quorum-lang
program and the kit runtime.

- Meaning: the design's `Replica` (sec 6 of the design). `Rep` = a set of
  certified steps (a grow-only set). `none` = the empty set. `merge` =
  set union. `⟦_⟧` = the tip, the end of the chain from genesis. By
  `no-fork` the certified steps form one chain, so the tip is unique.
- Laws: `⟦none⟧` (the empty set means genesis) and `⟦merge⟧ˡ`,
  `⟦merge⟧ʳ`, `⟦merge⟧ᵘ` (merge is the join, a fast-forward). They need
  the total order of certified states (O3).
- What a client checks: `certified→legit` over a certificate chain. The
  client checks each FROST signature from genesis to the tip. It learns
  `Legit σ` and holds no ballot.
- FHE route (real in v1): verify each ballot proof, add the ciphertexts
  (`⊕`), collect partial decryptions with DLEQ proofs, combine, then run
  `decide` in public on the counts. Law: `tallyᶠ-correct`.
- MPC route (law-only until a later MPC slice, Q6 (b)): `tallyᴹ` and
  `tallyᴹ-correct` are guest theorems at the denotation. Until S10 the
  replica does not run general MPC. S10 adds the MPC route under the
  protocol that Q14 rules.
- Exports (S8 fixes the names): `cert_verify`, `rep_merge`, `rep_tip`,
  `ballot_verify`, `tally_add`, `partial_verify`, `combine`,
  `step_apply`, `amend_accept`.
- Cryptography inside Wasm: Q9. (a) A fixed host-import ABI: the runner
  gives the field and group operations. (b) Bigint code emitted into the
  module.
- IVC: the v1 instance is the certificate chain (linear size, Q11 (b)).
  `start` = the empty chain. `extend` = append one certificate. A later
  slice (S11) adds a constant-size proof under the scheme that Q15 rules
  (O13). Its verifier laws stay guest terms (ruling 2).

## 6. Self-amendment

- `constitution σ a : Circuit (FMSet Ballot) (Maybe Edit)` is code in the
  State, and `rules σ a = run (constitution σ a)`. An Edit can replace
  the code. So a constitution IS a quorum-lang program.
- `Circuit a b` (Q3 (a)) is a closed first-order fragment of quorum-lang.
  Codes `a b : Code` index it, with `El : Code -> U`. Its terms are
  `Bool` and `Nat` operations, `Maybe`, pairs of codes and bag folds
  (`foldᴮ`). It has no general recursion and no higher-order values.
  `run` is the guest evaluator of the fragment. The replica embeds the
  same evaluator.
- R2 limits base names only. A constitution can define a majority test
  by recursion on `Nat` from `suc`.
- `Core σ := Path Bool (coreCheck σ) true`. `coreCheck` is an entrenched
  circuit that no Edit can change. Then `isPropCore` follows from
  `isSet Bool` (S4), and evaluation decides `keeps`: the replica
  evaluates `coreCheck σ'`.
- Boundary exclusion (`amend_accept`). The replica accepts an Edit that
  changes the constitution only when all three checks pass:
  1. The new code parses and type checks in the fragment at type
     `Circuit (FMSet Ballot) (Maybe Edit)`.
  2. Its laws check. For the FHE route the code has the form `decide`
     after `agg`, so `factors` holds by definition.
  3. `coreCheck σ'` evaluates to `true`.
- Q10: (a) the module carries the fragment checker; (b) the module
  trusts the certificate only.
- Rebase by patch commutation ("Homotopical Patch Theory") is not in the
  design. NOT DOING in v1 (O10).

## 7. Agent adoption

Each item of the pasted brief "Agent Incentives to Use DSL Programming
Languages" (design/DESIGN.md sec 1) maps to a deliverable, a slice and a
measurable gate, or to NOT DOING with a reason. The brief section number
comes first in the Brief item column.

| ID | Brief item | Deliverable | Slice | Gate, or NOT DOING reason |
|---|---|---|---|---|
| A1 | 1. Canonical, constrained surface: one form per operation, named intermediates, verbose keywords | Agda-like Unicode grammar (Q13 (b)) with one canonical form per operation (`→`, `λ`, `Σ`, mixfix design names such as `_×_`); named steps (`let x = t in u`, S2); no operator overloading; ASCII spellings give `W_NONCANON` (O12); `langc fmt` canonical printer; non-canonical input gives `W_NONCANON` with the canonical text as `fix` | S1 | `langc fmt F` equals F for each committed `.lang` file; `fmt` is idempotent; each non-canonical form has a fixture that gives `W_NONCANON` |
| A2 | 1. Fast, structured feedback: JSON diagnostics with fixes and retry fields | `langc check --json`: one JSON object per diagnostic with `code`, `span`, `expected`, `found`, `fix`, `retry`; docs/DIAGNOSTICS.md lists each code | S1 | each code in DIAGNOSTICS.md has a fixture; its JSON line matches the expect file byte for byte; the gate counts codes without a fixture and requires 0 |
| A3 | 1. Seed 3 to 5 high-quality examples | examples/agent/: 5 graded examples (certificate check, cast and tally, threshold reveal, amendment, replica merge) | S9 | each example checks with laws m of m; the SKILL.md copies equal the files (gate cmp) |
| A4 | 1. Custom agent instructions | AGENTS.md routing rule (S0, refreshed in S9) and skills/quorum-lang/SKILL.md | S0, S9 | each `langc` verb in AGENTS.md occurs in `langc --help` (gate) |
| A5 | 1. MCP servers that expose the schema and the types | `langc mcp`: a stdio JSON-RPC 2.0 server in C, built by tcc; tools `check`, `explain`, `list-base`, `show-law` | S9 | a fixed request transcript gives a fixed response transcript (cmp); `list-base` names = the sec 3 names |
| A6 | 1. Validator in the loop | SKILL.md loop: write, `check --json`, apply `fix`, repeat; the `retry` field says if a retry can help | S1, S9 | for each fixture with a `fix`, the fixed input gives exit 0 or the next code in the expect file |
| A7 | 2. Each well-formed program has a machine-checkable denotational semantics | ruling 2: each design law is a guest theorem; `langc check` checks it; `langc laws FILE` lists each law and its status | S4, S5 | `langc laws` on the design file reports 12 of 12 discharged (sec 3) |
| A8 | 2. Compositional denotations that agents can query | R1 (sec 2): each constructor is a CM (Q1 (b)), so bind and its laws come from the kernel; `langc explain --json NAME` gives kind, type, R1 class and slice | S2, S9 | one `explain` fixture for each sec 3 kind |
| A9 | 2. Multi-target compilation (Lean, ZK circuits, EVM or TVM IR) | none | none | NOT DOING: ruling 1 sets one target (the Wasm replica); ruling 2 keeps proofs in the guest |
| A10 | 2. Fixed point: only programs of useful semantic types are valid | a constitution must have type `Circuit (FMSet Ballot) (Maybe Edit)` and keep `Core`; the replica refuses other code | S8 | the A11 gate |
| A11 | 3. Exclusion or strong preference at the boundary | `amend_accept` in the Wasm replica (sec 6) | S8 | refuse fixtures (ill-typed code, a law fails, `Core` breaks) each give their code; 1 accept fixture is accepted; 0 other outcomes |
| A12 | 3. Soft incentives: fee discounts, collateral, matching, reward multipliers | none | none | NOT DOING: the design has no fees, collateral or markets, and R2 admits no such base type |
| A13 | 3. Token-efficient design | docs/TOKEN-BASELINE.md: 3 tasks in quorum-lang, Python and Rust, with token counts from one fixed offline proxy (Q12); a Unicode symbol (Q13 (b)) can cost more tokens than its ASCII spelling, and the baseline measures it | S9 | each table cell has a count; each quorum-lang file in the table checks |
| A14 | 3. Bounties or grants | none | none | NOT DOING by Claude: a USER decision (money) |
| A15 | 3. Reward shaping: dense credit for parse, type check and obligation discharge | progress counts as the last line of `check --json`: `{"parsed":p,"typed":t,"laws":{"discharged":d,"total":m}}` | S1 (parsed, typed), S4 (laws) | a fixture with a partial program reports the exact numbers |
| A16 | 4. Agent Skill (SKILL.md and files) or MCP server | skills/quorum-lang/SKILL.md, docs/GRAMMAR.md (one-page grammar card), the A3 examples, `langc mcp` | S9 | the A3 and A5 gates; SKILL.md front matter has `name` and `description` |
| A17 | 4. Fine-tune or distill a small model (< 500 MB) | corpus/INDEX.md: each program with its labels (codes, counts) | S9 (corpus only) | NOT DOING by Claude: the USER trains; gate: corpus/INDEX.md lists each `.lang` file in examples/ and test/ |
| A18 | 4. Publish the reference implementation, grammar and examples; list in catalogues (agentlanguages.dev) | this repo, docs/GRAMMAR.md, corpus/ | S9 | the listing is a USER step, never Claude |
| A19 | 4. Agents discover the DSL and default to it when the domain matches | README "When to reach for quorum-lang" table and the AGENTS.md routing rule | S0, S9 | each README "Yes" row names the slice that lands it |
| A20 | Practical starting sequence, steps 1 to 5 | step 1 = S1; step 2 = S2 to S5 (guest semantics, not a Lean embedding, ruling 2); step 3 = S9; step 4 = S8; step 5 = USER | all | the gates of those slices |

## 8. Port sources

SHA = `git -C REPO log -1 --format=%h` on 2026-10-25.

| Repo | SHA | What to port |
|---|---|---|
| lang-template | 5265a2a | hosts/tcc-wasm kit (the seed) |
| intent-lang | 79e1898 | src/front/{u256,bn254,elgamal,threshold,sigma,secp256k1}.c (BN254 G1, exponential ElGamal, Shamir deal, partial decrypt with DLEQ, Lagrange, disjunctive Chaum-Pedersen `sig_or_*`); check.c `REFUSE_CELL` and cocell; docs/PLAN.md 2.2 CM and CC table (lines 177 to 206); Enc as a sealed identity CM (lines 279 to 294) |
| bridge-lang | 5e4b34b | src/front/{elgamal,sigma}.c (second copy); test/gate.sh:321 em-dash exemption |
| mandate-lang | 0fb3760 | src/front/secp256k1.c (`secp_recover` only), u256.c, field.c; docs/PLAN.md shape (secs 1 to 11, Q items) |
| resolve-lang | 251c1ca | src/front/check.c `REFUSE_CELL` (second implementation) |
| zkpolicy-lang | 1d263fb | tcc-wasm kit with HITs and QIITs (C4) and Glue and ua (C6): src/front/{check,eval,lower}.c |
| agent-lang | 06854bf | src/front/parser.c JSON diagnostics (`"fix"`, expected and found) (S1 survey: no `"fix"` field, so no port; new C) |
| dil-lang | 9e57528 | src/front/{parser,check}.c JSON diagnostics (S1 survey: no `"fix"` field, so no port; new C) |
| tile-lang | e995934 | src/front/parser.c JSON diagnostics (S1 survey: no `"fix"` field, so no port; new C) |

NEW (no precedent in any *-lang repo): SHA-256, expand_message_xmd,
FROST, the `langc fmt` printer, the `check --json` printer, the
`langc mcp` server (O5).

## 9. Slices

One session for each slice. Each slice closes with the gate GREEN, its
mutants killed, PLAN and docs/STATUS.md updated, the change staged, a
commit message file and the next prompt file. The USER commits.

| Slice | Scope | Gate (measurable) | Mutants | Docs |
|---|---|---|---|---|
| S0 | kit seed, design/DESIGN.md, this plan, README.md, AGENTS.md | GREEN: make -j 2 check EXIT 0, gate: 0 failures, 16-line log | none | this file |
| S1 | surface: Agda-like Unicode grammar (Q13 (b)); `langc fmt`; `W_NONCANON`; `check --json`; progress counts (parsed, typed); kit formers under R1 and R2 (O7) | GREEN (A1, A2, A6, A15): make check EXIT 0, gate: 0 failures, 19-line log; fmt: 56 files canonical; json: 19 fixtures; diagnostics: 30 codes, 0 without a fixture or a row; refusals: 26 check, 9 parse; differential: 745 cases, 0 mismatches; wasm: 13 modules valid | 3: `fmt` not idempotent, a JSON key dropped, a count off by one; 3 of 3 KILLED | docs/DIAGNOSTICS.md, docs/GRAMMAR.md, docs/STATUS.md |
| S2 | kernel: Path, PathP, I, transp, hcomp, Sigma, Pi, U and levels (port zkpolicy-lang); `REFUSE_CELL` for CMs only (Q1 (b); port the CM branch of intent-lang, resolve-lang); indexed families; records as named Sigma (Q2); parameter sections (O8) | each sec 2.4 refuse fixture gives `REFUSE_CELL`; each admit fixture checks; `sym`, `cong`, `trans` type check | 3: generator test skipped, CC refusal skipped, family index check skipped | sec 2 notes |
| S3 | HITs: `∥_∥₁`, `FMSet` in generator form with its eliminator (O1), union, the truncation recursor, `∃`: the sec 3.1 Prelude in the guest | the guest Prelude checks; the `_++_` equation and the union unit, associativity and commutativity laws check; Wasm differential for bag operations, 0 mismatches | 3: comm path dropped, swap obligation not checked, set truncation dropped | sec 3.1 status |
| S4 | design secs 1 to 6 at the denotation: slots, `Policy`, `rules`, `Step`, `Reach`, `Legit`, `Authority`, descent, `Tip`, `Replica`, `current`, `Agree`; a closed toy instance; `langc laws`; law counts in `check --json` | 7 of 7 sec 1 to 6 laws discharged; the toy instance proves each obligation; O3 result recorded | 3: `keeps` not checked, quorum index ignored, `single` dropped | sec 3.2, 3.3 status |
| S5 | `Circuit` fragment (Q3), `run`, design secs 7 to 10 at the denotation (`Hidden` sealed, `Round`, `Aggregate`, `ZK`, `IVC`, `Sharing`); denotational instances | 12 of 12 design laws discharged; `run` agrees with direct evaluation on each fixture (Wasm differential) | 3: fragment admits a higher-order value, `⟦_⟧` escapes the seal, `factors` not checked | sec 3.4, sec 6 |
| S6 | BN254 ElGamal, Pedersen DKG for the ElGamal key (Q8 (b)), ballot validity proofs, threshold decryption (port intent-lang); kit differential tests of the representation map (Q5 (a)) | decrypt of the sum of casts = the bag counts, N cases, 0 mismatches; known-answer vectors equal; each invalid-proof fixture refused; each DKG fixture (good dealing, bad share, bad proof of knowledge) gives its result | 3: one slot of `⊕` skipped, DLEQ check skipped, Lagrange sign flipped | sec 4.2 |
| S7 | SHA-256 (FIPS 180-4), expand_message_xmd (RFC 9380), secp256k1 point operations, FROST key generation by Pedersen DKG (Q8 (b)), commit, sign, aggregate, verify (RFC 9591), reshare | FIPS 180-4, RFC 9380 and RFC 9591 Appendix E vectors byte-equal (signing); each DKG fixture gives its result; old and new committees sign under one group key after reshare | 3: binding factor dropped, one SHA-256 round skipped, reshare coefficient wrong | sec 4.3, 4.4 |
| S8 | Wasm replica: sec 5 exports, certificate chain check, merge and tip, FHE tally route, `amend_accept` | a scripted history of k certified steps; two replicas merge to one tip; refuse fixtures (bad signature, fork, ill-typed constitution, `Core` break) each give their code; the accept fixture is accepted | 3: fork check skipped, `Core` check skipped, fragment check skipped | sec 5, sec 6 |
| S9 | agent kit: SKILL.md, docs/GRAMMAR.md, examples/agent/ (5), `langc mcp`, `langc explain --json`, AGENTS.md refresh, docs/TOKEN-BASELINE.md, corpus/INDEX.md | A3, A4, A5, A8, A13, A16, A17, A19 gates | 3: MCP tool drops a field, a SKILL.md copy drifts, `list-base` misses a name | sec 7 status |
| S10 | general MPC tally route (Q6 (b)) under the protocol that Q14 rules; the replica runs `tallyᴹ` | `tallyᴹ` = `tallyᶠ` on each fixture, N cases, 0 mismatches; `tallyᴹ-correct` checks | 3: one share dropped from the sum, a reconstruction coefficient wrong, MPC output not checked | sec 5 |
| S11 | constant-size IVC proof (Q11 (b)) under the scheme that Q15 rules; verifier laws as guest terms (ruling 2) | proof size is the same for histories of 1, 10 and 100 steps; `start✓`, `extend✓` and `IVC.⟦_⟧` check for the new instance; each bad-proof fixture refused | 3: one step not folded, verifier check skipped, state hash not bound | sec 3.4, sec 5 |
| S12 | close: docs final, mutant sweep of S1 to S11, README status | full gate GREEN; each earlier mutant killed again | sweep | STATUS, README |

## 10. O items

- O1. `foldᴮ`. The Prelude gives a cons-form eliminator with a swap
  obligation. In generator form, the kernel gives the generator eliminator as a
  primitive eliminator into a set, and the swap obligation is an
  argument. S3 decides if the generator recursor can derive it.
- O2. `zero`. The Prelude imports only `suc` from Nat. quorum-lang
  admits `zero` as part of the `Nat` data declaration and adds no other
  operation. The USER can rule otherwise.
- O3. Tip order (design "Not covered", item 3). S4 tries a guest proof
  by induction on height from `advance` and `no-fork`. If it fails, the
  replica laws take the order as an explicit parameter.
- O4. Crypto test vectors as guest tests. Each vector calls a kit
  primitive from a guest test and compares bytes (ruling 2; tests in the
  development language).
- O5. New C code without precedent: SHA-256, expand_message_xmd, FROST,
  `langc fmt`, `langc mcp` and its JSON printer.
- O6. Gate tools: the gate needs tcc, clang, node, wasm-validate and
  wasm-objdump on PATH.
- O7. Kit core names under R1 and R2 (S1, decided). The cons form of
  `List` is refused: `List`, `cons` and `nil` give `REFUSE_CELL`, and the
  design does not use lists. `Flag` becomes `Bool` (`true`, `false`).
  `Nat` becomes `ℕ` with `suc`. `Option` becomes `Maybe` (`just`,
  `nothing`). `Prod` becomes `_×_` (ambient, infix). `Sum` is not in the
  design: S1 removes it, and does not keep it as a Sigma over `Bool`.
  `Sum` and its operations give `REFUSE_BASE`. `filter` is derived, not a
  core operation: it gives `REFUSE_BASE`, and a guest example defines it
  on `Maybe`. `Eq` becomes `Path` (S2).
- O8. Parameter sections. The design telescope and the modules
  `Authority`, `Round` and `Aggregate` become a guest parameterized `module` form (as in Agda).
  Its parameters become Pi binders, so the form is ambient.
- O9. CC. The design uses no comonad, and Q1 (b) rules CM only. S2
  ports the CM branch of `REFUSE_CELL` only. A coinductive record with a
  type parameter is a refuse fixture (`REFUSE_CELL`).
- O10. NOT DOING in v1 (design "Not covered"): liveness, coercion
  resistance, fork attribution, differential-privacy noise (it needs a
  distribution monad, which R2 does not admit), patch commutation for
  rebase.
- O11. A rare weight value can identify a voter (design "Not covered",
  item 5). v1 uses unit weight (Q7 (a)).
- O12. Non-canonical input (Claude reading, NOT ruled). The parser
  accepts an ASCII spelling (`->` for `→`, `\` for `λ`) and other
  non-canonical forms. `langc check` then gives `W_NONCANON` with the
  canonical Unicode text as `fix`, so `langc fmt` keeps one form per
  operation. The USER can rule that ASCII input is an error.
- O13. Constant-size IVC (Q11 (b)). A constant-size proof needs a proof
  system outside the ruling 3 set (ElGamal and FROST). So the USER rules
  the scheme (Q15) before S11. Its verifier laws stay guest terms
  (ruling 2).

## 11. Q items (for USER ruling; (a) is RECOMMENDED)

- Q1. R1 reading. RULED (b) 2026-10-25. (a) The intent-lang and mandate-lang reading (sec 2.1).
  (b) A stricter reading: CM only, no CC.
- Q2. Records. RULED (a) 2026-10-25. (a) A record is a named iterated Sigma, ambient, with type
  parameters allowed (`ZK {X}`). (b) Records only at closed instances.
- Q3. `Circuit`. RULED (a) 2026-10-25. (a) A codes-indexed closed first-order fragment with
  folds only. (b) Ambient functions with no quoting; then the replica
  cannot check an amendment.
- Q4. `Hidden`. RULED (a) 2026-10-25. (a) The sealed identity CM; `⟦_⟧` is law-only (intent-lang
  Q3 (a)). (b) An abstract field `U -> U`, which R1 refuses.
- Q5. Representation laws. RULED (a) 2026-10-25. (a) The guest checks each law at the
  denotation; kit differential tests check the representation map.
  (b) A guest model of the exponents mod r; the guest proves each
  homomorphism over the model.
- Q6. Tally routes. RULED (b) 2026-10-25. (a) The replica runs the FHE route; the MPC route is
  law-only. (b) General MPC later.
- Q7. Ballot. OPEN: it blocks S6 only; Claude asks it at the S5 close. (a) One of k choices with unit weight. (b) Public weights.
  (c) Encrypted weights with range proofs.
- Q8. Key generation. RULED (b) 2026-10-25. (a) Trusted dealer with Feldman VSS. (b) Pedersen
  DKG.
- Q9. Cryptography in Wasm. RULED (a) 2026-10-25. (a) A fixed host-import ABI. (b) Bigint code
  emitted into the module.
- Q10. Amendment check. RULED (a) 2026-10-25. (a) The module carries the fragment checker.
  (b) The module trusts the certificate.
- Q11. IVC. RULED (b) 2026-10-25. (a) The certificate chain, linear size. (b) A constant-size
  proof later.
- Q12. Token counts. RULED (a) 2026-10-25. (a) One fixed offline proxy, written in
  TOKEN-BASELINE.md; the USER can refresh the counts with the API.
  (b) API counts only.
- Q13. Surface. RULED (b) 2026-10-25. (a) An ASCII verbose-keyword surface with a name map from
  the design's Unicode (sec 3). (b) An Agda-like Unicode surface.
- Q14. MPC protocol (S10, Q6 (b)). (a) Honest-majority BGW over the
  committee's Shamir shares. (b) SPDZ-style with preprocessing (dishonest
  majority). Needed before S10.
- Q15. Constant-size IVC proof scheme (S11, Q11 (b), O13). (a) A folding
  scheme (Nova-style) with a final compressed proof. (b) A recursive
  SNARK. Needed before S11.
