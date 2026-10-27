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
USER ruling on Q7, 2026-10-26 (S5 close, AskUserQuestion), verbatim:
"(a) Unit weight (Recommended)".

| Q | Ruling | Effect |
|---|---|---|
| Q1 | (b) | R1 admits CMs only. A CC is refused with `REFUSE_CELL` (secs 2.1, 2.3, 2.4). S2 has no cocell branch (O9). |
| Q2 | (a) | A record is a named iterated Sigma, ambient, with type parameters (sec 2.2). |
| Q3 | (a) | `Circuit` is the codes-indexed closed first-order fragment (sec 2.3, S5). |
| Q4 | (a) | `Hidden` is the sealed identity CM. `⟦_⟧` is law-only (sec 2.3, S5). |
| Q5 | (a) | The guest checks each law at the denotation. Kit differential tests check the representation map (S6, S7). |
| Q6 | (b) | The MPC route stays law-only until the MPC slice S10 (sec 5, Q14). |
| Q7 | (a) | A ballot is one of k choices with unit weight (sec 4.2, S6). |
| Q8 | (b) | A Pedersen DKG makes the FROST key and the ElGamal key (secs 4.2 to 4.4, S6, S7). |
| Q9 | (a) | Cryptography in Wasm uses a fixed host-import ABI (sec 5, S8). |
| Q10 | (a) | The module carries the fragment checker (sec 6, S8). |
| Q11 | (b) | v1 keeps the certificate chain. The slice S11 adds a constant-size proof (sec 5, Q15, O13). |
| Q12 | (a) | One fixed offline proxy gives the token counts (A13, S9). |
| Q13 | (b) | The surface is Agda-like Unicode with the design names (sec 3, A1, docs/GRAMMAR.md, S1). |
| Q16 | (b) | Ruled 2026-10-26 at S3 (AskUserQuestion), verbatim "(b) Guest proof". The kernel has a dependent eliminator `elim` for ℕ and Bool. Discreteness and Hedberg are guest laws in lib/prelude.lang. The kernel has no constant for `isSet` (sec 3.1, O37, O44). |

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

S2 status (Claude reading, NOT ruled; O14 to O36). S2 implements this
ambient structure: Pi; `Σ` with `_,_`, `fst` and `snd`, and `A × B` as
the non-dependent `Σ`; `PathP L a b` and `a ≡ b` (`Path` is a kernel
name only); `I`, `i0`, `i1`, `~ r`, `r ∧ s` and `r ∨ s`; `primTransp`
and `primHComp` (a system `λ { ... }` is legal only as the side of
`primHComp`); `Type`, `Type₁`, `Level`, `lzero`, `lsuc`, `ℓ-max` and
`Type ℓ` for a closed level of at most 1. S2 has no level variables
(O18). `record NAME group* : Type where` is a transparent named `Σ`
(O15). `module NAME group* where` is a parameter section (O16).
`let x = t in u` is a named step (O17). An indexed family has the head
`data NAME group* : A₁ → ... → Type where`, with value parameters and
index types that are not dependent (O24). S2 has no eliminator for an
indexed family or a higher inductive family: `fold` over one gives
`DOMAIN_FAMILY` (O31). S3 adds the eliminators (O37, O38, O40):
`elim` for ℕ and Bool, `fold` over a CM with path constructors and
`foldᴮ` for a bag. A `fold` over an indexed family still gives
`DOMAIN_FAMILY`.

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

S2 status (Claude reading, NOT ruled; O14). The checker sorts a program
`data` declaration in this order. (1) A declaration with a type
parameter gets the CM check (the port of `cell_header`, `cell_field` and
`cell_generators`); a failure gives `REFUSE_CELL`. (2) A declaration
with an index type that ends in a universe gives `REFUSE_CELL`. (3) A
declaration with value parameters or indices is an indexed family. (4)
A closed declaration gives `REFUSE_DATA`: a base type comes only from
`domain/domain.lang` (R2). A record field of a type-constructor type and
a coinductive record give `REFUSE_CELL` (O15). The fixtures use the S1
surface. Refuse fixtures (test/check, each `REFUSE_CELL`):
`cell-pair.lang`, `cell-list.lang` (`List₀`, because `List` is a refused
name), `cell-fmset-cons.lang`, `cell-record-field.lang`, `cell-cc.lang`,
and `cell-type-index.lang` for case (2). Admit fixtures
(examples/cells.lang): `Maybe₀`, `Trunc₀` and `Bag₀` in generator form.
examples/paths.lang defines `sym`, `cong`, `trans` and `transport` as
guest terms (O19).

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

S3 status (Claude reading, NOT ruled; O37 to O56). Each row above with
slice S3 is a guest term or a kernel rule, and `langc check` checks it.
lib/prelude.lang holds `_∘_`, `sym`, `cong`, `_∙_`, `isProp`, `isSet`,
`∥_∥₁` (`∣_∣₁`, `squash₁`), `rec₁`, `∃` and the Hedberg chain (Q16 (b),
O44): `absurd`, `eqℕ`, `reflℕ`, `soundℕ`, `eqBool`, `reflBool`,
`soundBool`, `discreteIsSet`, `isSetℕ` and `isSetBool`.
examples/bag.lang holds `FMSet` in generator form (constructors `eta`,
`[]`, `m`, `munit`, `massoc`, `mcomm`, `trunc`) and, in
`module Bag (A : Type)`, the derived view `_∷_` and `comm`, `_++_`
(`m`), the laws (O45, O56) and `count` by `foldᴮ`. `foldᴮ` is a kernel
eliminator (O40). `∃[ x ꞉ A ] B` is a notation for
`∃ A (λ (x : A) → B)` (O41).

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

S4 status (Claude reading, NOT ruled; O57 to O66). examples/threshold.lang
holds secs 1 to 4 in `module Design` (the 22 slot and obligation params,
O58): `Policy`, `rules`, `StepD`, `step`, `Chain`, `Reach`, `root`,
`_▸_`, `Legit`, `chain-core` and the laws `reach-core` and `legit-core`
(`→` is reserved, O62). `Step` is a top-level record with 9 params and
the 6 fields of Q2 (O59). `Reach` is a chain of ℕ length by `elim` on
ℕ, not a data type (O57). The slot `⟦_⟧ᵉ` is the param `apply` (O62).
The closed toy instance (O65) proves `isSetState`, `advance`,
`isPropCore` and `core₀`, and applies `reach-core` (`toyOne`) and
`legit-core`. The toy fills `Circuit` and `run` with
`Circuit A B = A → B` and `run A B f = f`. S5 fills them with the
language (Q3).

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

S4 status (Claude reading, NOT ruled; O57 to O66). examples/threshold.lang
holds secs 5 and 6 in `module Authority` (the 22 params of `Design` and
`Honest`, `Endorses`, `honest-meet`, `faithful`, `single`, O58).
`Authorized`, `Desc`, `_⊑_`, `here`, `_⊳_`, `Tip`, `ReplicaA`,
`current` and `Agree` are definitions. `_⊑_` is a chain of ℕ length
(O57). The laws `honest-in`, `sound`, `no-fork`, `certified-legit` and
`certified-core` check. `Replica` is a top-level record (O59) with the
fields `Rep`, `none`, `merge`, `denote`, `denote-none`,
`denote-mergeˡ`, `denote-mergeʳ` and `denote-mergeᵘ` (O62). It takes
the order `Le` as a param, and `ReplicaA` gives it `_⊑_`. `tip-order`
proves the tip order (O3). The toy instance applies `certified-core`
(`toyCertifiedCore`). Each of the 7 laws of secs 1 to 6 has the `law`
mark (O64), and `langc laws examples/threshold.lang` prints
`laws: 7 of 7 discharged`. S8 gives the Wasm instance of `Replica`.

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

S5 status (Claude reading, NOT ruled; O72 to O75). examples/threshold.lang
holds secs 7 to 10. `Hidden` and `unseal` are the domain ones (O72), so
`⟦_⟧` is the law-only `unseal`. `Private` is a top-level record (O59)
with the fields `cast`, `∅`, `_⊕_`, `eval`, `reveal`, `⟦cast⟧`, `⟦∅⟧`,
`⟦⊕⟧`, `⟦eval⟧` and `⟦reveal⟧`. `_≼_` is a top-level definition. `Round`
and `Aggregate` are top-level modules (O74a). Each takes the 11
parameters that it uses (the last is `P`), and `Aggregate` then takes
`M`, `agg`, `decide` and `factors`. `ZK`, `IVC` and `Sharing` are
top-level records. `IVC.prove` is the law `ivc-prove` in `module Design`,
by ℕ `elim` on the chain length (O57). The `_++_` equation is the law
`app-cons`. Each of the 12 laws has the `law` mark, and `langc laws
examples/threshold.lang` prints `laws: 12 of 12 discharged`.
examples/denote.lang holds the denotational instances (O75, O75a):
`Private` over the domain seal (`law den-private`: `⊕` and `eval` open
the seal and seal the result again), `ZK` (`Proof x = ∥ W x ∥₁`), `IVC`
(`Proof = LegitM`), `Sharing` (`reshare = id`) and an `Aggregate`
instance (`denAgg` is a `run` of `tally`). `langc laws
examples/denote.lang` prints `laws: 1 of 1 discharged`.

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

S6 status (Claude reading, NOT ruled; O78 to O87). src/crypto holds the
port of intent-lang 79e1898 (keccak, u256, bn254, elgamal, threshold and
sigma; thr_deal and elg_scale are not ported) and the new C file dkg.c
(the Pedersen DKG of O79). langc does not link src/crypto: the host
import ABI comes in S8 (Q9 (a)). The C tool test/tallytool.c
(build/tallytool) has the known-answer rows (O82), the invalid-proof
rows (O83) and the DKG rows (O84). Its `rep` mode is the tally route
(O80): one DKG (t 2, n 3), a cast for each ballot (k 2), `tally_add`
slot by slot, `thr_open` of each slot over the quorum {1, 2}, and one
eval line for each count. The gate gives each line to `langc eval` on
the entries denCount1 to denCount3 of examples/denote.lang (O81): 14
cases, 28 counts, 0 mismatches.

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

S5 status (Claude reading, NOT ruled; O68 to O71, O76). `Code` is
domain data in domain/domain.lang: `bitC`, `natC`, `optC`, `pairC` and
`bagC` (O68). lib/prelude.lang renames its old `Code` to `BoolCode`.
examples/circuit.lang declares `data Circuit : Code → Code → Type`, a
program indexed family with the constructors `idC`, `seqC`, `fanC`,
`zeroC`, `sucC`, `addC`, `leC`, `guardC` and `countC` (O69). `El : Code →
Type` is a guest `fold`. The kernel name `foldᴵ` is the index recursor
(O70), and `run a b c` is a `foldᴵ` over `Circuit`. A circuit family
has only `Code` indices. Each constructor field must be a `Code`, a `ℕ`,
a `Bool` or the family itself, else REFUSE_CIRCUIT (O71). So a circuit
is first order. `majRun`, `countRun` and `addRun` run closed circuits,
`majDirect` is the direct guest evaluation, and `agree a b c` compares
`majRun` and `majDirect` (O76). The eval rows and the Wasm differential
show that `run` agrees with direct evaluation, with 0 mismatches.
examples/threshold.lang takes `Circuit` and `run` as parameters over
`Type`. Its toy instance uses `toyCircuit A B = A → B` and `toyRun A B f
= f`.

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

S6 note: src/crypto ports intent-lang 79e1898
src/front/{keccak,u256,bn254,elgamal,threshold,sigma}.c. secp256k1.c
waits for S7. thr_deal (the Shamir deal) and elg_scale (weighted
ballots; Q7 (a) has unit weight) are not ported. The DKG
(src/crypto/dkg.c) is new C (O79).

## 9. Slices

One session for each slice. Each slice closes with the gate GREEN, its
mutants killed, PLAN and docs/STATUS.md updated, the change staged, a
commit message file and the next prompt file. The USER commits.

| Slice | Scope | Gate (measurable) | Mutants | Docs |
|---|---|---|---|---|
| S0 | kit seed, design/DESIGN.md, this plan, README.md, AGENTS.md | GREEN: make -j 2 check EXIT 0, gate: 0 failures, 16-line log | none | this file |
| S1 | surface: Agda-like Unicode grammar (Q13 (b)); `langc fmt`; `W_NONCANON`; `check --json`; progress counts (parsed, typed); kit formers under R1 and R2 (O7) | GREEN (A1, A2, A6, A15): make check EXIT 0, gate: 0 failures, 19-line log; fmt: 56 files canonical; json: 19 fixtures; diagnostics: 30 codes, 0 without a fixture or a row; refusals: 26 check, 9 parse; differential: 745 cases, 0 mismatches; wasm: 13 modules valid | 3: `fmt` not idempotent, a JSON key dropped, a count off by one; 3 of 3 KILLED | docs/DIAGNOSTICS.md, docs/GRAMMAR.md, docs/STATUS.md |
| S2 | kernel: Path, PathP, I, transp, hcomp, Sigma, Pi, U and levels (port zkpolicy-lang); `REFUSE_CELL` for CMs only (Q1 (b); port the CM branch of intent-lang, resolve-lang); indexed families; records as named Sigma (Q2); parameter sections (O8) | GREEN: each sec 2.4 refuse fixture gives `REFUSE_CELL` (6 files in test/check, sec 2.4 note); `Maybe₀`, `Trunc₀`, `Bag₀` check (examples/cells.lang); `sym`, `cong`, `trans` type check (examples/paths.lang); make check EXIT 0, gate: 0 failures (serial log); fmt: 74 files canonical; json: 22 fixtures; diagnostics: 33 codes, 0 without a fixture or a row; refusals: 38 check, 9 parse; evals: 41; differential: 767 cases, 0 mismatches; wasm: 16 modules valid | 3: generator test skipped (`cell-ghost.lang` fails), CC refusal skipped (`cell-cc.lang` fails), family index check skipped (`cell-type-index.lang` fails); 3 of 3 KILLED | sec 2 notes; sec 10 O14 to O36; docs/DIAGNOSTICS.md, docs/GRAMMAR.md, docs/STATUS.md |
| S3 | HITs: `∥_∥₁`, `FMSet` in generator form with its eliminator (O1), union, the truncation recursor, `∃`: the sec 3.1 Prelude in the guest | GREEN: lib/prelude.lang checks (the guest Prelude, with `isSetℕ` and `isSetBool` by a guest Hedberg proof, Q16 (b)); in examples/bag.lang the `_++_` equation (`consApp`, `appUnitL`) and the union unit, associativity and commutativity laws (`appUnitL`, `appUnitR`, `appAssoc`, `appComm`) check; make check EXIT 0, gate: 0 failures (serial log); fmt: 83 files canonical; json: 23 fixtures; diagnostics: 34 codes, 0 without a fixture or a row; refusals: 43 check, 9 parse; evals: 56; differential: 4007 cases, 0 mismatches (bag entries `count3`, `countUnion`, `countFlags`, `scale`); wasm: 18 modules valid | 3: comm path dropped (`bag-no-comm.lang` fails), swap obligation not checked (`bag-bad-swap.lang` fails), set truncation dropped (`bag-no-trunc.lang` fails); 3 of 3 KILLED | sec 1.2 Q16; sec 2.2 and 3.1 status; sec 10 O37 to O56; docs/DIAGNOSTICS.md, docs/GRAMMAR.md, docs/STATUS.md |
| S4 | design secs 1 to 6 at the denotation: slots, `Policy`, `rules`, `Step`, `Reach`, `Legit`, `Authority`, descent, `Tip`, `Replica`, `current`, `Agree`; a closed toy instance; `langc laws`; law counts in `check --json` | GREEN: examples/threshold.lang checks; 7 of 7 sec 1 to 6 laws discharged (`reach-core`, `legit-core`, `honest-in`, `sound`, `no-fork`, `certified-legit`, `certified-core`); the toy instance proves each obligation (`isSetState`, `advance`, `isPropCore`, `core₀`); O3 PROVED (`tip-order`); `langc laws`: `laws: 7 of 7 discharged`; `check --json`: `"laws":{"discharged":7,"total":7}`; make check EXIT 0, gate: 0 failures (serial log); fmt: 86 files canonical; json: 24 fixtures; diagnostics: 34 codes, 0 without a fixture or a row; refusals: 43 check, 9 parse; evals: 61; differential: 4074 cases, 0 mismatches; wasm: 20 modules valid | 3: `keeps` not checked (`step` fails, `laws: 0 of 7`), quorum index ignored (`Authorized` fails, `laws: 2 of 7`, O67), `single` dropped (`fork-meet` fails, so `no-fork` and `tip-order` fail, `laws: 4 of 7`); the examples loop and the laws line kill each one; 3 of 3 KILLED | sec 3.2 and 3.3 status; sec 10 O3, O57 to O67; docs/GRAMMAR.md, docs/STATUS.md, AGENTS.md |
| S5 | `Circuit` fragment (Q3), `run`, design secs 7 to 10 at the denotation (`Hidden` sealed, `Round`, `Aggregate`, `ZK`, `IVC`, `Sharing`); denotational instances | GREEN: examples/threshold.lang checks; 12 of 12 design laws discharged (the 7 S4 laws, `app-cons`, `ivc-prove`, `tallyᴹ-correct`, `tallyᶠ-correct`, `mpc≼fhe`); `langc laws`: `laws: 12 of 12 discharged`; `check --json`: `"laws":{"discharged":12,"total":12}`; examples/denote.lang: `laws: 1 of 1 discharged` (`den-private`); `run` agrees with direct evaluation (`agree` gives 1 on each eval row; the circuit.lang and denote.lang entries are in the Wasm differential); make check EXIT 0, gate: 0 failures (serial log); fmt: 95 files canonical; json: 27 fixtures; diagnostics: 36 codes, 0 without a fixture or a row; refusals: 48 check, 9 parse; evals: 72; differential: 5246 cases, 0 mismatches; wasm: 22 modules valid | 3: fragment admits a higher-order value (O71 check off: `circuit-ho.lang` and the `REFUSE_CIRCUIT` json fixture fail), `⟦_⟧` escapes the seal (`REFUSE_LAW` off: `seal-fold.lang`, `seal-unseal.lang`, `seal-relay.lang` and the `REFUSE_LAW` json fixture fail), `factors` not checked (its right side becomes its left side: `tallyᶠ-correct` fails with `TYPE_MISMATCH`, `check --json` gives 10 of 12 laws); 3 of 3 KILLED | sec 3.4 and sec 6 status; sec 10 O68 to O77; sec 11 Q7; docs/GRAMMAR.md, docs/STATUS.md |
| S6 | BN254 ElGamal, Pedersen DKG for the ElGamal key (Q8 (b)), ballot validity proofs, threshold decryption (port intent-lang); kit differential tests of the representation map (Q5 (a)) | GREEN: decrypt of the sum of casts = the bag counts (`build/tallytool rep` against `langc eval` on denCount1 to denCount3): `tally: 14 cases, 28 counts, 0 mismatches`; known-answer vectors equal (O82); each invalid-proof fixture refused (9 rows, O83); each DKG fixture gives its result (good dealing: QUAL {1, 2, 3}; bad share: DKG_BAD_SHARE, QUAL {1, 3}; bad proof of knowledge: DKG_BAD_PROOF, QUAL {2, 3}; DKG_BAD_INDEX; DKG_TOO_FEW); `tally regressions: passed`; make check EXIT 0, gate: 0 failures (serial log); fmt: 103 files canonical; json: 29 fixtures; diagnostics: 36 codes, 0 without a fixture or a row; refusals: 54 check, 9 parse; evals: 75; laws: 12 of 12 (examples/threshold.lang) and 1 of 1 (examples/denote.lang); ir: 19 lowered; differential: 5274 cases, 0 mismatches; wasm: 22 modules valid | 3: one slot of `⊕` skipped (`tally_add` bound `j + 1u < k`: 10 of the 28 rep lines differ, the row `tally k 2 slot 1` fails), DLEQ check skipped (the `thr_open` refusal off: the rows `part D + G` and `part z + 1` fail), Lagrange sign flipped (each rep line gives `open-1`, 8 open rows fail); 3 of 3 KILLED | sec 4.2 status; sec 8 note; sec 10 O78 to O89; docs/STATUS.md, README.md |
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
  argument. S3 decides if the generator recursor can derive it. S3
  result: it cannot, so `foldᴮ` is a kernel rule with the swap
  obligation as an argument (O40).
- O2. `zero`. The Prelude imports only `suc` from Nat. quorum-lang
  admits `zero` as part of the `Nat` data declaration and adds no other
  operation. The USER can rule otherwise.
- O3. Tip order (design "Not covered", item 3). S4 tries a guest proof
  by induction on height from `advance` and `no-fork`. If it fails, the
  replica laws take the order as an explicit parameter. S4 result:
  PROVED. `tip-order : (t : Tip) → (u : Tip) → ∥ Ordered (fst t)
  (fst u) ∥₁` (examples/threshold.lang, `module Authority`): two tips
  are in the descent order, one before the other. The proof uses
  `no-fork` only, by induction on the length of one chain (O66).
  `Replica` keeps the order `Le` as a param (O59), and `ReplicaA`
  gives it `_⊑_`.
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
- O14. `REFUSE_DATA` and `REFUSE_CELL` (Claude reading, NOT ruled; S2).
  The checker sorts a program `data` declaration in the sec 2.4 order:
  a type parameter (the CM check), a type index (`REFUSE_CELL`), value
  parameters or indices (an indexed family), closed (`REFUSE_DATA`). The
  declarations in `domain/` keep the S1 path.
- O15. Records (Claude reading, NOT ruled; S2, Q2 (a)). A record is a
  transparent named `Σ`: `R p` unfolds to a `Σ` chain, a value is a `_,_`
  tuple, and each field name is a global projection. A record with a
  type parameter is admitted. A field of a type-constructor type (for
  example `Type → Type`) and a coinductive record give `REFUSE_CELL`. A
  field that names its own record gives `REFUSE_REC`.
- O16. Parameter sections (Claude reading, NOT ruled; S2, O8).
  `module NAME group* where` holds definitions indented by 2. In the
  section, a name of the section gets the section parameters. Outside
  the section, the name takes the parameters explicitly. S2 has no
  qualified names and no data or records in a section.
- O17. Named steps (Claude reading, NOT ruled; S2, A1). `let x = t in u`
  infers the type of `x` from `t` and binds `x` as a defined local. S2
  has no type annotation on `let`. A value that does not infer gives the
  `TYPE_INFER` texts.
- O18. Levels (Claude reading, NOT ruled; S2). S2 has closed levels
  only. `Level` is a distinct type (not convertible with `ℕ`). `Type ℓ`
  takes a `Level` term with a closed normal form of at most 1. A level
  that is not closed gives `TYPE_UNIVERSE`. S2 has no level variables,
  so the S3 guest Prelude uses fixed levels. The examples and test/eval
  have no `Level` definition, so the lowering of a `Level` value has no
  gate line.
- O19. `Eq` becomes `Path` (Claude reading, NOT ruled; S2, O7). S2
  removes the kit names `Eq`, `symm`, `trans`, `cong`, `transport` and
  the `Eq` proof irrelevance. `refl` stays a builtin: against
  `PathP L a b` it becomes `λ i → a` when `a` and `b` are convertible.
  examples/paths.lang defines `sym`, `cong`, `trans` and `transport` as
  guest terms.
- O20. Path surface (Claude reading, NOT ruled; S2). The surface has
  `PathP L a b` and the infix `a ≡ b`. `Path` is a kernel name only.
  `a ≡ b` takes the type from `a`, else from `b`. A path application is
  a plain application `p r`. A path abstraction is `λ i → t` against a
  `PathP` type. `×` binds tighter than `≡`, and `≡` binds tighter than
  `→`.
- O21. Interval and Kan operations (Claude reading, NOT ruled; S2). The
  surface has `I`, `i0`, `i1`, `~ r`, `r ∧ s`, `r ∨ s`,
  `primTransp (λ i → A) r u` and `primHComp (λ j → λ { ... }) u0`. A
  system is legal only as the side of `primHComp`. S2 has no surface
  `Partial` or `fromPartial`, and no ASCII spelling for these forms.
- O22. `Σ` and pairs (Claude reading, NOT ruled; S2). `A × B` is a `Σ`
  with a constant codomain. `a , b` makes a pair, and `fst` and `snd`
  project. S2 removes the kit names `pair`, `first`, `second`, `pack`,
  `witness` and `payload` (`NAME_UNKNOWN`). The value printer prints a
  constant `Σ` as `A × B`.
- O23. Higher inductive constructors (Claude reading, NOT ruled; S2). A
  constructor result is a point, a 1-cell `s ≡ t` over point terms, or a
  2-cell `p ≡ q` over path fields. A path constructor is a global
  constant of its path type, and its ends reduce at `i0` and `i1`. S2
  has no eliminator (S3).
- O24. Indexed families (Claude reading, NOT ruled; S2). The head is
  `data NAME group* : A₁ → ... → Type where`. A constructor result is
  the family name, each parameter name and one atom for each index. The
  checker checks each atom against its index type (`TYPE_MISMATCH`). A
  recursive field is the family applied, with no arrow. The fields of
  an indexed family are a telescope. In a CM with value indices, a field
  can use only the parameters. The index types of the head are not
  dependent. S2 has no mixfix use of guest operators: write `_∈_ b bs`.
- O25. `explain --json` (Claude reading, NOT ruled; S2, A8). S2 adds no
  verb. The R1 class of each family (CM, indexed family, record, base
  type) is the input of the S9 verb `explain --json`.
- O26. New codes (Claude reading, NOT ruled; S2). `TYPE_ENDPOINT`: an
  end of a path abstraction is not the end in its type. `TYPE_SYSTEM`:
  two cells of a system do not agree where they overlap. Each code has a
  row in docs/DIAGNOSTICS.md and a test/json fixture.
- O27. Lowering (Claude reading, NOT ruled; S2). `PathP`, path
  abstractions, `I`, `i0`, `i1` and proofs erase as the S1 `Eq` and
  `refl` values did. A Kan operation that is stuck at run time is an
  internal error. `primTransp` reduces to its base when its face holds,
  or when its line is a universe, `ℕ`, `Bool` or `Unit`. `primHComp`
  reduces to its side at `i1` when its face holds. S2 has no structural
  Kan computation for Pi, `Σ`, `PathP` or domain data. At other types
  the operations stay stuck: conversion is structural and incomplete.
- O28. Pi over the interval (Claude reading, NOT ruled). A Pi with the
  domain `I` (`(i : I) → A`) gives `TYPE_MISMATCH` ("found a term of
  type SSet"). The checker builds lines as hints, so S2 does not need
  this form.
- O29. Kan checks that S2 does not port from zkpolicy-lang (Claude
  reading, NOT ruled). A `primTransp` line that is not constant gives
  `TYPE_MISMATCH` (no `TYPE_LINE` code). A pretype (`I`, SSet, Partial)
  as the `primHComp` type gives `TYPE_MISMATCH` (no `TYPE_PRETYPE`
  code). The Pi case of the hcomp type is not ported. A system failure
  gives the zkpolicy-lang text "two cells disagree".
- O30. The type of `a ≡ b` comes from the left side (Claude reading, NOT
  ruled). A pair with no type hint infers the non-dependent `×`. Thus,
  with `p : Σ ℕ (λ n → n ≡ n)`, `(fst p , snd p) ≡ p` gives
  `TYPE_MISMATCH` and `p ≡ (fst p , snd p)` checks (test/fronttool.c).
- O31. No `fold` over an indexed family or a higher inductive family
  (Claude reading, NOT ruled). Each needs a dependent eliminator (S3),
  so S2 gives `DOMAIN_FAMILY`. A `fold` over a CM, or over a family with
  value parameters only, works as in S1. S3 narrows O31: a `fold`
  over a CM with path constructors works (O38). An indexed family
  keeps `DOMAIN_FAMILY`.
- O32. Path constructors (Claude reading, NOT ruled). A path constructor
  is legal only in a CM. In another program family it gives
  `DOMAIN_FAMILY`. The fields of a path constructor are a telescope. S2
  has no `DOMAIN_HIT` code: the path constructor check gives
  `REFUSE_CELL`, with its texts in the docs/DIAGNOSTICS.md row. The
  reduction of a path constructor end has no gate line.
- O33. New keywords (Claude reading, NOT ruled). `let`, `in`, `record`,
  `coinductive` and `module` are keywords, so a program cannot use them
  as names.
- O34. Record limits (Claude reading, NOT ruled). A record head with
  indices gives `PARSE_EXPECT` ("'Type'"). The type-constructor field
  test inspects the checked field types, including definition aliases.
  Field names and parameter names share the `Σ` and `let` binders, so a field
  with the name of a parameter hides it. A type error text can show the
  projection binder `%r`.
- O35. Section limits (Claude reading, NOT ruled). A section holds
  definitions only: a postulate, data, a record or a nested module in a
  section gives `PARSE_EXPECT`. A module name is not a global name, so
  two modules can have the same name. The inner definitions start at
  column 3. `fmt` prints a comment in a module at column 1. The section
  rewrite recurses on application spines, so the C stack limits its
  depth.
- O36. DOMAIN codes and the codes check (Claude reading, NOT ruled).
  Before S2, `DOMAIN_FAMILY` had no row in docs/DIAGNOSTICS.md. The
  test/gate.sh pattern that finds the codes in src (:167) has no DOMAIN
  prefix, so that check does not see a DOMAIN code. S2 adds the
  `DOMAIN_FAMILY` row and test/json/DOMAIN_FAMILY.{lang,json}. A later
  slice can add DOMAIN to the pattern.
- O37. `elim` (D1 of the S3 design; Claude reading, NOT ruled).
  `elim P c₁ .. cₙ x` is the dependent eliminator for the closed kernel
  types ℕ and Bool (O48). The motive P is `D → Type` or `D → Type₁`
  (large elimination). For ℕ, `elim P z s n` with
  `s : (k : ℕ) → P k → P (suc k)`. For Bool, `elim P yes no b` (O49).
  The core drops P. An `elim` over a domain family gives
  `DOMAIN_FAMILY` (test/check/elim-family.lang). An `elim` over another
  type gives `TYPE_MISMATCH`. The non-dependent `fold` stays.
- O38. `fold` over a higher inductive type (D2; Claude reading, NOT
  ruled). A `fold` over a CM with path constructors takes one case for
  each constructor in order, the path cases included (port of
  zkpolicy-lang 1d263fb). A recursive field gives B. A path field
  `x ≡ y` over the family gives `Path B x* y*`. A 1-cell case has the
  type `Path B a* b*`, and a 2-cell case has the type
  `Path (Path B x* y*) p* q*`. Thus the `squash₁` case is `isProp B`
  and a set truncation case is `isSet B`. A `fold` at a 1-cell at an
  interval variable reduces to the case at that variable. The lowering
  drops the path cases. An indexed family keeps `DOMAIN_FAMILY` (O31
  narrowed).
- O39. `rec₁` (D3; Claude reading, NOT ruled). `rec₁` is a guest
  definition in lib/prelude.lang: `rec₁ A B pr f x = fold f pr x`, with
  `pr : isProp B`.
- O40. `foldᴮ` (D4; Claude reading, NOT ruled). `foldᴮ f swap st b xs`
  is a kernel builtin. xs has the type `F A`, where F is a bag: a CM with
  one type parameter and 7 constructors in this order: a point with one
  field of type A, a point with no field, a point with two recursive
  fields, the 1-cells `m e x ≡ x`, `m (m x y) z ≡ m x (m y z)` and
  `m x y ≡ m y x`, and the 2-cell set truncation. B comes from the
  expected type, else from b. `f : A → B → B`;
  `swap : (x : A) → (y : A) → (b : B) → f x (f y b) ≡ f y (f x b)`;
  `st : isSet B` (unfolded); `b : B`. The core drops swap and st. The
  first point `x` reduces to `f x b`, the empty point to `b`, and
  `m x y` to `foldᴮ f swap st (foldᴮ f swap st b y) x`. The unit and
  associativity cells hold by computation. The comm and set truncation
  cells at an interval variable stay stuck: swap and st justify them.
  This answers O1: the generator recursor does not give the cons-form
  fold without a dependent eliminator over the higher inductive type,
  so `foldᴮ` is a kernel rule. A last argument that is not a bag gives
  `TYPE_BAG`.
- O41. Operators (D5; Claude reading, NOT ruled). S3 has a fixed table
  and no general mixfix. The infix operators `∷`, `++`, `∘` and `∙` are
  at one right-associative level between `≡` and `×`. `l OP r` changes
  at parse time to `_OP_ l r`. The notation `∥ t ∥₁` is `∥_∥₁ t`. The
  notation `∃[ x ꞉ A ] B` is `∃ A (λ (x : A) → B)`, and it extends to
  the right, as λ does. `_OP_`, `∥_∥₁`, `∣_∣₁` and `[]` are names. S3
  has no `∣ t ∣₁` notation: a constructor takes its parameters
  (`∣_∣₁ A a`). S3 has no implicit arguments, so the infix use of a
  polymorphic operator works only in a module section, where the
  section gives the type parameters. Outside a section, write
  `_++_ A xs ys`. S3 has no ASCII spellings, so it adds no
  `W_NONCANON` fixture. `+`, `[` and `]` are name characters in S3, so
  test/parse/bad-char.lang changes `natAdd 1 + 2` to `natAdd 1 @ 2`
  (the row still expects `LEX_CHAR`). `fmt` removes the parentheses on
  the right of a right-associative operator (`xs ++ (ys ++ zs)` prints
  `xs ++ ys ++ zs`) and keeps the parentheses on the left.
- O42. Levels (D6; Claude reading, NOT ruled). The Prelude uses the
  fixed level `Type`. Large elimination at `Type₁` occurs only through
  an `elim` motive. S3 adds no level variables (O18 stays).
- O43. The Prelude file (D7; Claude reading, NOT ruled). The S3 design
  put the Prelude in examples/prelude.lang. O47 moves it to
  lib/prelude.lang. The file is standalone: S3 has no imports, and S4
  decides a preload or a copy. examples/paths.lang keeps its own `sym`,
  `cong`, `trans` and `transport`.
- O44. `isSet` for the base types (D8, Q16 (b); Claude reading, NOT
  ruled). The kernel has no constant for `isSet`. lib/prelude.lang
  proves `isSetℕ` and `isSetBool` in the guest. `absurd` uses
  `primTransp` over the large motive
  `elim (λ (b : Bool) → Type) C ℕ`. `eqℕ`, `eqBool`, `reflℕ`,
  `reflBool`, `soundℕ` and `soundBool` use `elim`. `discreteIsSet` is
  Hedberg: the constant map `collapse`, its constancy `collapseConst`,
  then the square of the cubical library by `primHComp`. The structural
  conversion (O27) is sufficient: the square checks. Negative probes
  (scratch copies, not gate lines) give `TYPE_SYSTEM` or `TYPE_REFL`,
  so the check is not vacuous.
- O45. Laws (D9; Claude reading, NOT ruled). The laws are guest paths
  in `module Bag (A : Type)` of examples/bag.lang: the union unit (left
  `munit`, right `mcomm ∙ munit`), associativity (`massoc`),
  commutativity (`mcomm`), the Prelude equation
  `(x ∷ xs) ++ ys ≡ x ∷ xs ++ ys` (`massoc (eta x)`) and
  `[] ++ ys ≡ ys` (`munit`). `_∷_ x xs = m (eta x) xs`. The derived
  `comm` is `sym massoc ∙ (cong (λ z → m z xs) mcomm ∙ massoc)`.
  `check --json` counts no laws in S3 (laws are counted from S4).
- O46. Bag entries in Wasm (D10; Claude reading, NOT ruled). The bag
  differential entries are closed ℕ and Bool functions with a bag of
  static shape (the elements are the parameters): `count3`,
  `countUnion`, `countFlags` and `scale` in examples/bag.lang. The
  evaluator reduces `foldᴮ` on points, so the residual has no bag. A
  `foldᴮ` that stays in a residual gives `REFUSE_RUNTIME_TREE` (host
  limit). S8 decides a run-time bag form.
- O47. The Prelude place (Claude reading, NOT ruled). The Prelude is
  lib/prelude.lang, not examples/prelude.lang (O43). The gate builds
  each examples/*.lang file to Wasm and runs each ℕ and Bool entry
  (test/gate.sh:223). `eqℕ` is such an entry, and its residual holds a
  stuck `elim` that the host cannot lower (O50). lib/ is in the `fmt`
  loop, and the eval rows check it (O51). The json, codes and IR checks
  do not read lib/.
- O48. The scope of `elim` (Claude reading, NOT ruled). ℕ and Bool are
  kernel builtins, not domain families, so `elim` is a rule for these
  two types only. A domain family keeps `fold`. A program cannot
  declare closed data (`REFUSE_DATA`, R2).
- O49. The Bool case order (Claude reading, NOT ruled).
  `elim P yes no b` has the order of `flagIf b yes no`: the case for
  `true` is first.
- O50. `elim` in Wasm (Claude reading, NOT ruled). An `elim` over a
  run-time ℕ in a Wasm entry gives `REFUSE_RUNTIME_TREE` (host limit:
  the host has no loop with a counter yet). A later slice can lower it
  as fold_nat in src/front/lower.c. S3 does not need it (O55).
- O51. Eval rows for lib/ (Claude reading, NOT ruled). An eval row for
  a lib/ file uses the FILE form `../lib/NAME`, because test/gate.sh
  reads `examples/FILE.lang`.
- O52. A `fold` at a 2-cell (Claude reading, NOT ruled). A `fold` at a
  2-cell path constructor stays stuck in S3. `foldᴮ` does not need it.
- O53. The bag test (Claude reading, NOT ruled). `foldᴮ` tests the bag
  shape when it checks (bag_shaped in src/front/check.c), not at the
  data declaration. FamilyInfo has no bag flag (D4 changed).
- O54. The Hedberg name (Claude reading, NOT ruled). The design name
  `discrete→isSet` is `discreteIsSet`, because `→` is a reserved
  symbol.
- O55. The place of the bag entries (Claude reading, NOT ruled).
  examples/bag.lang holds a local copy of the Hedberg chain for ℕ.
  `eqℕ`, `reflℕ`, `soundℕ` and `isSetℕ` are in
  `module NatSet (X : Type) where`, so outside the section each one
  takes a type first, and the differential does not select it as an
  entry. An alias `Cmp A = A → A → Bool` does not help: the entry test
  reads the unfolded Pi, and `langc abi` gives
  `REFUSE_RUNTIME_CLOSURE` on `eqℕ`, because the `elim` motive is a
  function type.
- O56. Law names (Claude reading, NOT ruled). The design law names
  `++-unitˡ`, `++-unitʳ`, `++-assoc` and `++-comm` are `appUnitL`,
  `appUnitR`, `appAssoc` and `appComm`. The Prelude equation is
  `consApp`. A name that starts with `+` or holds `ˡ` was not tried.
- O57. Chains (Claude reading, NOT ruled). `Reach` and `_⊑_` are
  chains of ℕ length, made by a large `elim` on ℕ.
  `Chain : ℕ → State → Type`, `Chain 0 σ = genesis ≡ σ`,
  `Chain (suc k) σ = Σ State (λ τ → Chain k τ × Step τ σ)` and
  `Reach σ = Σ ℕ (λ n → Chain n σ)`. `Desc σ n τ` is the same with
  `σ ≡ τ` and `Authorized`, and `_⊑_ σ τ = Σ ℕ (λ n → Desc σ n τ)`.
  The constructors are definitions: `root = 0 , refl`,
  `_▸_ σ σ' h s = suc (fst h) , σ , snd h , s`, `here` and `_⊳_`.
  Reason: a `Reach` data type over the telescope has the type
  parameter `State` and value parameters (`REFUSE_CELL`, rule R1); a
  `fold` over an indexed family gives `DOMAIN_FAMILY` (O31); a section
  holds no data (O35). A chain of length n is a rooted path of n
  steps, so the meaning is the same. The laws by recursion use `elim`
  on the length. S4 adds no eliminator, and O31 stays open.
- O58. Two parameter sections (Claude reading, NOT ruled).
  `module Design` has the 22 telescope params (secs 2 to 4).
  `module Authority` has the 22 params and `Honest`, `Endorses`,
  `honest-meet`, `faithful` and `single` (secs 5 and 6). A section
  holds no section (O35), so `Authority` repeats the 22 params and
  calls the `Design` definitions with the 22 arguments. `Authority`
  starts with short local names (`StepA`, `ReachA`, `LegitA`, `rootA`,
  `snocA`, `legit-coreA`), so each long application occurs one time.
  The type of `faithful` writes the `Step` application in full.
- O59. Top-level records (Claude reading, NOT ruled). `Step` and
  `Replica` are top-level records with only the params that their
  fields use (a section holds no record, O35). `record Step` has 9
  params (`State`, `Agenda`, `Ballot`, `Edit`, `rules`, `apply`,
  `Core`, `σ`, `σ'`) and the 6 fields of Q2 (`agenda`, `bag`, `edit`,
  `chosen`, `lands`, `keeps`). A projection takes the record params
  first, then the value. `record Replica (State : Type)
  (genesis : State) (Le : State → State → Type) : Type₁` has `Rep`,
  `none`, `merge`, the meaning map `denote` and its 4 laws. `Design`
  defines `StepD σ σ'` and `step` (the tuple). `Authority` defines
  `ReplicaA`. A later slice can let a `module` hold a record.
- O60. Prelude copy (Claude reading, NOT ruled). The design file
  copies the Prelude definitions that it uses (`sym`, `cong`, `_∙_`,
  `isProp`, `isSet`, `∥_∥₁`, `rec₁`, `∃`, `absurd` and the Hedberg
  chain) and `FMSet` from examples/bag.lang. O43 stays: S4 adds no
  preload and no import form. `squash A : isProp ∥ A ∥₁` is an eta
  wrapper for `squash₁ A`, so no constructor is applied to its type
  parameter only. `eqℕ`, `reflℕ`, `soundℕ` and `isSetℕ` are in
  `module NatSet (X : Type)`, as in examples/bag.lang (O55). Reason: a
  top-level `eqℕ : ℕ → ℕ → Bool` is a Wasm entry, and the `ir` and
  `wasm` gate lines gave `REFUSE_RUNTIME_CLOSURE` on it.
- O61. File (Claude reading, NOT ruled). examples/threshold.lang holds
  secs 1 to 6 and then the toy instance. The gate loop over each
  committed `.lang` file checks it and does its `fmt` round trip.
- O62. Names (Claude reading, NOT ruled). `→` is reserved (O54) and
  `-` is a name character. The 7 laws are `reach-core`, `legit-core`,
  `honest-in`, `sound`, `no-fork`, `certified-legit` and
  `certified-core`. `⟦` gives `NAME_UNKNOWN`, so the slot `⟦_⟧ᵉ` is
  `apply` and the `Replica` fields are `denote`, `denote-none`,
  `denote-mergeˡ`, `denote-mergeʳ` and `denote-mergeᵘ`. These names
  show that a name can hold `ˡ` (O56).
- O63. Explicit arguments (Claude reading, NOT ruled). There are no
  implicit arguments (O41): each `{σ σ'}`, `{c}`, `{i}` and `{A B}` is
  explicit. `∃[ i ꞉ M ] B` is `∃ M (λ i → B)`. A pattern λ is a bare
  λ with `fst` and `snd`. A bare `λ x →` occurs only under `Σ`; each
  other binder has a type.
- O64. Laws (Claude reading, NOT ruled). The keyword `law` comes
  before a signature, at the top level or in a section:
  `law reach-core : (σ : State) → Reach σ → Core σ`. In
  `check --json`, `total` is the number of parsed law signatures and
  `discharged` is the number of laws whose definition checks (R2
  refuses postulates, so a law that checks has a proof).
  `langc laws PROG` prints one line `law NAME discharged` (or `open`)
  for each law in source order, then `laws: D of T discharged`. It
  exits 0 only when the file checks and D = T, and 1 otherwise.
  src/main.c counts the laws (`count_laws`, `print_laws`), so check.c
  has no change. There is no new diagnostic code: a `law` at an
  incorrect position gives `PARSE_EXPECT`, and the text of that
  diagnostic at the start of a declaration names `law`.
  test/fmt/law.lang and test/json/laws.lang are the fixtures.
- O65. Toy instance (Claude reading, NOT ruled). The closed toy
  instance in examples/threshold.lang has Artifact, Ballot, Agenda,
  Edit, Member and Committee = `Bool` or `ℕ`; `Quorum c = Bool`;
  `_∈_ c i q = i ≡ i`; `Circuit A B = A → B`; `run A B f = f`;
  `constitution σ a = λ b → just true`; `State = ℕ`;
  `height = λ n → n`; `apply e σ = suc σ`; `genesis = 0`;
  `Core σ = 0 ≡ 0`. The obligations are `isSetState = isSetℕ ℕ`,
  `advance = refl`, `isPropCore = isSetℕ ℕ 0 0` and `core₀ = refl`.
  Two S4 changes from the first plan: `constitution` gives `just true`
  (not `nothing`), so a real step exists, and `toyOne` proves
  `toyCore 1` by `reach-core` on a chain of one step; `_∈_` is
  `i ≡ i` (not `i ≡ q`), so each member is in each quorum and two
  quorums meet (`toyHonestMeet`). The toy also gives `toyHonest`,
  `toyEndorses` (`suc σ ≡ τ`), `toyFaithful` and `toySingle`, and
  `toyCertifiedCore` applies `certified-core` to the 27 toy
  arguments.
- O66. Tip order proof (Claude reading, NOT ruled). For two tips t
  and u, `tip-order` gives `∥ Ordered (fst t) (fst u) ∥₁`, with
  `Ordered σ τ = Σ Bool (λ b → elim (λ (x : Bool) → Type) (_⊑_ τ σ)
  (_⊑_ σ τ) b)` (`Sum` gives `REFUSE_BASE`, O7; the Bool `elim` takes
  the `true` case first). The helpers are `auth-from`, `desc-cons`,
  `desc-uncons`, `ord-jump`, `ord-back`, `ord-step` and `desc-ord`. In
  `ord-jump`, `no-fork` makes the first step of the longer chain equal
  to the new tip. `desc-ord` is by induction on the length of one tip
  chain and gives the untruncated `Σ`, and `tip-order` is `∣_∣₁` of
  it. The first plan (a height lemma from `sound`, `lands` and
  `advance`, then a prefix by length) was not necessary: the proof has
  no ℕ arithmetic. `tip-order` is not a law, so the laws stay 7 of 7.
  O3 has the result.
- O67. Quorum index mutant (Claude reading, NOT ruled). S4 mutant 2
  is a guest edit in examples/threshold.lang: `Authorized σ τ` takes
  its quorum at the fixed committee of `genesis` (`Quorum (committee
  genesis)`), and `Cert σ τ q` keeps `Quorum (committee σ)`. `langc
  check` refuses `Authorized` with `TYPE_MISMATCH` (`Quorum (committee
  σ)` against `Quorum (committee genesis)`), so the examples loop and
  the laws line fail (`laws: 2 of 7`). The reason for the guest edit:
  two gate lines that exist kill it, with no new fixture, so the
  refusal counts stay 43 check and 9 parse. The kill comes from the
  checker: it compares the index of the family `Quorum`. A checker
  that ignored the index would let the edit check.
- O68. Codes (Claude reading, NOT ruled). `data Code : Type` is in
  domain/domain.lang. It is closed and first order, with no arrow code:
  `bitC`, `natC`, `optC (optOf : Code)`, `pairC (pairL pairR : Code)`
  and `bagC (bagOf : Code)`. lib/prelude.lang renames its `Code` and
  `code0` to `BoolCode` and `boolCode0`. `El : Code → Type` is a guest
  `fold` into `Type` (Bool, ℕ, Maybe, `×`, FMSet). Each file that needs
  it has a copy (O60).
- O69. Circuit fragment (Claude reading, NOT ruled). `data Circuit :
  Code → Code → Type` is a guest program family (FAMILY_INDEXED) in
  examples/circuit.lang. The constructors are first order and use folds
  only. The set is small: `idC`, `seqC`, `fanC`, `zeroC`, `sucC`, `addC`,
  `leC`, `guardC` and `countC`, the constructors that the fixtures use.
  `countC p` counts the elements of a bag that satisfy `p`. Its swap
  proof is by Bool `elim` cases.
- O70. Index recursor (Claude reading, NOT ruled). The kernel name
  `foldᴵ` (RULE_FOLDI): `foldᴵ P c₁ .. cₙ x` over an indexed family with
  no value params, with exactly n + 2 arguments. `P` is a motive over
  the indices only, not over `x`. The case for a constructor takes its
  fields in order, with each recursive field replaced by `P` at the
  indices of that field, and gives `P` at the result indices of the
  constructor. `fold` and `elim` over an indexed family keep
  DOMAIN_FAMILY (O31). A later constructor field type or result index
  that depends on a recursive field's original value also gives
  DOMAIN_FAMILY: replacing that value by its fold result would change
  the meaning of the dependent type. The check normalizes the types
  first, so unused arguments do not create a dependency. `run a b c`
  is a `foldᴵ` with the motive `λ (x :
  Code) (y : Code) → El x → El y`. O70a: `foldᴵ` has no new core op. It
  elaborates to OP_FOLD_FAMILY and drops the motive, so the iota, the
  stuck form, quote, print and lower.c serve `foldᴵ` as they serve
  `fold`. A stuck `foldᴵ` prints as `fold`. A Wasm entry takes ℕ or Bool
  params only, so it cannot hold a neutral circuit, and lower.c needs no
  new refusal.
- O71. First order check (Claude reading, NOT ruled). In check_family,
  a FAMILY_INDEXED declaration whose index types are all `Code` is a
  circuit family. Each constructor field type must be `Code`, ℕ, Bool or
  the family itself, else the new code REFUSE_CIRCUIT. Fixtures:
  test/check/circuit-ho.lang (a field `(mf : ℕ → ℕ)`) and
  test/json/REFUSE_CIRCUIT.lang. S5 mutant 1 turns the check off.
- O72. Seal (Claude reading, NOT ruled). The new keyword `sealed` is
  domain-only: a `sealed` declaration in a program gives REFUSE_DATA
  (test/check/seal-data.lang). domain/domain.lang declares `sealed data
  Hidden (A : Type) : Type` with `seal : (sealOf : A) → Hidden A`, and
  `law unseal : (A : Type) → Hidden A → A`. `langc laws` does not count
  domain laws. A sealed family must be a cell monad with one generator,
  else REFUSE_CELL. The rule applies to bodies only: a body opens the
  seal when it has a `fold` over a sealed family into a type that is
  not a sealed family, or a reference to a law-only global. A law-only
  global opens the seal and has a type that does not end in a Path or a
  universe. A declaration that opens the seal, is not a `law` and has a
  type that does not end in a Path or a universe gives the new code
  REFUSE_LAW. So bind and map inside `Hidden` do not open the seal.
  Fixtures (REFUSE_LAW): test/check/seal-fold.lang, seal-unseal.lang,
  seal-relay.lang and test/json/REFUSE_LAW.lang. S5 mutant 2 turns the
  refusal off. O72a: (1) A projection (`sealOf`) of a sealed family also
  opens the seal. (2) A law in a section keeps its `law` mark, so it can
  open the seal. (3) The REFUSE_CELL of a sealed family points at the
  start of the declaration. It has no fixture.
  The S5 review also checks the quoted endpoints inserted by Path
  application. A proof's declared type can contain an unseal even when
  its body is `refl` or a record projection. Extracting an unsealed
  endpoint opens the seal and gets REFUSE_LAW in an ordinary definition.
  Eliminations into a sealed family retain a sealed-result annotation
  through evaluation and quotation, so resealing remains available even
  inside an endpoint passed to another function.
- O73. Laws file (Claude reading, NOT ruled). examples/threshold.lang
  holds the 12 design laws: the 7 S4 laws, `app-cons` (the `_++_`
  equation, as `consApp` in examples/bag.lang), `tallyᴹ-correct`,
  `tallyᶠ-correct`, `mpc≼fhe` and `ivc-prove`. Each design name lexes,
  so the file uses the design names. The gate laws line and the json
  line change from 7 of 7 to 12 of 12.
- O74. Secs 7 to 10 shape (Claude reading, NOT ruled). `Private` is a
  top-level record (O59) over the params that it uses. Its types use
  the domain `Hidden` and `unseal` (sec 2.4: a field cannot range over
  `U -> U`). `Round` and `Aggregate` are modules (O8), and `factors` is
  a param of `Aggregate`. `ZK`, `IVC` and `Sharing` are top-level
  records. `ivc-prove` is by ℕ `elim` on the chain length (O57). O74a:
  (1) `Round` takes only the 11 params that it uses (the last is `P`,
  O59 style), not the 22 params of `Design`. It has its own `rulesR`
  (the body of `Design.rules`). Modules do not nest, so `Aggregate` is a
  top-level module after `Round`, with the same 11 params first. (2) The
  record `IVC` is before `module Design`, and `ivc-prove` is in `Design`,
  so no new module takes the 22 params. (3) The target of S5 mutant 3 is
  the `Aggregate` param `factors` (O77).
- O75. Denotational instances (Claude reading, NOT ruled).
  examples/denote.lang (new) has an O60 copy of the records that it needs
  and the instances: `Private` over the domain seal (`law den-private`,
  because `reveal = unseal` opens the seal), `ZK` (`Proof x = ∥ W x ∥₁`,
  `verify` gives `true`), `IVC` (`Proof = LegitM`, over a free `Move`),
  `Sharing` (`Shares c = S`, `reshare = id`) and an `Aggregate` instance
  (`denAgg` is a `run` of `tally`, with `denDecide` and `denFactors`).
  The gate has its own laws line for the file: `laws: 1 of 1
  discharged`. O75a: `elim` takes 4 arguments, for ℕ and Bool only. So
  no `elim` over `Hidden`, and a fold of a free `Hidden` value does not
  reduce. In the instance, `⊕` and `eval` open the seal and seal the
  result again inside `den-private`, so `⟦⊕⟧` and `⟦eval⟧` are `refl`.
  `cast` and `∅` do not open the seal. No kernel edit.
- O76. `run` against direct evaluation (Claude reading, NOT ruled).
  examples/circuit.lang has ℕ and Bool wrappers over closed circuits,
  each with a direct guest definition: `majRun a b c` (the majority
  circuit on a bag of 3 ballots, 1 for `just` and 0 for `nothing`) and
  `majDirect a b c`, `countRun`, `addRun`, and `agree a b c`, which
  compares `majRun` and `majDirect`. test/eval/expect.txt has a row for
  each, and `agree` gives 1 on each row. The Wasm loop covers the file
  by the glob, with 0 mismatches.
- O77. S5 mutants (Claude reading, NOT ruled). Mutant 1 turns the O71
  check off (the REFUSE_CIRCUIT condition in check_family never holds).
  Mutant 2 turns the O72 refusal off (the REFUSE_LAW condition never
  holds). They are src edits, and the fixtures kill them. Mutant 3 is a
  guest edit in examples/threshold.lang: the right side of the `factors`
  param type becomes its left side, so `factors` is not checked (O74a
  (3)). Then `tallyᶠ-correct` fails with TYPE_MISMATCH, `mpc≼fhe` stays
  open, and `check --json` gives 10 of 12 laws. The examples loop and
  the laws line kill it. The three mutants: 3 of 3 KILLED
  (W/mut-s5.py).
- O78. Port set and layout (Claude reading, NOT ruled). New directory
  src/crypto (the code is not front end). Files: keccak.{c,h} (as is),
  u256.{c,h} (cut word_text and the WORD_* enum), bn254.{c,h} (as is;
  ec0_* stay, g1_* wrap them; add `scalar_reduce` = blsag_reduce with
  its modulus words), elgamal.{c,h} (drop elg_scale: Q7 (a) has unit
  weight), threshold.{c,h} (drop thr_deal; keep thr_hash, thr_challenge,
  thr_nonce, thr_partial, thr_verify, thr_lagrange, thr_open),
  sigma.{c,h} (as is). Include paths change from "front/X.h" to
  "crypto/X.h"; blsag.h and the blsag_* calls change to bn254.h and
  scalar_reduce. Each file gets a one-line head comment with its source
  (`intent-lang 79e1898 src/front/X.c`). langc does NOT link src/crypto
  in S6 (Q9 (a): the host-import ABI is S8).
- O79. Pedersen DKG (Claude reading, NOT ruled). New C
  (src/crypto/dkg.{c,h}): the FROST paper Figure 1 over BN254 G1, t of n
  with n <= THR_N_MAX. Dealer i: coefficients a_{i,k} =
  thr_nonce(seed_i, k) for k < t; Feldman commitments C_{i,k} = a_{i,k}
  G; Schnorr proof of knowledge of a_{i,0}: nonce w = thr_nonce(seed_i,
  t), R = w G, c = H chain (DKG_TAG, ctx, i, C_{i,0}, R), z = w + c
  a_{i,0} mod r; share f_i(j) by Horner (the threshold.c:83-87 loop).
  Checks: proof zG = R + c C_{i,0}; share f_i(j) G = sum over k of j^k
  C_{i,k}. QUAL = the dealers with a valid proof and a valid share for
  each member (a complaint against one share removes the dealer for all
  members, so QUAL is the same at each member). sk_j = sum over QUAL of
  f_i(j); PK_j = sk_j G; PK = sum over QUAL of C_{i,0}. The output is
  ThrShare rows, so thr_partial and thr_open take DKG shares. DkgResult:
  DKG_OK, DKG_BAD_SHARE, DKG_BAD_PROOF, DKG_BAD_INDEX, DKG_TOO_FEW (QUAL
  smaller than t).
- O80. Host form of the representation map (Claude reading, NOT ruled).
  Kit entries, not a langc verb. A C tool test/tallytool.c
  (build/tallytool, linked with src/crypto only) has two modes. No
  argument: the C fixture rows (O82 to O84), `tally regressions:
  passed`. `rep`: one DKG (t 2, n 3), then for each case of O81 it casts
  each ballot (k = 2 slots, Enc(1) at the slot of b, Enc(0) at the
  other), adds the ballots slot by slot (`tally_add`, new, in
  src/crypto/elgamal.c), reveals each slot by thr_open over the quorum
  {1, 2}, and prints the eval line `denote NAME J B1 .. Bm => COUNT`.
  The gate runs the O87 loop over these lines with `langc eval`. So the
  kit value of cast, ⊕ and reveal meets the guest denotation line by
  line.
- O81. Guest side and N (Claude reading, NOT ruled).
  examples/denote.lang gets entries over the denotation of den-private
  (the right sides of ⟦cast⟧ and ⟦⊕⟧: a cast is `_∷_ Bool b ([] Bool)`,
  ⊕ is `_++_ Bool`): `denCount1 j b1`, `denCount2 j b1 b2`, `denCount3 j
  b1 b2 b3`, each the count of the choice j in the union of the cast
  bags (a count with a Bool test per element, a copy of bag.lang `count`
  with `elim` on the element, the O60 copy rule). The entries do not
  unseal (no REFUSE_LAW). N = 14 cases: each ballot list over Bool of
  length 1 to 3 (2 + 4 + 8), each with the 2 slots, so 28 count lines.
  Reading: the 14 cases need about 530 G1 multiplications at the
  measured speed, under 60 s. Result: the 3 entries check, the file
  stays canonical under `fmt`, and the gate gives 14 cases, 28 counts, 0
  mismatches.
- O82. Known-answer vectors (Claude reading, NOT ruled). C rows in
  tallytool, hex constants in the C file, each with its source in a
  comment: (1) keccak256("") =
  c5d2460186f7233c927e7db2dcc703c0e500b653ca82273b7bfad8045d85a470 and
  keccak256("abc") (Ethereum Keccak, not SHA3; H2a confirmed each row
  against a second source: `cast keccak` and a Python big-integer check,
  W/s6-kat-check.py); (2) G on the curve, 2G = intent-lang
  test/eval/expect.txt:53 (decimal), cross-checked with
  precompile.sh:51-52; (3) r G = the point at infinity and (r - 1) G =
  (1, p - 2) (exact by the group order); (4) C1 = elg_nonce(1) G =
  precompile.sh:110-111 (port fidelity of keccak, scalar_reduce and
  g1_mul).
- O83. Invalid-proof fixtures (Claude reading, NOT ruled). C rows, each
  refused with its code: (1) a slot with plaintext 2 and a simulated OR
  proof (SIG_BAD_SLOT); (2) a two-hot ballot, each OR proof valid
  (SIG_BAD_SUM); (3) an all-zero ballot (SIG_BAD_SUM); (4) a forged
  split e0 + e1 != e (SIG_BAD_SLOT); (5) a slot proof moved to another
  slot index j (SIG_BAD_SLOT); (6) a valid ballot checked under another
  ctx (the port gives SIG_BAD_SLOT); (7) a partial decryption with D + G
  (THR_BAD_PROOF); (8) a partial with z + 1 (THR_BAD_PROOF); (9) an
  off-curve C1 (THR_REFUSED). Plus the good rows: one-hot k 2 and k 4
  verify, open = the count.
- O84. DKG fixtures (Claude reading, NOT ruled). C rows: (1) good
  dealing: n 3, t 2, each dealing verifies, PK = sum of C_{i,0}, PK_j =
  sum over k of j^k C_{i,k} summed over QUAL, and a cast then threshold
  open over {1, 2}, {1, 3} and {2, 3} gives the plaintext (DKG_OK); (2)
  bad share: dealer 2 gives member 3 the share f_2(3) + 1, the check
  gives DKG_BAD_SHARE and QUAL = {1, 3}; the key of QUAL still decrypts;
  (3) bad proof of knowledge: dealer 1 with z + 1 gives DKG_BAD_PROOF,
  QUAL = {2, 3}. Plus DKG_BAD_INDEX rows for member 0 and member n + 1,
  and DKG_TOO_FEW when QUAL is empty (each dealing bad). A QUAL of one
  dealer is still a t of n sharing (a sum of degree t - 1 polynomials),
  so DKG_TOO_FEW is for an empty QUAL only.
- O85. S6 mutants (Claude reading, NOT ruled). W/mut-s6.py is a copy of
  W/mut-s5.py with the MUTANTS table and the killers changed (scratch
  copy, restore, cmp; `make -B`). (1) one slot of ⊕ skipped: the
  `tally_add` loop bound `j < k` becomes `j + 1u < k`; killer: the O87
  rep loop (the slot 1 counts differ) and the tallytool open rows. (2)
  DLEQ check skipped: the thr_open refusal condition becomes `if (0 &&
  !thr_verify(...))`; killer: O83 rows 7 and 8. (3) Lagrange sign
  flipped: `fe_sub(&den, &xj, &xi, ...)` becomes `fe_sub(&den, &xi, &xj,
  ...)`; killer: the rep loop and the open rows (M is wrong, so BSGS
  gives NOT_FOUND). Result: 3 of 3 KILLED (W/S6-mutants.log). Mutant 1:
  10 of the 28 rep lines differ and the row `tally k 2 slot 1` fails.
  Mutant 2: the rows `part D + G` and `part z + 1` fail. Mutant 3: each
  of the 28 rep lines gives `open-1` (THR_NOT_FOUND) and 8 open rows
  fail.
- O86. Speed (Claude reading, NOT ruled). Port bn254 as is first (KATs
  pin it). If `build/tallytool` (both modes) takes more than 120 s, add
  Jacobian coordinates inside g1_mul only (no inverse per add, one
  inverse at the end), keep the affine API, and the KAT rows check it.
  Each long run stays under 4 GB (BSGS at 8 bits). Result: `rep` 31.80 s
  and the rows 20.93 s, 52.7 s for both, so no Jacobian change.
- O87. Gate lines (Claude reading, NOT ruled). test/gate.sh, after the
  evals loop: `build/tallytool rep > "$tmp/rep"`, then the evals loop
  body over "$tmp/rep" (same compare), and the line `tally: 14 cases, 28
  counts, 0 mismatches`. Makefile: CRYPTO = src/crypto/*.c (an explicit
  list), TALLY_TOOL = test/tallytool.c $(CRYPTO); build/tallytool in
  `build`; check runs build/tallytool after build/fronttool; check-clang
  adds TALLY_TOOL; HEADERS adds src/crypto/*.h. The Wasm differential
  covers the new denote.lang entries by its glob (5246 to 5274 cases).
  New eval rows in test/eval/expect.txt: one row for each denCount entry
  (evals 72 to 75).
- O88. Docs (Claude reading, NOT ruled). H4, one exact-count Python
  script (W/s6-h4-docs.py; W/s5-h4-docs.py is the model): PLAN sec 4.2
  "S6 status" (port set, DKG, tally route), sec 8 note (thr_deal not
  ported; DKG new C), sec 10 O78 to O89, sec 9 S6 row at Close; STATUS
  (S6 line, known limits: crypto not in langc until S8, not constant
  time, BSGS bound); README.md lists the build files, so it gets
  src/crypto/ and test/tallytool.c. AGENTS.md does not list them. No new
  langc code, so no DIAGNOSTICS row.
- O89. S5 baseline (Claude reading, NOT ruled). The S5 baseline counts
  are the USER commit counts (54 check refusals, 29 JSON fixtures). H2a
  STEP 0 ran the serial gate once (W/S6-step0-gate.log) and recorded the
  exact lines before any edit.

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
- Q7. Ballot. RULED (a) 2026-10-26 (S5 close; USER answer verbatim: "(a) Unit weight
  (Recommended)"). (a) One of k choices with unit weight. (b) Public weights.
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
- Q16. `isSet ℕ` and `isSet Bool` (S3). RULED (b) 2026-10-26. (b) A
  guest proof: a dependent eliminator `elim` for ℕ and Bool in the
  kernel, and discreteness and Hedberg as guest laws in the Prelude.
