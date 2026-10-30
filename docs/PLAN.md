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
| Q14 | (a) | Honest-majority BGW over the committee's Shamir shares. Ruled 2026-10-28 at S10 (sec 5, O135 to O143, S10). |
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

S7 status (Claude reading, NOT ruled; O90 to O95, O98 to O102).
src/crypto adds sha256.c (a port of cairn-lang 6748510 src/sha256.c),
xmd.c (expand_message_xmd and hash_to_field, RFC 9380, new C),
secp256k1.c (the curve on the bn254.h field and point code; the
constants come from intent-lang 79e1898) and frost.c (RFC 9591, new C).
langc does not link src/crypto: the host import ABI comes in S8 (Q9
(a)). Thus the RFC 9591 vectors are C rows, not guest tests. The C tool
test/frosttool.c (build/frosttool) has the SHA-256 rows (FIPS 180-4),
the xmd rows (RFC 9380 App. K.1), the secp256k1 rows and the RFC 9591
App. E.5 rows, byte-equal (`frost regressions: passed`). Its `rep` mode
is the representation map of `Authorized` (O98): one secp256k1 DKG (t 2,
n 3), a FROST signature by each of the 8 signer sets, and one eval line
`denote denAuth3 B1 B2 B3 => V` for each set (V is 1 when the aggregate
verifies). Then the same for the 16 signer sets of the reshared
committee (t' 3, n' 4) on denAuth4. The gate gives each line to `langc
eval` on examples/denote.lang: 24 cases, 0 mismatches.

### 4.4 Resharing (`Sharing`)

- `Secret` = the group signing key and the ElGamal key. `Shares c` = the
  share vector of committee c.
- `reshare q c'`: each member i of q deals a sub-sharing of λ_i s_i to
  c' with the dealing of the DKG (Feldman commitments and a Schnorr proof
  of knowledge, Q8 (b)). Each new member adds its sub-shares. The group public key does not
  change, so clients keep the key that they pin.
- Exact: `⟦reshare⟧` (Lagrange). Assumed: honest dealing. Feldman
  commitments make each dealing checkable.

S7 status (Claude reading, NOT ruled; O96, O97). One DKG serves both
curves: dkg.c takes a curve descriptor (`DKG_BN254` keeps the S6 keccak
challenge, `DKG_SECP256K1` uses xmd_to_scalar), and the S6 DKG rows pass
unchanged. The secp256k1 DKG rows are the five S6 fixtures (good
dealing: QUAL {1, 2, 3}; bad share: DKG_BAD_SHARE, QUAL {1, 3}; bad
proof of knowledge: DKG_BAD_PROOF, QUAL {2, 3}; DKG_BAD_INDEX;
DKG_TOO_FEW) and FROST by {1, 2} and by {2, 3} under the DKG key. In the
reshare (new C, `dkg_reshare_deal`), member i of the signing quorum Q
deals g_i with g_i(0) = λ_{i,Q} s_i. The new check C'_{i,0} = λ_{i,Q}
PK_i refuses a bad dealing with DKG_BAD_RESHARE. The rows reshare the (t
2, n 3) key over Q = {1, 3} to (t' 3, n' 4). The new group key is the
old key. The old {1, 2} and the new {2, 3, 4} sign under it. The new
shares {1, 2, 3} interpolate to the old secret. The new {1, 2} gives a
signature that does not verify. A dealing without λ gives
DKG_BAD_RESHARE. The BN254 reshare row (O97) is in build/tallytool:
Q = {1, 3} of the S6 good dealing reshares the ElGamal key to (t' 3,
n' 4), and the new {2, 3, 4} open an S6 cast under the old PK.

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
- MPC route (arithmetic model since S10, Q6 (b), Q14 (a)): BGW
  over degree-1 Shamir shares in Fr of BN254 (n = 3 members, 1 corrupt
  member at most). Each ballot is a Feldman dealing of its bit, with
  the commitments in G1. The members check each share, add the shares,
  and do the bit check and the compare with the public threshold k by
  BGW multiplication with degree reduction. Each local product has a
  Chaum-Pedersen proof (Q-S10-4 (b)). The tally entry returns only the
  decision bit; bit checks also open `b (b - 1)` zero-test results
  (O135 to O140). The replica calls the host imports
  `q_mpc_check`, `q_mpc_add`, `q_mpc_mul`, `q_mpc_mulc`, `q_mpc_affine`
  and `q_mpc_open`. `langc eval` (src/front/eval.c) and the C host
  test/replicatool.c do the field and group work with
  src/crypto/bgw.c. The new replica entries are `mpc_tally`,
  `mpc_route` and `tally_decide`. Law: `tallyᴹ-correct`. The gate gives
  `replica mpc: 38 cases (15 by langc eval), 0 mismatches` (`tallyᴹ`)
  and `replica decide: 34 cases, 0 mismatches` (`tallyᶠ` on the same
  ballots): `tallyᴹ` = `tallyᶠ` on each fixture.
- S10 security scope: this is a BGW arithmetic transcript validation
  model, not a private MPC deployment. Each Feldman constant commitment
  is `C[0] = b G`: a bit is public by comparison with the identity point
  and generator. Summing those commitments also reveals the small tally
  by enumeration. In addition, the host receives every committee share
  in the transcript and can reconstruct inputs and intermediates.
  Opening only the outcome refers to the return value, not secrecy of
  the transcript. The fixture comparisons establish functional agreement
  only. Ballot privacy requires hiding commitments with compatible
  proofs and separate member execution over private authenticated
  channels. S10 does not implement those requirements; the private
  ballot route remains threshold ElGamal (S6).
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

S8 status (Claude reading, NOT ruled; O104 to O108, O110, O112 to O114,
O116). replica/replica.lang is the replica program. `langc build` writes
build/replica.wasm, wasm2c translates it, and TCC compiles the
translation into the C host test/replicatool.c (build/replicatool). The
host imports of module "q" call the src/crypto code (Q9 (a), O105), and
`langc eval` calls the same C functions. The exports are `cert_verify`,
`rep_tip`, `rep_merge`, `merge_tip`, `step_apply`, `ballot_verify`,
`tally_sum`, `partial_verify`, `combine` and `amend_accept`. `tally_sum`
has the place of `tally_add`, and `merge_tip` gives the tip of a merge.
A run-time input is an entry parameter of a list type below `heap_base`
(O109 (i), the USER ruling). A certificate is the FROST signature of the
chain digest h_n, and h_n covers the parent, the step body and the index
(O107). `rep_merge` gives REP_FORK when the two chains have different
digests at the length of the shorter chain (O108). The gate gives each
line of test/replica/history.txt (25 lines) and test/replica/tally.txt
(19 lines) to `langc eval` and to build/replicatool: 0 mismatches. The
scripted history has 4 certified steps (tip 4), and the merge rows give
tip 4. The refuse fixtures give REP_BAD_SIG, REP_BAD_LINK, REP_FORK,
BALLOT_BAD and PARTIAL_BAD. The FHE route gives the S6 tally counts (14
cases).

S8 readings. The USER ruled O109 (i), R-C1 to R-C14, R-E1 (split), R-E5
(one slot for each ballot), R-E18 (the `Core` check is the threshold
template with k at least 1) and R-E37 (a) (accept the time of the tally
rows). The S8 session readings D1 to D9, R-A1 to R-A9, R-B1 to R-B8,
R-C15 to R-C20, R-D1 to R-D9, R-E2 to R-E4, R-E6 to R-E17, R-E19 to
R-E36 and R-E38 to R-E51 are Claude readings, NOT ruled.
W/S8-PROGRESS.md and W/S8-H5-SITEMAP.md record each one.

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

S8 status (Claude reading, NOT ruled; O111 under Q10 (a), with the USER
ruling R-E18). `amend_accept` takes the new constitution as a run-time
list of opcode words in postfix form. It runs the three checks in the
order 1, 2, 3. Check 1 walks the words with a stack of code pairs, at
most 4 deep: a term that does not type check gives AMEND_ILL_TYPED (4).
Check 2 wants the entrenched `agg` opcodes first and `seqC` last, else
AMEND_NOT_FHE (5). Check 3 is `Core`: the threshold template with k at
least 1 (R-E18), else AMEND_CORE (6). It gives 0 on accept.
test/replica/amend.txt has 4 rows (ill 4, notfhe 5, corebrk 6, accept
0). `langc eval` and `build/replicatool amend` give the same code on
each row (`replica accept: 1 of 1`).

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

S9 readings. The USER ruled Q-S9-1 to Q-S9-6 (a). The S9 session
readings (the R-H2 to R-H6 items and O117 to O134) are Claude readings,
NOT ruled. W/S9-PROGRESS.md records each one. A13 (R-H6-2): in each task
of docs/TOKEN-BASELINE.md, the quorum-lang file costs more tokens than
the Python and the Rust samples (T1 527 / 505 / 253 / 367, T2 435 / 419
/ 327 / 413, T3 688 / 649 / 274 / 339; quorum-lang / ASCII / Python /
Rust). The cause is the helpers by `elim` (no imports) and the proof
terms. A13 measures the cost; it does not promise a lower cost. The
samples stay as they are.

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

S7 note: src/crypto/sha256.c ports cairn-lang 6748510 src/sha256.c
(sha256_words cut). The secp256k1 constants and the parity lift_x come
from intent-lang 79e1898 src/front/secp256k1.c (secp_recover and keccak
cut), on the bn254.h field and point code. xmd.c, frost.c, the SEC1
encodings and the reshare in dkg.c are new C (O90). The S7 survey found
SHA-256 in C in cairn-lang, so the NEW line above and the sec 4.3 text
"No *-lang repo has SHA-256 in C" are out of date.

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
| S7 | SHA-256 (FIPS 180-4), expand_message_xmd (RFC 9380), secp256k1 point operations, FROST key generation by Pedersen DKG (Q8 (b)), commit, sign, aggregate, verify (RFC 9591), reshare | GREEN: FIPS 180-4, RFC 9380 App. K.1 and RFC 9591 App. E.5 vectors byte-equal (signing); the secp256k1 rows pass; each DKG fixture gives its result on secp256k1 (good dealing: QUAL {1, 2, 3}; bad share: DKG_BAD_SHARE, QUAL {1, 3}; bad proof of knowledge: DKG_BAD_PROOF, QUAL {2, 3}; DKG_BAD_INDEX; DKG_TOO_FEW) and the DKG key signs; old and new committees sign under one group key after reshare (Q = {1, 3}, (t 2, n 3) to (t' 3, n' 4); a dealing without λ gives DKG_BAD_RESHARE); `frost regressions: passed`; `build/frosttool rep` against `langc eval` on denAuth3 and denAuth4: `auth: 24 cases, 0 mismatches`; make check EXIT 0, gate: 0 failures (serial log); fmt: 103 files canonical; json: 29 fixtures; diagnostics: 36 codes, 0 without a fixture or a row; refusals: 54 check, 9 parse; evals: 77; tally: 14 cases, 28 counts, 0 mismatches; laws: 12 of 12 (examples/threshold.lang) and 1 of 1 (examples/denote.lang); ir: 19 lowered; differential: 5318 cases, 0 mismatches; wasm: 22 modules valid | 3: binding factor dropped (`frost_group_commitment` R_i = D_i: none of the 9 V-1 rep lines gives 1; 7 FAIL lines, `e5 P1 sig_share`, `e5 P3 sig_share`, `e5 sig`), one SHA-256 round skipped (round bound `SHA256_ROUNDS - 1u`: 36 FAIL lines, the FIPS, xmd and E.5 rows), reshare coefficient wrong (g_i(0) = (λ + 1) s_i: the 5 V-1 denAuth4 rep lines give 0; 22 FAIL lines, `reshare good` gives DKG_BAD_RESHARE); 3 of 3 KILLED | sec 4.3 and 4.4 status; sec 8 note; sec 10 O90 to O103; docs/STATUS.md, README.md |
| S8 | Wasm replica: sec 5 exports, certificate chain check, merge and tip, FHE tally route, `amend_accept` | GREEN: a scripted history of 4 certified steps by the S7 secp256k1 DKG committee (`replica history: 4 steps, tip 4`); two replicas merge to one tip (`replica merge: 3 rows, tip 4`); the refuse fixtures give their codes (bad signature REP_BAD_SIG, fork REP_FORK, ill-typed constitution AMEND_ILL_TYPED, `Core` break AMEND_CORE; also REP_BAD_LINK, AMEND_NOT_FHE, BALLOT_BAD and PARTIAL_BAD: `replica refusals: 8 of 8`); the accept fixture is accepted (`replica accept: 1 of 1`); `langc eval` against build/replicatool: `replica: 25 cases, 0 mismatches`, `replica route: 19 cases, 0 mismatches`, `replica tally: 14 cases, 0 mismatches` (the S6 counts); `replica apply: 3 rows, state 4`; `host: 2 rows`; `input: 4 rows`; make check EXIT 0, gate: 0 failures (serial log); fmt: 104 files canonical; json: 29 fixtures; diagnostics: 36 codes, 0 without a fixture or a row; refusals: 54 check, 9 parse; evals: 77; tally: 14 cases, 28 counts, 0 mismatches; auth: 24 cases, 0 mismatches; laws: 12 of 12 (examples/threshold.lang) and 1 of 1 (examples/denote.lang); ir: 19 lowered; differential: 5318 cases, 0 mismatches; wasm: 22 modules valid | 3: fork check skipped (`mergeCode` without the digest compare: the fork row gives 0, not REP_FORK), `Core` check skipped (`amendCore` gives 0: the corebrk row gives 0, not AMEND_CORE), fragment check skipped (the fragment fold replaced by 0: the ill row gives AMEND_CORE, not AMEND_ILL_TYPED); 3 of 3 KILLED | sec 5 and sec 6 status; sec 10 O104 to O116; docs/STATUS.md, README.md |
| S9 | agent kit: SKILL.md, docs/GRAMMAR.md, examples/agent/ (5), `langc mcp`, `langc explain --json`, AGENTS.md refresh, docs/TOKEN-BASELINE.md, corpus/INDEX.md | GREEN (A3, A4, A5, A8, A13, A16, A17, A19): `agents: 10 verbs, 0 missing`; `explain: 13 fixtures`; `base: 152 names, 0 missing`; `mcp: 15 requests, 0 mismatches`; `skill: 6 copies, 0 drift`; `agent examples: 5 files, 13 of 13 laws`; `tokens: 3 tasks, 12 cells`; `corpus: 135 files, 0 mismatches`; `readme: 5 yes rows, 0 without a slice`; speed (O132): the mcp block 0.05 s, the explain block 0.27 s, the 9 S9 blocks 2.76 s; make check EXIT 0, gate: 0 failures (serial log); fmt: 110 files canonical; json: 29 fixtures; diagnostics: 36 codes, 0 without a fixture or a row; refusals: 54 check, 9 parse; evals: 77; tally: 14 cases, 28 counts, 0 mismatches; auth: 24 cases, 0 mismatches; the 10 S8 replica, host and input lines as at S8; laws: 12 of 12 (examples/threshold.lang) and 1 of 1 (examples/denote.lang); ir: 19 lowered; differential: 5318 cases, 0 mismatches; wasm: 22 modules valid | 3: MCP tool drops a field (the explain printer of src/main.c without `"type"`: `mcp: 15 requests, 1 mismatches`), a SKILL.md copy drifts (one line of the copy of examples/agent/03-threshold-reveal.lang changes: `skill: 6 copies, 1 drift`), `list-base` misses a name (the row `Set` of src/front/basenames.c goes: `base: 152 names, 1 missing`); 3 of 3 KILLED | sec 7 status; sec 10 O117 to O134; docs/STATUS.md, README.md, AGENTS.md |
| S10 | BGW arithmetic transcript validation model for the MPC tally route (Q6 (b)) (Q14 (a), ruled 2026-10-28): src/crypto/bgw.c and bgw.h, the host imports `q_mpc_check`, `q_mpc_add`, `q_mpc_mul`, `q_mpc_mulc`, `q_mpc_affine` and `q_mpc_open`, the replica entries `mpc_tally`, `mpc_route` and `tally_decide`, the generator test/mpctool.c and the fixture test/replica/mpc.txt; the replica runs `tallyᴹ` | GREEN: `replica mpc: 38 cases (15 by langc eval), 0 mismatches` (`tallyᴹ`); `replica decide: 34 cases, 0 mismatches` (`tallyᶠ` on the same ballots, N = 34): `tallyᴹ` = `tallyᶠ` on each fixture, so `tallyᴹ-correct` checks; `replica refusals: 11 of 11`; `bgw regressions: passed`; make check EXIT 0, gate: 0 failures (serial log); laws: 12 of 12 (examples/threshold.lang) and 1 of 1 (examples/denote.lang); all other count lines as at S9 | 3: one share dropped from the sum (the bgw_sum loop stops at count - 1: `FAIL replica mpc: build/mpctool lang is not test/replica/mpc.txt`, `FAIL bgw mutant 1: each sum share checks`; the mismatches stay 0, because replicatool reads the fixture), a reconstruction coefficient wrong (bgw_open gives a wrong x to the Lagrange call: `replica mpc: 38 cases (15 by langc eval), 19 mismatches`, `FAIL bgw mutant 2: open at each pair of members`), MPC output not checked (bgw_open does not check the output shares: `FAIL replica mpc badout mpc_route: want 12, ...`, `FAIL replica refusals: 10 of 11`, `FAIL bgw mutant 3: open with a bad output share rejects`); 3 of 3 KILLED | sec 1.2 Q14 row; sec 5 MPC route; sec 10 O135 to O143; sec 11 Q14 RULED; docs/STATUS.md, README.md |
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
- O90. Port set and layout (Claude reading, NOT ruled). All in
  src/crypto; langc does not link it (Q9 (a)). New files: (1)
  sha256.{c,h}: cairn-lang 6748510 src/sha256.c as is, with sha256_words
  and the front/u256.h include cut (the FROST inputs are byte strings).
  Head comment `Source: cairn-lang 6748510 src/sha256.c (sha256_words
  cut)`. (2) xmd.{c,h}: NEW C, expand_message_xmd and hash_to_field
  (O92). (3) secp256k1.{c,h}: constants and the parity lift_x from
  intent-lang 79e1898 src/front/secp256k1.c:6 to :49 (secp_recover and
  keccak cut), on R bn254.h fe_* and ec0_*; NEW C for SEC1 and scalar
  bytes (O93). (4) frost.{c,h}: NEW C, RFC 9591 (O94). (5) dkg.{c,h}:
  changed, not new: one DKG for both curves (O96), plus reshare (O97).
- O91. SHA-256 input (Claude reading, NOT ruled). SHA-256 is a one-shot
  function. Callers build each input in a fixed buffer (the largest: an
  RFC 9380 msg of 517 bytes plus 64 + 3 + DST; the FROST commitment list
  of THR_N_MAX x 98 bytes). XMD_MSG_MAX 1024 bytes; a longer input is
  refused (return 0), not cut.
- O92. expand_message_xmd (Claude reading, NOT ruled). xmd.c (NEW C, RFC
  9380 sec 5.3.1): `int xmd_expand(unsigned char *out, size_t len, const
  unsigned char *msg, size_t msg_len, const unsigned char *dst, size_t
  dst_len)`: b_in_bytes 32, s_in_bytes 64; refuse len > 255 x 32, len 0,
  dst_len > 255 (no long-DST hash: the FROST DSTs are short) and msg_len
  > XMD_MSG_MAX. `int xmd_to_scalar(Fe *out, const unsigned char *msg,
  size_t msg_len, const unsigned char *dst, size_t dst_len, const
  Modulus *n)`: hash_to_field with count 1 and L = 48 (RFC 9591 sec
  6.5): the 48 bytes are hi (16 bytes) and lo (32 bytes); out = hi x
  (2^256 mod n) + (lo mod n), with 2^256 mod n = 2^256 - n (n < 2^256 <
  2n) and lo mod n by one subtraction (scalar_of). Exact, no bias
  argument needed in the code.
- O93. secp256k1 (Claude reading, NOT ruled). secp256k1.c on R fe_* and
  ec0_* (one point type G1, so the DKG of O96 takes both curves):
  SECP_P, SECP_N, secp_b (7), secp_gen, secp_on_curve, secp_add,
  secp_mul (ec0_mul), secp_neg, secp_eq; `int secp_encode(unsigned char
  out[33], const G1 *p)` (SEC1 compressed, 02 for even y, 03 for odd y;
  the identity is refused, RFC 9591 SerializeElement); `int
  secp_decode(G1 *out, const unsigned char in[33])` (prefix 02 or 03, x
  < p, lift_x by parity, refuse a non-square); `int scalar_decode(Fe
  *out, const unsigned char in[32])` (big endian, refuse >= n),
  `scalar_encode`. cairn-lang group.h is not the base: it has a
  fixed-curve API, the smaller-y lift and no SEC1.
- O94. FROST (Claude reading, NOT ruled). frost.c (NEW C, RFC 9591,
  FROST(secp256k1, SHA-256), context "FROST-secp256k1-SHA256-v1"): H1 =
  xmd_to_scalar(m, ctx || "rho"), H2 ctx || "chal", H3 ctx || "nonce",
  H4 = SHA-256(ctx || "msg" || m), H5 = SHA-256(ctx || "com" || m).
  Functions after RFC 9591 secs 4 and 5: frost_nonce (nonce_generate
  from 32 random bytes and the secret, sec 4.1), frost_commit (round
  one, sec 5.1), frost_binding_factors (sec 4.4: rho_input = enc(PK) ||
  H4(msg) || H5(enc commitment list) || enc(identifier)),
  frost_group_commitment (sec 4.5: R = sum of D_i + rho_i E_i),
  frost_challenge (sec 4.6), frost_lagrange (sec 4.2,
  derive_interpolating_value over the signer identifiers), frost_sign
  (round two, sec 5.2: z_i = d_i + e_i rho_i + λ_i s_i c),
  frost_verify_share (sec 5.4), frost_aggregate (sec 5.3: (R, z), 65
  bytes), frost_verify (zG = R + cPK, cofactor 1). FrostResult:
  FROST_OK, FROST_BAD_SHARE, FROST_BAD_INDEX (0, above THR_N_MAX,
  repeated, not sorted), FROST_BAD_POINT (decode or identity),
  FROST_BAD_SIG. frost_aggregate does not check t: the coordinator
  checks MIN_PARTICIPANTS. So the rep mode (O98) can show that a set
  below t gives a signature that does not verify.
- O95. Vector sources (Claude reading, NOT ruled). Each row has its
  source in a C comment; each source has a second source, checked once
  in W: (1) SHA-256: FIPS 180-4 (App. B.1 to B.3 of FIPS 180-2, the same
  values): "abc", the 448-bit message, 1M 'a', plus "" (CAVP ShortMsg
  Len 0). Second source: cairn-lang 6748510 test/shatool.c:36 to :43 and
  `shasum -a 256` on the host (H2a, recorded in W/S7-PROGRESS.md). (2)
  expand_message_xmd: RFC 9380 App. K.1 (SHA-256, DST
  "QUUX-V01-CS02-with-expander-SHA256-128", len_in_bytes 0x20 and 0x80,
  msgs "", "abc", "abcdef0123456789", "q128_" + 128 'q', "a512_" + 512
  'a': 10 rows). Second source: W/s7-xmd-check.py (Python hashlib, from
  the sec 5.3.1 text, run with `python3 -I`), and the CFRG hash-to-curve
  repo vector file if WebFetch reaches it. Copies:
  W/vectors/rfc9380-k1.txt. (3) FROST: RFC 9591 App. E.5
  FROST(secp256k1, SHA-256): group secret and public key, message, share
  polynomial coefficient, the 3 shares, signer set {1, 3}, nonce
  randomness, nonces, commitments, binding factor inputs and binding
  factors, the signature shares, the final signature. Each is a
  byte-equal row. Second source: the CFRG frost repo poc vector file for
  secp256k1 (or the ZF frost-secp256k1 vectors.json) and
  W/s7-frost-check.py (Python big integers, `-I`, from the RFC inputs).
  Copies: W/vectors/rfc9591-e5.txt. (4) secp256k1: G on the curve, n G =
  infinity, (n - 1) G = -G, 2 G (SEC 2 and a Python check), enc(G) = 02
  79BE667E... (SEC 2 compressed G).
- O96. One DKG for both curves (Claude reading, NOT ruled). Reading: sec
  4.4 reshares BOTH keys, so one DKG and one reshare serve BN254 and
  secp256k1. dkg.c gets a curve descriptor `DkgCurve` (the field, the
  order, b, the generator and the PoK challenge function); `DKG_BN254`
  keeps the S6 dkg_challenge (keccak chain) and `DKG_SECP256K1` uses
  xmd_to_scalar with DST ctx || "dkg" over (i, enc C_{i,0}, enc R). Each
  dkg_* function takes `const DkgCurve *` first; tallytool call sites
  change to `&DKG_BN254` and nothing else. The S6 rows (DKG fixtures, 28
  rep counts, KATs) pin the BN254 path: they must pass unchanged.
  Alternative (rejected): a second copy of dkg.c for secp256k1 (two QUAL
  rules, two reshares). secp256k1 DKG fixtures: the S6 five on secp256k1
  (good dealing QUAL {1, 2, 3}; bad share DKG_BAD_SHARE QUAL {1, 3}; bad
  proof DKG_BAD_PROOF QUAL {2, 3}; DKG_BAD_INDEX; DKG_TOO_FEW), plus
  "the DKG key signs": FROST by {1, 2} and by {2, 3} verifies under the
  DKG PK.
- O97. Reshare (Claude reading, NOT ruled). NEW in dkg.c: old committee
  (t, n), signing quorum Q (|Q| >= t), new committee (t', n'). Member i
  of Q deals g_i of degree t' - 1 with g_i(0) = λ_{i,Q} s_i (λ over Q at
  0, the frost_lagrange rule): Feldman commitments C'_{i,k} and a PoK of
  g_i(0), as a DKG dealing. New check: C'_{i,0} = λ_{i,Q} PK_i, with
  PK_i the old verification share of i (dkg_key). A failed check gives
  the new code DKG_BAD_RESHARE (the dealer leaves QUAL'). New member j:
  s'_j = sum over QUAL' of g_i(j). The new group key = sum of C'_{i,0} =
  PK when QUAL' = Q (a smaller QUAL' gives DKG_TOO_FEW: λ is over Q).
  Second source for the formula: cairn-lang 6748510 src/front/dkg.h:79,
  :87. Fixture (secp256k1): old (t 2, n 3) from the good DKG; Q = {1,
  3}; new (t' 3, n' 4). Rows: (1) new PK = old PK; (2) old {1, 2} signs
  and verifies under PK; (3) new {2, 3, 4} signs and verifies under PK;
  (4) Lagrange of the new shares {1, 2, 3} = the old secret (the tool
  knows the dealers' constant terms); (5) new {1, 2} gives a signature
  that does not verify (t' = 3); (6) a dealing with g_i(0) = s_i (no λ)
  gives DKG_BAD_RESHARE. Plus one BN254 row: the new committee opens an
  S6 cast (Secret includes the ElGamal key).
- O98. Representation map of `Authorized` (Q5 (a), S7; Claude reading,
  NOT ruled). `build/frosttool rep`: one secp256k1 DKG (t 2, n 3); for
  each set S of {1, 2, 3} (8 sets) sign msg with S (S empty: no signer,
  print 0), aggregate, verify under PK, print `denote denAuth3 B1 B2 B3
  => V` (V = 1 when the signature verifies); then the O97 reshare to (t'
  3, n' 4) and the 16 sets: `denote denAuth4 B1 B2 B3 B4 => V`. Guest
  (examples/denote.lang): `denAuth3 b1 b2 b3` = 1 when at least 2 flags
  are true, else 0; `denAuth4` with 3 of 4 (the threshold quorum of the
  toy instance, a count with `elim` on each flag, the O60 copy rule). 24
  cases, 0 mismatches. The kit value (verify of the aggregate) meets the
  guest quorum decision line by line.
- O99. C tool (Claude reading, NOT ruled). A NEW test/frosttool.c
  (build/frosttool), not a tallytool mode: it keeps the S6 tool, its
  52.7 s and its mutant killers as they are. No argument: the rows (O95,
  O96, O97), `frost regressions: passed`. `rep`: O98. Makefile: CRYPTO
  adds sha256.c, xmd.c, secp256k1.c, frost.c; FROST_TOOL =
  test/frosttool.c $(CRYPTO); build/frosttool in `build`; check runs
  build/frosttool after build/tallytool; check-clang adds FROST_TOOL.
- O100. Speed (Claude reading, NOT ruled). ec0_mul is Jacobian already;
  at the S6 rate (about 60 ms per multiplication) the rows need about
  300 multiplications and `rep` about 180, so about 30 s for both modes.
  Budget 60 s for frosttool; above 120 s, profile before any change.
  Each run stays under 4 GB. Result: the rows 12.5 s and `rep` 32.0 s
  (user time), 44.5 s for both, so no change.
- O101. S7 mutants (Claude reading, NOT ruled). W/mut-s7.py is a copy of
  W/mut-s6.py with a new MUTANTS table and killers. (1) binding factor
  dropped: frost_group_commitment R_i = D_i (no rho_i E_i). Killers: the
  E.5 group commitment and signature rows, the share verify rows, every
  rep line with a quorum (V 1 to 0). (2) one SHA-256 round skipped:
  sha256.c round loop (cairn :43) bound `SHA256_ROUNDS - 1u`. Killers:
  the FIPS rows, the xmd rows, each FROST row. (3) reshare coefficient
  wrong: the dealer uses λ + 1 for g_i(0). Killers: reshare rows (1),
  (3), (4) (DKG_BAD_RESHARE), the denAuth4 rep lines. Result: 3 of 3
  KILLED (W/S7-mutants.log). Mutant 1: none of the 9 V-1 rep lines gives
  1 (9 mismatches), and the rows give 7 FAIL lines (`e5 P1 sig_share`,
  `e5 P3 sig_share`, `e5 sig`). The `e5 verify` rows pass: they check
  the fixed RFC 9591 signature, not the group commitment. Mutant 2: the
  rows give 36 FAIL lines (the FIPS, xmd and E.5 rows). Mutant 3: the 5
  V-1 denAuth4 rep lines give 0 (5 mismatches), and the rows give 22
  FAIL lines (`reshare good` gives DKG_BAD_RESHARE; `reshare new PK =
  old PK`, `reshare new FROST {2, 3, 4}` and `reshare Lagrange {1, 2, 3}
  = secret` fail).
- O102. Gate lines and docs (Claude reading, NOT ruled). test/gate.sh
  after the tally block: the same loop over `build/frosttool rep`, the
  line `auth: 24 cases, 0 mismatches`. test/eval/expect.txt: one row
  each for denAuth3 and denAuth4 (evals 75 to 77). The Wasm differential
  covers the new denote.lang entries by its glob (5274 to 5318 cases).
  fmt stays 103 files. Docs by one exact-count Python script
  (W/s7-docs.py, W/s6-h4-docs.py the model): PLAN sec 4.3 and 4.4
  status, sec 8 note (SHA-256 is a port of cairn-lang 6748510; secp256k1
  constants from intent-lang 79e1898; xmd and FROST NEW), sec 9 S7 row
  at Close, sec 10 O90 to O103; STATUS (S7 sentence, counts, mutants,
  Crypto known limits: not constant time, the tool nonces use fixed
  randomness, n at most 8); README build files (the new src/crypto
  files, test/frosttool.c). Result: the gate gives `auth: 24 cases, 0
  mismatches`, 77 evals and 5318 differential cases with 0 mismatches;
  fmt stays 103 files. W/s7-docs.py makes the docs edits.
- O103. S6 baseline (Claude reading, NOT ruled). The S6 counts at
  09f7f59 (gate 0 failures, tally 14/28/0, evals 75, fmt 103, json 29,
  laws 12/12 and 1/1, check refusals 54, parse 9, 36 codes, ir 19, wasm
  22, differential 5274/0). H2a STEP 0 runs the serial gate once
  (W/S7-step0-gate.log) before any edit.
- O104. Where the replica lives and who hosts it (Claude reading, NOT
  ruled). The replica program is replica/replica.lang (a new directory;
  it is NOT in examples/, so the node loop of F6 does not change).
  `langc build` writes build/replica.wasm. The host is the C tool
  test/replicatool.c, linked with the wasm2c translation of
  build/replica.wasm, the wasm2c runtime (F7) and CRYPTO. The Makefile
  chain: build/langc, then build/replica.wasm, then build/replica.c
  (wasm2c), then build/replicatool. Compiler: TCC when the H2a probe P1
  passes, else CC for this one tool (README says why). Result: TCC
  compiles build/replicatool. The wasm2c translation takes the shim
  src/w2c-tcc.h, because TCC has no `__builtin_add_overflow` (the
  Makefile comment says why). No new node, Python or shell harness. The
  node runner stays for import-free modules.
- O105. The host-import ABI (Q9 (a); Claude reading, NOT ruled). Import
  module "q". Each import parameter and result is an i64. A pointer
  parameter is the address of a kit block in memory 0 (F2 layout). The
  module exports memory 0 as "memory". A U256 or a digest is 4 words,
  word 0 most significant, each word as 8 big-endian bytes (so the 32
  bytes are the words in order). A point is 8 words (x, then y), as
  g1_to_words (bn254.h:66-67); secp256k1 points use the same form with a
  new secp_from_words that refuses an off-curve point (the USER S7 fix
  of F1). The result is the C enum value (0 = OK). An output goes into a
  block that the guest allocates before the call. The imports, in this
  order (function indices 0 to 5; `alloc` becomes 6 and entry K becomes
  7 + K): 0 q_hash2 (out4, a4, b4): SHA-256(a 32 bytes, b 32 bytes)
  (cairn thr_hash), result 0; 1 q_frost_verify (pk8, sig12, msg4):
  secp_encode(R) and z, then frost_verify, result FrostResult; 2
  q_ballot_verify (proof, pk8, ct16, ctx4): sig_or_verify, result
  SigResult; 3 q_tally_add (out16, a16, b16): tally_add, result 0; 4
  q_partial_verify (part29, key8, ct16): thr_verify, result 0 or 1; 5
  q_combine (out1, parts, k, keys, t, n, ct16): thr_open, result
  ThrResult. sig12 = R (8 words) then z (4 words). part29 = x (1) then
  d, a, b (24) then z (4). The proof layout and the `bits` value of
  q_combine come from sigma.h:45-53 and the S6 tallytool `rep` mode (H2b
  reads them once).
- O106. The guest form of the imports (Claude reading, NOT ruled). Each
  import is a kit name in domain/domain.lang with a fixed type over word
  records (`W4`, `Pt`, `Ct`, `Part`, `Proof`). The checker treats it as
  opaque. `langc eval` calls the same C function (langc links CRYPTO
  from S8). lower.c gives a new IR statement IR_STMT_HOST (import
  number, argument expressions, result local), after an ALLOC of the
  output block. wasm.c writes the IMPORT section, the index shift,
  `call` (0x10) and the memory export. A module without a host name
  stays byte-equal to S7 (no import section): the wasm 22 and
  differential 5318 lines do not change.
- O107. Certificate format and chain link (the cairn-lang precedent of
  F10; Claude reading, NOT ruled). A step body is 4 words (n, slot,
  value, editTag). e_n = H2(body, 0). h_0 = H2(tagGenesis, 0) with
  tagGenesis = "quorum-genesis" (ASCII, big endian, zero padded to 32
  bytes). h_n = H2(H2(tagAppend, h_{n-1}), e_n) with tagAppend =
  "quorum-append". A certificate is (body, R, z): the FROST signature
  (RFC 9591, the S7 code) of the 32 message bytes h_n under the group
  key PK. The signature thus covers the parent (through h_{n-1}), the
  body and the index (body word 0 = n). `cert_verify pk chain` walks the
  chain from genesis. The first failure gives its code: a body word 0
  that is not the position gives REP_BAD_LINK; a signature that does not
  verify gives REP_BAD_SIG.
- O108. Merge, fork and tip (Claude reading, NOT ruled). A replica state
  is a chain (a list of certificates for 1 to m). The total order of
  certified states is the chain length (O3, the S4 tip-order proof).
  `rep_tip pk chain` = m when `cert_verify` gives 0. `rep_merge pk a b`:
  both chains verify; with m_a <= m_b, h_{m_a} of b must equal h_{m_a}
  of a (b fast-forwards a), else REP_FORK. The merged tip is the longer
  chain. Equal lengths with different digests give REP_FORK. This is the
  PLAN sec 5 reading "merge is the join, a fast-forward". One pass over
  each list (F4 chain walk) with a record accumulator (count, h, h at
  m_a) is sufficient: no walk of two lists in step.
- O109. Run-time input (closes the O46 question; USER ruled (i)). The
  run-time bag form is a list in arrival order: ballots, certificates
  and circuit opcodes are run-time lists of word records, walked by the
  list walk of F4. Two forms, in this order: (i) an entry parameter of a
  list type, passed by address in the kit block layout; the entry starts
  its heap after the input (an exported mutable global `heap_base`, 0
  when the module has no input); the host writes the input; (ii) if
  probe P2 shows that (i) needs more than one session of lower.c work,
  the S8 fixtures are closed entries over constant lists (the evaluator
  unrolls the walk; the host calls stay in the residual because O106
  makes them opaque), and (i) moves to a new O item for S12. H2a decides
  between (i) and (ii) and records it. Result: (i), the USER ruling. The
  gate line `input: 4 rows` compares the Stack that build/replicatool
  writes below `heap_base` with `langc eval`.
- O110. FHE tally route (Claude reading, NOT ruled). The replica does:
  `ballot_verify` on each ballot (q_ballot_verify), `tally_add` of the
  casts slot by slot (q_tally_add), `partial_verify` of each partial
  decryption (q_partial_verify), `combine` of each slot (q_combine, the
  count), then `decide` in public on the counts (guest code, no import).
  The host computes only the 4 imports. The data (one DKG t 2 n 3, the
  casts, the partials) comes from a new `tallytool lang` mode with the
  S6 seeds. Result: `build/tallytool lang` writes test/replica/tally.txt
  (19 lines). The gate gives `replica route: 19 cases, 0 mismatches` and
  `replica tally: 14 cases, 0 mismatches` against the S6 tally counts.
- O111. `amend_accept` (Q10 (a): the module carries the fragment
  checker; Claude reading, NOT ruled). The new constitution is a
  run-time list of opcode words: the postfix form of a `Circuit` term
  (the 9 constructors of F9), with each `Code` in one word (postfix
  digits in base 8: bitC 1, natC 2, optC 3, pairC 4, bagC 5). Check 1
  (fragment): a walk with a stack of (a, b) code pairs, depth at most 4
  (8 words in the accumulator; deeper gives AMEND_ILL_TYPED). The end
  stack must be one `Circuit (bagC ballot) (optC edit)`. Check 2 (laws,
  FHE route): the opcodes start with the entrenched `agg` opcodes, word
  for word, and end with `seqC`: the code is `decide` after `agg`, so
  `factors` holds by definition. Else AMEND_NOT_FHE. Check 3 (`Core`):
  `coreCheck σ'` (an entrenched closed circuit, run by the guest `run`)
  gives `true`, else AMEND_CORE. The checks run in the order 1, 2, 3.
  Result: the USER ruling R-E18 makes the `Core` check the threshold
  template with k at least 1. test/replica/amend.txt has 4 rows (ill 4,
  notfhe 5, corebrk 6, accept 0), and `langc eval` and
  `build/replicatool amend` give the same code on each row.
- O112. Replica result codes (Claude reading, NOT ruled): 0 OK, 1
  REP_BAD_SIG, 2 REP_BAD_LINK, 3 REP_FORK, 4 AMEND_ILL_TYPED, 5
  AMEND_NOT_FHE, 6 AMEND_CORE, 7 BALLOT_BAD, 8 PARTIAL_BAD. They are
  return values of the exports, not langc diagnostics: the codes check
  (36) does not change. PLAN sec 5 has the table. If H2 adds a langc
  diagnostic (for example a host name in `langc eval` without CRYPTO),
  the codes check count changes and the HANDOFF of that step names it.
  Result: no step adds a langc diagnostic, so the codes check stays 36.
- O113. Fixtures (test/replica/; Claude reading, NOT ruled). The
  scripted history: k = 4 certified steps, signed by the S7 secp256k1
  DKG committee (t 2, n 3, the good dealing), signers {1, 2} for steps 1
  and 2, {2, 3} for steps 3 and 4. A new `frosttool chain` mode writes
  test/replica/history.lang from the fixed S7 seeds. The gate writes it
  again and `cmp`s it with the checked-in file. Merge rows: A = steps 1
  to 2, B = steps 1 to 4: merge A B = merge B A = tip 4; merge A A = tip
  2. Refuse fixtures and codes: bad signature (one z word of step 3
  changed: REP_BAD_SIG), fork (B' = steps 1, 2 and a different step 3
  with a valid signature; merge B B': REP_FORK), ill-typed constitution
  (seqC over codes that do not meet: AMEND_ILL_TYPED), `Core` break (a
  well-typed FHE-form edit with `coreCheck σ'` false: AMEND_CORE).
  Accept fixture: a well-typed FHE-form edit with `coreCheck σ'` true:
  0. Result: `build/frosttool chain` writes test/replica/history.txt (25
  lines: ROW ENTRY WANT X0 .. Y3 PRE), not a .lang file, and the gate
  `cmp`s it with the checked-in file. test/replica/amend.txt has the 4
  amend rows (R-E19).
- O114. Gate lines (new; Claude reading, NOT ruled): `replica: N cases,
  0 mismatches` (langc eval against build/replicatool on each fixture
  entry), `replica history: 4 steps, tip 4`, `replica merge: 3 rows, tip
  4`, `replica refusals: 4 of 4`, `replica accept: 1 of 1`, and the FHE
  route row `replica tally: 14 cases, 0 mismatches` against the S6 tally
  counts. fmt grows by the new .lang files (each step names its count).
  Result: the gate gives `host: 2 rows`, `input: 4 rows`, `replica: 25
  cases, 0 mismatches`, `replica history: 4 steps, tip 4`, `replica
  merge: 3 rows, tip 4`, `replica apply: 3 rows, state 4`, `replica
  route: 19 cases, 0 mismatches`, `replica tally: 14 cases, 0
  mismatches`, `replica accept: 1 of 1` and `replica refusals: 8 of 8`
  (bad signature, bad link, fork, the 2 tally refusals and the 3 amend
  refusals). fmt grows from 103 to 104 files (replica/replica.lang). The
  other S7 counts do not change.
- O115. Mutants (3; Claude reading, NOT ruled), in replica/replica.lang
  (W/mut-s8.py from W/mut-s7.py; each rebuild `make -B` of
  build/replica.wasm and build/replicatool): M1 fork check skipped
  (`rep_merge` takes the longer chain without the digest compare;
  killer: the fork fixture wants REP_FORK); M2 `Core` check skipped
  (killer: the `Core` break fixture wants AMEND_CORE); M3 fragment check
  skipped (killer: the ill-typed fixture wants AMEND_ILL_TYPED). Result:
  3 of 3 KILLED (W/S8-mutants.log). The killers are the history and
  amend loops of test/gate.sh alone. M1 (the digest compare in
  `mergeCode` replaced by 0): the fork row gives 0 on both sides, not 3
  (2 FAIL lines). M2 (`amendCore` gives 0): the corebrk row gives 0, not
  6. M3 (the fragment fold replaced by 0): the ill row gives 6, not 4.
- O116. Speed budget (Claude reading, NOT ruled). One frost_verify is
  the cost unit (frosttool: about 12.5 s for all S7 rows). The replica
  section of the gate (eval and Wasm sides, about 40 verifies) is at
  most 60 s, with build/replicatool at most 30 s. Result: one
  frost_verify takes about 94 to 113 ms (TCC). A tally combine row takes
  2.64 to 3.05 s of user time on each side, over the budget. The USER
  ruling R-E37 (a) accepts the time.
- O117. (Claude reading, NOT ruled) Baseline. H2 STEP 0 runs one serial
  gate into W/S9-base-gate.log. Its count lines (expect fmt 105) are the
  S9 baseline, not W/S8-gate.log.
- O118. (Claude reading, NOT ruled) `langc --help` and `langc help`
  print the usage on stdout and exit 0. The usage adds `langc explain
  [--json] NAME` and `langc mcp`. A4 gate line: each `langc VERB` in
  AGENTS.md is in `langc --help` (`agents: V verbs, 0 missing`).
- O119. (Claude reading, NOT ruled) `langc explain --json NAME` prints
  one line `{"name":S,"kind":S,"type":S,"class":S|null,"slice":S}` and
  exits 0. `type` is the canonical (fmt) print of the type. `class` is
  the R1 class of O25 (`CM`, `indexed family`, `record`, `base type`),
  null for a term. `kind` and `slice` come from the PLAN sec 3 columns.
  The text form prints `NAME : TYPE` and one line `kind class slice`. An
  unknown name gives the existing unbound-name code (no new code; H2
  names it from docs/DIAGNOSTICS.md). A8 gate: one fixture
  test/explain/KIND.json for each sec 3 kind (`explain: K fixtures`).
- O120. (Claude reading, NOT ruled) Names. A new C table
  src/front/base.c holds each sec 3 name with its kind and slice. `type`
  and `class` come from the checker environment of lib/prelude.lang and
  domain/domain.lang. `list-base` prints the table names. A5 gate: the
  sorted names that gate.sh extracts from the PLAN sec 3 tables equal
  the sorted `list-base` names (`base: B names, 0 missing`). Then
  gate.sh reads docs/PLAN.md: the Close runs the gate after the last
  PLAN edit.
- O121. (Claude reading, NOT ruled) `langc mcp`: MCP stdio transport,
  JSON-RPC 2.0, one message on each line, no Content-Length frame.
  Methods: `initialize` (echo the client protocolVersion; serverInfo
  {name "quorum-lang", version "S9"}; capabilities {tools {}}),
  `notifications/initialized` (no reply), `ping`, `tools/list`,
  `tools/call`. Errors: -32700 parse, -32600 bad request, -32601 unknown
  method, -32602 bad params. EOF gives exit 0. Same binary build/langc,
  built by tcc.
- O122. (Claude reading, NOT ruled) MCP tools (inputSchema in
  tools/list): `check {path}` gives one text item with the `check
  --json` lines, isError = exit not 0; `explain {name}` gives the O119
  line; `list-base {}` gives the names, one on each line; `show-law
  {path, name}` gives the fmt print of the law and `discharged` or
  `open`. Output field order is fixed. A5 gate: test/mcp/requests.jsonl
  through `build/langc mcp` equals test/mcp/responses.jsonl byte for
  byte (`mcp: N requests, 0 mismatches`).
- O123. (Claude reading, NOT ruled) A small JSON reader in new C
  (src/front/jsonin.c: object, array, string with escapes and \u,
  number, true, false, null). C tests in test/fronttool.c or a new
  test/mcptool.c (H3 picks the one with less churn).
- O124. (Claude reading, NOT ruled) skills/quorum-lang/SKILL.md. Front
  matter: `name: quorum-lang`, `description:` (one line, at most 1024
  chars). Body: the routing rule, the A6 loop (write, `check --json`,
  apply `fix`, retry), the verbs, the grammar card, the 5 examples. Each
  copy is a fenced block whose info string names its source
  (`quorum-lang examples/agent/NAME.lang`, `quorum-lang
  docs/GRAMMAR.md#card`). gate.sh extracts each block with awk and
  compares it with its source (`skill: 6 copies, 0 drift`, plus the two
  front matter keys: A16).
- O125. (Claude reading, NOT ruled) Grammar card: a new section `##
  Card` (at most 60 lines) after the title of docs/GRAMMAR.md, one line
  for each canonical form. The title changes to the S8 surface. SKILL.md
  copies the card section.
- O126. (Claude reading, NOT ruled) examples/agent/ (A3), graded 1 to 5:
  01-certificate.lang (certificate check), 02-cast-tally.lang (cast and
  tally into a bag), 03-threshold-reveal.lang (reveal needs a quorum),
  04-amendment.lang (an amendment keeps Core), 05-replica-merge.lang
  (merge is a join). Each has at least 2 laws and `langc laws` gives m
  of m. H4 writes the exact counts (`agent examples: 5 files, L of L
  laws`). fmt +5.
- O127. (Claude reading, NOT ruled) TOKEN-BASELINE.md (A13, Q12 (a), Q13
  (b)). 3 tasks: T1 certificate check, T2 cast and tally, T3 amendment
  check. 4 columns: quorum-lang (Unicode), quorum-lang ASCII spelling
  (the :182 forms), Python, Rust. The proxy is new C test/tokproxy.c
  (build/tokproxy): a run of ASCII letters, digits and `_` costs
  ceil(len / 4); each other ASCII non-space byte costs 1; each non-ASCII
  UTF-8 byte costs 1; white space costs 0. The Python and Rust files are
  text samples in test/baseline/ (not run). Gate: each quorum file
  checks, fmt of the ASCII file equals the Unicode file, and each table
  cell equals tokproxy of its file (`tokens: 3 tasks, 12 cells`).
- O128. (Claude reading, NOT ruled) corpus/INDEX.md (A17, corpus only;
  the USER trains). One row for each `.lang` file in examples/ and
  test/: `| path | first code or ok | parsed | typed | laws D/T |`. A
  gate.sh loop builds the same rows from `check --json` and compares
  them with the table (`corpus: N files, 0 mismatches`). H5 writes the
  table once with a W script.
- O129. (Claude reading, NOT ruled) README and AGENTS (A19, A4). The 5
  Yes rows already name a slice: gate line `readme: 5 yes rows, 0
  without a slice`. AGENTS.md: replace "Status at S1" and "Tool loop at
  S1" with the S9 state; add explain, mcp and the skill path; keep the
  routing rule. README Status (:23) changes to the S9 text.
- O130. (Claude reading, NOT ruled) New gate lines (H2 to H5): agents,
  explain, base, mcp, skill, agent examples, tokens, corpus, readme.
  Changed counts: fmt 105 + 5 agent + 3 ASCII baseline + new fixtures;
  json 29 and diagnostics 36 stay if no new code. R-H5-1 changed the fmt
  count: the gate line stays `fmt: 110 files canonical` (the H5 gate).
- O131. (Claude reading, NOT ruled) Mutants (W/mut-s9.py, a copy of
  W/mut-s8.py): M1 the mcp printer of `explain` drops `"type"` (mcp cmp
  fails); M2 one line of the SKILL.md copy of 03-threshold-reveal
  changes (skill drift); M3 one row of src/front/base.c goes (base gate
  fails).
- O132. (Claude reading, NOT ruled) Speed budget: the mcp transcript and
  the explain fixtures each under 1 s; the S9 gate lines together under
  10 s. tallytool time depends on load (STEP 0: 162 s).
- O133. (Claude reading, NOT ruled) W/bak-s8-h2b (17 files, not in
  R-E52): Q-S9-5.
- O134. (Claude reading, NOT ruled) PLAN sec 9 has S10 to S12, so the S9
  Close writes W/S10-PROMPT.md. S10 needs Q14 (OPEN).
- O135. (Claude reading; the USER ruled Q-S10-1 (a1)) The replica runs
  the decide part under MPC and returns only the `Maybe Edit` outcome,
  as the denotation `reveal (evalR (constitution σ a) box)`. Bit checks
  also open `b (b - 1)` zero-test results. This model does not hide the
  transcript (sec 5, S10 security scope). The compare
  of the shared count c (0 to V) with a public threshold k is an
  indicator polynomial f_k(c) = [c >= k] on 0 .. V with public
  coefficients (Lagrange on V+1 points). It needs c^2 .. c^V: V-1
  multiplications, each one degree reduction. V <= 3 in the fixtures:
  2 multiplications at most.
- O136. (Claude reading, NOT ruled) `tallyᶠ` in the replica is a new
  `decide k` in the clear on the S8 `combine` count: the threshold
  template of R-E18 with k >= 1, outcome 1 (`Just edit`) when count >=
  k, else 0 (`Nothing`). The MPC route opens the same outcome code, so
  `tallyᴹ` = `tallyᶠ` compares at the outcome type.
- O137. (Claude reading, NOT ruled) The MPC input. Each ballot is a
  degree-1 Shamir sharing of its bit to the 3 committee members (x =
  1, 2, 3), dealt with Feldman commitments (the DkgDealing form, t 2).
  Each member checks its share with `dkg_check_share` (the analogue of
  `ballot_verify`). Local add: each member sums its shares mod r
  (mutant 1 drops one share from this sum). The commitments of the sum
  are the point sums of the dealing commitments.
- O138. (Claude reading, NOT ruled) Multiply with degree reduction
  (BGW). Member i forms its degree-2 product share and reshares it
  with a degree-1 Feldman dealing. The new share of member j is the sum
  over i of lambda_i s_ij, lambda_i = `thr_lagrange` over all 3
  members (degree 2 needs 3 points). Each sub-share is checked with
  `dkg_check_share`. The commitments of the new sharing are the sum
  over i of lambda_i C_i (point ops). The local product has no check
  without a pairing. The USER ruled Q-S10-4 (b): each member proves
  its local product with a Chaum-Pedersen proof (`thr_partial`), and
  the reduce rejects a bad product proof.
- O139. (Claude reading, NOT ruled) Open. The members give their
  output shares. The replica checks each against the commitments of
  the output sharing (the `dkg_check_share` form; mutant 3 turns this
  check off), then reconstructs at 0 with `thr_lagrange` over 2 shares
  (mutant 2 makes one coefficient wrong). n = 3 >= 2t + 1 = 3 holds
  for degree 1 (t = 1 corrupt member).
- O140. (Claude reading; the USER ruled Q-S10-3 (a)) Bit check of each
  ballot: one multiplication b (b - 1) for each ballot, and the opened
  value must be 0, else the route rejects (a code, the badballot 7
  model). Without it, a ballot of 5 passes the share check, and the
  FHE route (BitProof) and the MPC route can give different outcomes.
  With O135, V = 3 costs 3 + 2 = 5 multiplications.
- O141. (Claude reading; the USER ruled Q-S10-2 (b), N = 34) Fixtures.
  test/replica/mpc.txt has 38 lines: 34 `mpc_tally` rows on the ballot
  vectors of the tally.txt `combine` rows (V 1 to 3; the 34 cases of
  `replica decide`), each with a public k and the MPC transcript words
  (input dealings, product proofs and reshare dealings, output
  shares), and 4 `mpc_route` rows: `mr`, `badin` (a bad input share,
  code 9), `badproof` (a bad product proof, code 10) and `badout` (a
  bad output share, code 12). The generator
  `build/mpctool lang` (test/mpctool.c, the tallytool model) writes
  it, and the gate compares it.
- O142. (Claude reading, NOT ruled) The MPC route enters the replica
  as host imports (the S8 model: C does the field and group work, the
  guest calls it): `q_mpc_check`, `q_mpc_add`, `q_mpc_mul` (one degree
  reduction), `q_mpc_mulc`, `q_mpc_affine` and `q_mpc_open` (check,
  then Lagrange). The new replica entries are `mpc_tally`, `mpc_route`
  and `tally_decide`. `langc eval` (src/front/eval.c) and the C host
  test/replicatool.c both call the byte forms of src/crypto/bgw.c.
- O143. (Claude reading, NOT ruled) Each S10 mutant is KILLED by a
  named mpc gate line and by one named C regression row of
  build/mpctool. M1 (a share dropped from the local sum): the gate
  line `FAIL replica mpc: build/mpctool lang is not
  test/replica/mpc.txt`. The mismatches stay 0 under M1: replicatool
  reads the fixture, and `q_mpc_add` does not call bgw_sum. M2 (a
  wrong x at the Lagrange call of the open): mismatches > 0. M3 (the
  output check off): `FAIL replica mpc badout mpc_route` and `FAIL
  replica refusals: 10 of 11`.

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
- Q14. MPC protocol (S10, Q6 (b)). RULED (a) 2026-10-28. (a) Honest-majority BGW over the
  committee's Shamir shares. (b) SPDZ-style with preprocessing (dishonest
  majority). Needed before S10.
- Q15. Constant-size IVC proof scheme (S11, Q11 (b), O13). (a) A folding
  scheme (Nova-style) with a final compressed proof. (b) A recursive
  SNARK. Needed before S11.
- Q16. `isSet ℕ` and `isSet Bool` (S3). RULED (b) 2026-10-26. (b) A
  guest proof: a dependent eliminator `elim` for ℕ and Bool in the
  kernel, and discreteness and Hedberg as guest laws in the Prelude.
