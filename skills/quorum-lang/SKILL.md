---
name: quorum-lang
description: Write, check and repair quorum-lang programs (an Agda-like cubical language for threshold authorization, anonymous ballots, private tallies, self-amending rules and offline replicas) with the langc checker. Use it when the task is in a Yes row of the quorum-lang README table.
---

# quorum-lang

## Routing rule

Use quorum-lang when the task is in a "Yes" row of the README table:
threshold authorization, anonymous ballots, private tallies,
self-amending rules, offline replicas. For other tasks, use a
general-purpose language.

## The loop (A6)

1. Write FILE.lang in the canonical form of the card below.
2. Run `build/langc check --json FILE.lang`. Each stdout line before the
   last is one diagnostic (docs/DIAGNOSTICS.md). The last line gives the
   parsed and typed counts and the laws. Exit 0: the file type checks.
3. A diagnostic with `"retry":true`: apply its `fix` at its `span` when
   `fix` is not null, else correct the file at the span. Then do step 2
   again.
4. A diagnostic with `"retry":false`: the design refuses the form. Change
   the approach. The `message` names the rule.
5. On W_NONCANON, write the output of `build/langc fmt FILE.lang` to a
   new file, and replace FILE.lang with it.
6. Run `build/langc laws FILE.lang`. It exits 0 only when the file checks
   and each law is discharged.

A program has no imports. Define each name that the program uses, as
the examples below do. `langc list-base` prints the base names, and
`langc explain NAME` gives the kind, class and slice of one name.

## Verbs

- `langc check [--json] PROG`: type check. Text: `ok`, or one line on
  stderr.
- `langc fmt PROG`: print the canonical text of PROG.
- `langc laws PROG`: `law NAME discharged` or `law NAME open` for each
  law, then `laws: D of T discharged`.
- `langc explain [--json] NAME` and `langc list-base`: the base names.
- `langc eval PROG NAME [ARGS...]`, `langc ir PROG`, `langc abi PROG` and
  `langc build PROG -o OUT [--runtime]`: the kit back end.
- `langc mcp`: a JSON-RPC 2.0 server on stdin and stdout, one message on
  each line. Its 4 tools are `check` (`path`), `explain` (`name`),
  `list-base` (no arguments) and `show-law` (`path`, `name`). A tool
  result is one text item, with `isError` true when the verb fails.

## Card

```quorum-lang docs/GRAMMAR.md#card
One line for each canonical form that `langc fmt` prints. `A` and `B`
are types, `t` and `u` are terms, `r` and `s` are interval terms. The
sections below give the full rules.

~~~
-- text                            a comment, at column 1
f : (x : A) → (y : B) → C          a signature: one group for each →
f x y = t                          the clause: it names the parameters
law name : A                       a law: it is discharged when it checks
data D (p : P) : A → Type where    an indexed family or a cell signature
  c : (x : A) → D p a              a constructor, 2 spaces in
record R (p : P) : Type where      the named Σ of the fields
  field : A                        a field, 2 spaces in
module M (p : P) where             a parameter section
  g : A                            each line of a section, 2 spaces in
Type   Type₁   Type ℓ              the universes
Level   lzero   lsuc ℓ   ℓ-max ℓ m the levels (a closed form, at most 1)
(x : A) → B                        a dependent function type
A → B                              a function type
λ x y → t                          nested λ terms as one λ
λ (x : A) → t                      a λ with a typed binder
f a (g b)                          an application: ( ) on a non-atom argument
let x = t in u                     one name, on one line
Σ A (λ (x : A) → B)                a dependent pair type
A × B                              a pair type
a , b                              a pair: fst p and snd p are its parts
a ≡ b                              a path type: PathP L a b is the full form
λ i → t                            a path: p r applies the path p to r
refl                               the constant path
i0   i1   ~ r   r ∧ s   r ∨ s      the interval: ends, reversal, meet, join
primTransp (λ i → A) r u           transport along a line
primHComp (λ j → λ { (i = i0) → a ; (i = i1) → b }) u0   composition
x ∷ xs   xs ++ ys   f ∘ g   p ∙ q  an operator with 2 arguments: infix
_∘_ f g n                          an operator with more arguments: prefix
∥ A ∥₁                             the propositional truncation
∣_∣₁ A a                           its constructor: prefix, the type first
∃[ x ꞉ A ] B                       there is an x in A with B
elim (λ (b : Bool) → P) t f b      Bool: the true case, then the false case
elim (λ (n : ℕ) → P) z s n         ℕ: s takes (k : ℕ) (ih : P)
0   1   suc n                      the numerals of ℕ
~~~
```

## Examples

Each file checks, and `langc laws` gives m of m.

### 1. A certificate check

```quorum-lang examples/agent/01-certificate.lang
-- Agent example 1 of 5 (S9 O126): a certificate check. A certificate
-- holds the signature flags of the 3 members of a committee. The check
-- accepts the certificate when at least t members sign. The file has no
-- imports: it defines each name that it uses.

-- flagN b n adds 1 to n when the flag b is true.
flagN : Bool → ℕ → ℕ
flagN b n = elim (λ (c : Bool) → ℕ) (suc n) n b

-- atMost m n is true when m is at most n.
atMost : ℕ → ℕ → Bool
atMost m n = elim (λ (k : ℕ) → ℕ → Bool) (λ (j : ℕ) → true) (λ (k : ℕ) (ih : ℕ → Bool) (j : ℕ) → elim (λ (i : ℕ) → Bool) false (λ (i : ℕ) (r : Bool) → ih i) j) m n

Cert : Type
Cert = Bool × Bool × Bool

signers : Cert → ℕ
signers c = flagN (fst c) (flagN (fst (snd c)) (flagN (snd (snd c)) 0))

certified : ℕ → Cert → Bool
certified t c = atMost t (signers c)

-- Members 1 and 3 sign: the certificate is good for t = 2.
law two-of-three : certified 2 (true , false , true) ≡ true
two-of-three = refl

-- Only member 3 signs: the certificate is not good for t = 2.
law one-of-three : certified 2 (false , false , true) ≡ false
one-of-three = refl

-- Each certificate is good for t = 0.
law zero-threshold : (c : Cert) → certified 0 c ≡ true
zero-threshold c = refl
```

### 2. Cast and tally into a bag

```quorum-lang examples/agent/02-cast-tally.lang
-- Agent example 2 of 5 (S9 O126): cast ballots and tally them into a
-- bag. A ballot is a Bool vote. A bag of votes is the pair of counts
-- (yes , no): it keeps each vote but not the order of the votes. The laws
-- show one tally, and that the order of two casts does not change the bag.

Bag : Type
Bag = ℕ × ℕ

emptyBag : Bag
emptyBag = 0 , 0

castVote : Bool → Bag → Bag
castVote v b = elim (λ (c : Bool) → Bag) (suc (fst b) , snd b) (fst b , suc (snd b)) v

tally3 : Bool → Bool → Bool → Bag
tally3 v1 v2 v3 = castVote v1 (castVote v2 (castVote v3 emptyBag))

-- Two yes votes and one no vote.
law tally-two-one : tally3 true false true ≡ (2 , 1)
tally-two-one = refl

-- The order of two casts does not change the bag.
law cast-comm : (u : Bool) → (v : Bool) → (b : Bag) → castVote u (castVote v b) ≡ castVote v (castVote u b)
cast-comm u v b = elim (λ (x : Bool) → castVote x (castVote v b) ≡ castVote v (castVote x b)) (elim (λ (y : Bool) → castVote true (castVote y b) ≡ castVote y (castVote true b)) refl refl v) (elim (λ (y : Bool) → castVote false (castVote y b) ≡ castVote y (castVote false b)) refl refl v) u
```

### 3. A reveal needs a quorum

```quorum-lang examples/agent/03-threshold-reveal.lang
-- Agent example 3 of 5 (S9 O126): a reveal needs a quorum. A private
-- tally stays sealed. revealAt opens it only when at least t of the 3 key
-- holders give their share. A result is a flag and a value. Without a
-- quorum, the flag is false and the value is 0, thus the result tells
-- nothing about the tally.

-- flagN b n adds 1 to n when the flag b is true.
flagN : Bool → ℕ → ℕ
flagN b n = elim (λ (c : Bool) → ℕ) (suc n) n b

-- atMost m n is true when m is at most n.
atMost : ℕ → ℕ → Bool
atMost m n = elim (λ (k : ℕ) → ℕ → Bool) (λ (j : ℕ) → true) (λ (k : ℕ) (ih : ℕ → Bool) (j : ℕ) → elim (λ (i : ℕ) → Bool) false (λ (i : ℕ) (r : Bool) → ih i) j) m n

pick : Bool → ℕ → ℕ → ℕ
pick b x y = elim (λ (c : Bool) → ℕ) x y b

quorum : ℕ → Bool → Bool → Bool → Bool
quorum t k1 k2 k3 = atMost t (flagN k1 (flagN k2 (flagN k3 0)))

revealAt : ℕ → Bool → Bool → Bool → ℕ → Bool × ℕ
revealAt t k1 k2 k3 x = quorum t k1 k2 k3 , pick (quorum t k1 k2 k3) x 0

-- Key holders 1 and 3 give their share: the tally 7 opens.
law reveal-quorum : revealAt 2 true false true 7 ≡ (true , 7)
reveal-quorum = refl

-- One share is not a quorum: the result is the same for each tally.
law sealed-blind : (x : ℕ) → (y : ℕ) → revealAt 2 false false true x ≡ revealAt 2 false false true y
sealed-blind x y = refl
```

### 4. An amendment keeps Core

```quorum-lang examples/agent/04-amendment.lang
-- Agent example 4 of 5 (S9 O126): an amendment keeps Core. The rules are
-- a pair (t , n): the threshold t and the count n of members. Core holds
-- when 1 is at most t and t is at most n. The amendment adds one member
-- and adds 1 to the threshold. The laws show that it keeps Core.

-- atMost m n is true when m is at most n.
atMost : ℕ → ℕ → Bool
atMost m n = elim (λ (k : ℕ) → ℕ → Bool) (λ (j : ℕ) → true) (λ (k : ℕ) (ih : ℕ → Bool) (j : ℕ) → elim (λ (i : ℕ) → Bool) false (λ (i : ℕ) (r : Bool) → ih i) j) m n

both : Bool → Bool → Bool
both a b = elim (λ (c : Bool) → Bool) b false a

absurd : false ≡ true → (C : Type) → C
absurd p C = primTransp (λ i → elim (λ (b : Bool) → Type) C ℕ (p i)) i0 0

Rules : Type
Rules = ℕ × ℕ

core : Rules → Bool
core s = both (atMost 1 (fst s)) (atMost (fst s) (snd s))

CoreHolds : Rules → Type
CoreHolds s = core s ≡ true

amend : Rules → Rules
amend s = suc (fst s) , suc (snd s)

-- When both a b is true, b is true.
bothRight : (a : Bool) → (b : Bool) → both a b ≡ true → b ≡ true
bothRight a b = elim (λ (c : Bool) → both c b ≡ true → b ≡ true) (λ (h : b ≡ true) → h) (λ (h : false ≡ true) → absurd h (b ≡ true)) a

-- The amendment of (2 , 3) is (3 , 4), and Core holds for it.
law amend-example : CoreHolds (amend (2 , 3))
amend-example = refl

-- The amendment keeps Core.
law amend-keeps-core : (s : Rules) → CoreHolds s → CoreHolds (amend s)
amend-keeps-core s h = bothRight (atMost 1 (fst s)) (atMost (fst s) (snd s)) h
```

### 5. The merge of replicas is a join

```quorum-lang examples/agent/05-replica-merge.lang
-- Agent example 5 of 5 (S9 O126): the merge of two replicas is a join. A
-- replica keeps 2 flags: flag i is true when the replica has the vote of
-- member i. mergeRep takes the join (or) of each flag. A join is
-- commutative, associative and idempotent, thus two replicas agree after
-- they exchange their states in each order.

joinFlag : Bool → Bool → Bool
joinFlag a b = elim (λ (c : Bool) → Bool) true b a

Rep : Type
Rep = Bool × Bool

mergeRep : Rep → Rep → Rep
mergeRep r s = joinFlag (fst r) (fst s) , joinFlag (snd r) (snd s)

law join-comm : (a : Bool) → (b : Bool) → joinFlag a b ≡ joinFlag b a
join-comm a b = elim (λ (x : Bool) → joinFlag x b ≡ joinFlag b x) (elim (λ (y : Bool) → joinFlag true y ≡ joinFlag y true) refl refl b) (elim (λ (y : Bool) → joinFlag false y ≡ joinFlag y false) refl refl b) a

law join-assoc : (a : Bool) → (b : Bool) → (c : Bool) → joinFlag (joinFlag a b) c ≡ joinFlag a (joinFlag b c)
join-assoc a b c = elim (λ (x : Bool) → joinFlag (joinFlag x b) c ≡ joinFlag x (joinFlag b c)) refl refl a

law join-idem : (a : Bool) → joinFlag a a ≡ a
join-idem a = elim (λ (x : Bool) → joinFlag x x ≡ x) refl refl a

-- The merge of two replicas does not depend on the order.
law merge-comm : (r : Rep) → (s : Rep) → mergeRep r s ≡ mergeRep s r
merge-comm r s i = join-comm (fst r) (fst s) i , join-comm (snd r) (snd s) i
```
