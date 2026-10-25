{-# OPTIONS --cubical --safe #-}
open import ThresholdVC.Prelude

-- A denotational design, after Conal Elliott, of a threshold-authorized,
-- self-amending version-control system for an off-chain protocol.
--
-- Method. Give each abstract type a meaning. Then require each
-- representation (ciphertext, share, signature, proof, replica) to map onto
-- that meaning by a homomorphism. The fields named ⟦…⟧ are those
-- homomorphism laws, and they are the whole correctness contract.

module ThresholdVC.Design
  ------------------------------------------------------------------------
  -- §1  Semantic types: what things ARE. No ciphertext, share, signature
  --     or hash appears in this telescope.
  ------------------------------------------------------------------------
  (Artifact  : Type)   -- what a client runs: code plus parameters, by meaning
  (Ballot    : Type)   -- one private input: a choice, a weight or a signal
  (Agenda    : Type)   -- the public question of one round: a proposal or a tick
  (Edit      : Type)   -- a change to the governed state, as syntax
  (Member    : Type)   -- one key-share holder
  (Committee : Type)   -- a body that holds one threshold key
  (Quorum    : Committee → Type)                         -- coalitions that may act for c
  (_∈_       : {c : Committee} → Member → Quorum c → Type)
  -- The language the constitution is written in, and its meaning.
  (Circuit   : Type → Type → Type)
  (run       : {A B : Type} → Circuit A B → A → B)
  ------------------------------------------------------------------------
  -- §2  The governed state, known by its observations.
  ------------------------------------------------------------------------
  (State        : Type)
  (isSetState   : isSet State)
  (height       : State → ℕ)
  (artifact     : State → Artifact)
  (committee    : State → Committee)
  (constitution : State → Agenda → Circuit (FMSet Ballot) (Maybe Edit))
  (⟦_⟧ᵉ         : Edit → State → State)
  -- Every edit advances the height, so no state occurs twice in a history
  -- (a git commit names its parent for the same reason).
  (advance      : (e : Edit) (σ : State) → height (⟦ e ⟧ᵉ σ) ≡ suc (height σ))
  (genesis      : State)
  -- The entrenched clause: a property that no amendment may break.
  (Core         : State → Type)
  (isPropCore   : (σ : State) → isProp (Core σ))
  (core₀        : Core genesis)
  where

-- A Policy is what a constitution means. Its input is a bag, so every
-- Policy ignores ballot order and sees no voter identity. The path
-- constructor `comm` enforces this; no proof obligation remains.
Policy : Type
Policy = Agenda → FMSet Ballot → Maybe Edit

-- The rules in force at σ are the meaning of σ's own constitution code.
-- An Edit may replace that code: this is self-amendment.
rules : State → Policy
rules σ a = run (constitution σ a)

------------------------------------------------------------------------
-- §3  One governance step. The rules of the SOURCE state choose the edit
--     from a bag of ballots. The step must keep Core.
------------------------------------------------------------------------
record Step (σ σ' : State) : Type where
  constructor step
  field
    agenda : Agenda
    bag    : FMSet Ballot
    edit   : Edit
    chosen : rules σ agenda bag ≡ just edit
    lands  : ⟦ edit ⟧ᵉ σ ≡ σ'
    keeps  : Core σ → Core σ'   -- the slot for a Lean proof or a ZK-attested check

------------------------------------------------------------------------
-- §4  History. Reach σ is the version-control object: a rooted path of
--     steps. It records every bag, so no client ever holds it.
------------------------------------------------------------------------
infixl 5 _▸_
data Reach : State → Type where
  root : Reach genesis
  _▸_  : {σ σ' : State} → Reach σ → Step σ σ' → Reach σ'

-- What a client may know: σ descends from genesis. The path, the bags and
-- the intermediate states stay hidden.
Legit : State → Type
Legit σ = ∥ Reach σ ∥₁

reach→core : {σ : State} → Reach σ → Core σ
reach→core root    = core₀
reach→core (h ▸ s) = Step.keeps s (reach→core h)

legit→core : {σ : State} → Legit σ → Core σ
legit→core {σ} = rec₁ (isPropCore σ) reach→core

------------------------------------------------------------------------
-- §5  Threshold authorization.
------------------------------------------------------------------------
module Authority
  (Honest   : Member → Type)
  (Endorses : Member → State → State → Type)   -- i released its share for σ ↦ σ'
  -- The threshold assumption, as one quorum-system law: two quorums of one
  -- committee share an honest member. With n members, threshold t and at
  -- most f corrupt, 2t > n + f gives it.
  (honest-meet : {c : Committee} (q r : Quorum c)
               → ∃[ i ꞉ Member ] (i ∈ q × i ∈ r × Honest i))
  -- What honesty means. An honest member endorses only a step it checked,
  -- and endorses at most one successor of any state.
  (faithful : {i : Member} {σ σ' : State}
            → Honest i → Endorses i σ σ' → ∥ Step σ σ' ∥₁)
  (single   : {i : Member} {σ a b : State}
            → Honest i → Endorses i σ a → Endorses i σ b → a ≡ b)
  where

  -- A certificate on σ ↦ σ' MEANS: some quorum of σ's committee endorsed
  -- it. The truncation records that the certificate does not name the
  -- quorum (a FROST signature does not depend on the signing set).
  Authorized : State → State → Type
  Authorized σ σ' =
    ∃[ q ꞉ Quorum (committee σ) ] ((i : Member) → i ∈ q → Endorses i σ σ')

  honest-in : {c : Committee} (q : Quorum c) → ∃[ i ꞉ Member ] (i ∈ q × Honest i)
  honest-in q =
    rec₁ squash₁ (λ { (i , i∈q , _ , hi) → ∣ i , i∈q , hi ∣₁ }) (honest-meet q q)

  -- Soundness: a certificate implies a real step.
  sound : {σ σ' : State} → Authorized σ σ' → ∥ Step σ σ' ∥₁
  sound = rec₁ squash₁ λ { (q , all) →
          rec₁ squash₁ (λ { (i , i∈q , hi) → faithful hi (all i i∈q) }) (honest-in q) }

  -- No fork: a committee cannot certify two successors of one state.
  -- This replaces the blockchain. Order comes from honest members who
  -- refuse to sign twice, plus quorum intersection.
  no-fork : {σ a b : State} → Authorized σ a → Authorized σ b → a ≡ b
  no-fork {a = a} {b} A B =
    rec₁ P (λ { (q , qa) →
    rec₁ P (λ { (r , rb) →
    rec₁ P (λ { (i , i∈q , i∈r , hi) → single hi (qa i i∈q) (rb i i∈r) })
           (honest-meet q r) }) B }) A
    where P = isSetState a b

  ----------------------------------------------------------------------
  -- §6  Certified descent: what anyone can check with public data.
  ----------------------------------------------------------------------
  infix  4 _⊑_
  infixl 5 _⊳_
  data _⊑_ (σ : State) : State → Type where
    here : σ ⊑ σ
    _⊳_  : {τ τ' : State} → σ ⊑ τ → Authorized τ τ' → σ ⊑ τ'

  -- Signature checks alone establish legitimacy.
  certified→legit : {σ : State} → genesis ⊑ σ → Legit σ
  certified→legit here    = ∣ root ∣₁
  certified→legit (c ⊳ a) =
    rec₁ squash₁ (λ h → rec₁ squash₁ (λ s → ∣ h ▸ s ∣₁) (sound a)) (certified→legit c)

  certified→core : {σ : State} → genesis ⊑ σ → Core σ
  certified→core = legit→core ∘ certified→legit

  -- The meaning of a replica: a certified point of history. By no-fork the
  -- certified points form one chain, so two of them always have a join.
  Tip : Type
  Tip = Σ State (genesis ⊑_)

  record Replica : Type₁ where
    field
      Rep   : Type
      none  : Rep
      merge : Rep → Rep → Rep   -- gossip, e.g. union of certificate sets
      ⟦_⟧   : Rep → Tip
      -- ⟦_⟧ is a join-semilattice morphism: merge MEANS the join of tips.
      ⟦none⟧   : fst ⟦ none ⟧ ≡ genesis
      ⟦merge⟧ˡ : (r s : Rep) → fst ⟦ r ⟧ ⊑ fst ⟦ merge r s ⟧
      ⟦merge⟧ʳ : (r s : Rep) → fst ⟦ s ⟧ ⊑ fst ⟦ merge r s ⟧
      ⟦merge⟧ᵘ : (r s : Rep) (τ : State)
               → fst ⟦ r ⟧ ⊑ τ → fst ⟦ s ⟧ ⊑ τ → fst ⟦ merge r s ⟧ ⊑ τ

    -- What a node runs, and when two nodes may talk.
    current : Rep → Artifact
    current = artifact ∘ fst ∘ ⟦_⟧

    Agree : Rep → Rep → Type
    Agree r s = fst ⟦ r ⟧ ≡ fst ⟦ s ⟧

------------------------------------------------------------------------
-- §7  Private computation. FHE ciphertexts and MPC sharings are two
--     representations of one meaning: the hidden value. No single party
--     computes ⟦_⟧; it fixes what each operation must do.
------------------------------------------------------------------------
record Private (c : Committee) : Type₁ where
  infixl 6 _⊕_
  field
    Hidden : Type → Type
    ⟦_⟧    : {A : Type} → Hidden A → A
    cast   : Ballot → Hidden (FMSet Ballot)   -- encrypt or share one ballot
    ∅      : Hidden (FMSet Ballot)
    _⊕_    : Hidden (FMSet Ballot) → Hidden (FMSet Ballot) → Hidden (FMSet Ballot)
    eval   : {A B : Type} → Circuit A B → Hidden A → Hidden B
    reveal : {A : Type} → Quorum c → Hidden A → A   -- threshold decrypt, or open
    -- ⟦_⟧ is a homomorphism for each operation.
    ⟦cast⟧   : (b : Ballot) → ⟦ cast b ⟧ ≡ b ∷ []
    ⟦∅⟧      : ⟦ ∅ ⟧ ≡ []
    ⟦⊕⟧      : (x y : Hidden (FMSet Ballot)) → ⟦ x ⊕ y ⟧ ≡ ⟦ x ⟧ ++ ⟦ y ⟧
    ⟦eval⟧   : {A B : Type} (f : Circuit A B) (x : Hidden A)
             → ⟦ eval f x ⟧ ≡ run f ⟦ x ⟧
    ⟦reveal⟧ : {A : Type} (q : Quorum c) (x : Hidden A) → reveal q x ≡ ⟦ x ⟧

------------------------------------------------------------------------
-- §8  A round, two ways. Both compute the Policy of §1. They differ only
--     in what they reveal.
------------------------------------------------------------------------
-- d reveals no more than e when d factors through e.
infix 4 _≼_
_≼_ : {D E : Type} → (FMSet Ballot → D) → (FMSet Ballot → E) → Type
_≼_ {D} {E} d e = Σ (E → D) λ g → (b : FMSet Ballot) → d b ≡ g (e b)

module Round {c : Committee} (P : Private c) where
  open Private P

  -- MPC: run the constitution itself on the hidden bag; open the outcome only.
  tallyᴹ : State → Agenda → Quorum c → Hidden (FMSet Ballot) → Maybe Edit
  tallyᴹ σ a q box = reveal q (eval (constitution σ a) box)

  tallyᴹ-correct : ∀ σ a q box → tallyᴹ σ a q box ≡ rules σ a ⟦ box ⟧
  tallyᴹ-correct σ a q box = ⟦reveal⟧ q _ ∙ ⟦eval⟧ (constitution σ a) box

  -- FHE: aggregate under encryption, open the aggregate, decide in public.
  -- Correct for any constitution that factors through the aggregate.
  module Aggregate {M : Type}
    (agg     : Circuit (FMSet Ballot) M)
    (decide  : State → Agenda → M → Maybe Edit)
    (factors : ∀ σ a b → rules σ a b ≡ decide σ a (run agg b))
    where

    tallyᶠ : State → Agenda → Quorum c → Hidden (FMSet Ballot) → Maybe Edit
    tallyᶠ σ a q box = decide σ a (reveal q (eval agg box))

    tallyᶠ-correct : ∀ σ a q box → tallyᶠ σ a q box ≡ rules σ a ⟦ box ⟧
    tallyᶠ-correct σ a q box =
      cong (decide σ a) (⟦reveal⟧ q _ ∙ ⟦eval⟧ agg box) ∙ sym (factors σ a ⟦ box ⟧)

    -- The MPC route reveals no more than the FHE route.
    mpc≼fhe : ∀ σ a → rules σ a ≼ run agg
    mpc≼fhe σ a = decide σ a , factors σ a

------------------------------------------------------------------------
-- §9  Proofs. A verified zero-knowledge proof MEANS the truncated
--     existence of a witness: the verifier learns that one exists, not
--     which one.
------------------------------------------------------------------------
record ZK {X : Type} (Witness : X → Type) : Type₁ where
  field
    Proof    : X → Type
    verify   : (x : X) → Proof x → Bool
    prove    : (x : X) → Witness x → Proof x
    complete : (x : X) (w : Witness x) → verify x (prove x w) ≡ true
    ⟦_⟧      : {x : X} (π : Proof x) → verify x π ≡ true → ∥ Witness x ∥₁

-- Recursive composition (IVC): a proof about σ whose meaning is Legit σ.
-- Legit σ is a proposition, so the meaning holds no data about the history.
-- That is the denotational reason a constant-size proof can exist.
record IVC : Type₁ where
  field
    Proof   : State → Type
    verify  : (σ : State) → Proof σ → Bool
    start   : Proof genesis
    extend  : {σ σ' : State} → Proof σ → Step σ σ' → Proof σ'
    start✓  : verify genesis start ≡ true
    extend✓ : {σ σ' : State} (π : Proof σ) (s : Step σ σ')
            → verify σ π ≡ true → verify σ' (extend π s) ≡ true
    ⟦_⟧     : {σ : State} (π : Proof σ) → verify σ π ≡ true → Legit σ

  -- Completeness for a whole history follows from the two local laws.
  prove : {σ : State} → Reach σ → Σ (Proof σ) λ π → verify σ π ≡ true
  prove root    = start , start✓
  prove (h ▸ s) = extend (fst (prove h)) s , extend✓ (fst (prove h)) s (snd (prove h))

------------------------------------------------------------------------
-- §10  Membership change. Resharing changes who holds the shares, never
--      what they mean. The group public key, which clients pin, stays the
--      same across committees.
------------------------------------------------------------------------
record Sharing : Type₁ where
  field
    Secret    : Type
    Shares    : Committee → Type
    ⟦_⟧       : {c : Committee} → Shares c → Secret
    reshare   : {c : Committee} → Quorum c → (c' : Committee) → Shares c → Shares c'
    ⟦reshare⟧ : {c : Committee} (q : Quorum c) (c' : Committee) (s : Shares c)
              → ⟦ reshare q c' s ⟧ ≡ ⟦ s ⟧
