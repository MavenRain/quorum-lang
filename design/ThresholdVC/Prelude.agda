{-# OPTIONS --cubical --safe #-}
-- Builtins only. Names follow the agda/cubical library, so the design
-- reads the same against it.
module ThresholdVC.Prelude where

open import Agda.Primitive public
  using (Level; lzero; lsuc) renaming (Set to Type; _⊔_ to ℓ-max)
open import Agda.Primitive.Cubical public
  using (I; i0; i1; primHComp; primTransp) renaming (primINeg to ~_)
open import Agda.Builtin.Cubical.Path public using (_≡_)
open import Agda.Builtin.Sigma public using (Σ; _,_; fst; snd)
open import Agda.Builtin.Bool public using (Bool; true; false)
open import Agda.Builtin.Nat public using (suc) renaming (Nat to ℕ)
open import Agda.Builtin.Maybe public using (Maybe; nothing; just)

private variable
  ℓ ℓ' ℓ'' : Level
  A : Type ℓ
  B : Type ℓ'
  C : Type ℓ''

infixr 9 _∘_
infixr 30 _∙_
infixr 2 _×_
infixr 5 _∷_ _++_

_∘_ : (B → C) → (A → B) → A → C
(g ∘ f) x = g (f x)

sym : {x y : A} → x ≡ y → y ≡ x
sym p i = p (~ i)

cong : (f : A → B) {x y : A} → x ≡ y → f x ≡ f y
cong f p i = f (p i)

_∙_ : {x y z : A} → x ≡ y → y ≡ z → x ≡ z
(p ∙ q) i = primHComp (λ j → λ { (i = i0) → p i0 ; (i = i1) → q j }) (p i)

isProp : Type ℓ → Type ℓ
isProp A = (x y : A) → x ≡ y

isSet : Type ℓ → Type ℓ
isSet A = (x y : A) → isProp (x ≡ y)

_×_ : Type ℓ → Type ℓ' → Type (ℓ-max ℓ ℓ')
A × B = Σ A (λ _ → B)

-- Propositional truncation: one exists, and you may not ask which.
data ∥_∥₁ (A : Type ℓ) : Type ℓ where
  ∣_∣₁    : A → ∥ A ∥₁
  squash₁ : isProp ∥ A ∥₁

rec₁ : isProp B → (A → B) → ∥ A ∥₁ → B
rec₁ P f ∣ a ∣₁           = f a
rec₁ P f (squash₁ x y i) = P (rec₁ P f x) (rec₁ P f y) i

∃ : (A : Type ℓ) → (A → Type ℓ') → Type (ℓ-max ℓ ℓ')
∃ A B = ∥ Σ A B ∥₁
syntax ∃ A (λ x → B) = ∃[ x ꞉ A ] B

-- Finite multisets: the free commutative monoid, as a higher inductive type.
data FMSet (A : Type ℓ) : Type ℓ where
  []    : FMSet A
  _∷_   : A → FMSet A → FMSet A
  comm  : (x y : A) (xs : FMSet A) → x ∷ y ∷ xs ≡ y ∷ x ∷ xs
  trunc : isSet (FMSet A)

-- The only way out of a bag: an order-blind fold into a set.
module _ (S : isSet B) (e : B) (f : A → B → B)
         (sw : (x y : A) (b : B) → f x (f y b) ≡ f y (f x b)) where
  foldᴮ : FMSet A → B
  foldᴮ []                    = e
  foldᴮ (x ∷ xs)              = f x (foldᴮ xs)
  foldᴮ (comm x y xs i)       = sw x y (foldᴮ xs) i
  foldᴮ (trunc xs ys p q i j) =
    S (foldᴮ xs) (foldᴮ ys) (λ k → foldᴮ (p k)) (λ k → foldᴮ (q k)) i j

_++_ : FMSet A → FMSet A → FMSet A
xs ++ ys = foldᴮ trunc ys _∷_ comm xs
