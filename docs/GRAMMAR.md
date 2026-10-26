# Grammar (S3 surface)

quorum-lang has an Agda-like Unicode surface (ruling Q13 (b),
2026-10-25). Each operation has one canonical spelling. `langc fmt FILE`
prints the canonical text of FILE. `langc check` accepts some other
spellings, and gives the warning W_NONCANON with the canonical text as
`fix` (docs/DIAGNOSTICS.md).

## Lexical rules

- The source is UTF-8. A comment starts with `--` and fills the line.
- A name starts with an ASCII letter, `_` or a byte of 0x80 or more, and
  continues with ASCII letters, digits, `_`, `'`, subscript digits
  `₀`..`₉` and bytes of 0x80 or more. A `-` is a name character when a
  name start follows it: `ℓ-max` is one name, and `x-1` gives LEX_CHAR.
  `x->y` is the name `x`, the symbol `->` and the name `y`.
- S3: `+`, `[` and `]` are also name characters, and a name can start
  with them. Thus `_++_`, `[]` and `++-assoc` are names.
- The code points `→`, `λ`, `×`, `Σ`, `≡`, `∧` and `∨` are symbols, not
  name characters. Thus `ℕ` and `ℓ` are names.
- A ℕ literal is decimal, from 0 to 2^64 - 1. A letter directly after a
  literal gives LEX_CHAR.
- Keywords: `data`, `record`, `coinductive`, `module`, `law`, `where`,
  `postulate`, `let`, `in`, `Type`. `Type` with subscript digits
  (`Type₁`) is the universe at that level. `Type` is level 0.
- Symbols: `:` `=` `(` `)` `→` `λ` `×` `Σ` `≡` `~` `∧` `∨` `,` `{` `}`
  `;`.
- S3 reserved names: `∷`, `++`, `∘`, `∙` (the operators), `∥`, `∥₁`,
  `∃[`, `꞉` and `]`. A reserved name is a token only when it is the full
  name, as a keyword: `x∷xs` is one name, and `x ∷ xs` is the operator.
  The names `_∷_`, `_++_`, `_∘_`, `_∙_`, `∥_∥₁`, `∣_∣₁`, `∃` and `[]` are
  not reserved.

## Grammar

```
file   := item*
item   := comment | decl
decl   := def
        | 'postulate' NAME ':' term
        | 'data' NAME group* ':' (atom '→')* TYPE 'where' NL ('  ' ctor NL)+
        | 'record' NAME group* ':' TYPE 'where' NL ('  ' 'coinductive' NL)?
            ('  ' NAME ':' term NL)+
        | 'module' NAME group* 'where' NL def+
def    := 'law'? NAME ':' term NL NAME NAME* '=' term
ctor   := NAME ':' (group '→')* result
result := NAME NAME* atom*
        | term
term   := 'let' NAME '=' term 'in' term
        | 'λ' '{' cell (';' cell)* '}'
        | 'λ' binder+ '→' term
        | '∃[' NAME '꞉' term ']' term
        | group '→' term
        | equiv ',' term
        | equiv ('→' term)?
cell   := face+ '→' term
face   := '(' NAME '=' ('i0' | 'i1') ')'
equiv  := oper ('≡' oper)?
oper   := times (OP oper)?
times  := max ('×' times)?
max    := min ('∨' max)?
min    := neg ('∧' min)?
neg    := '~' neg | app
app    := 'Type' atom | atom atom*
atom   := NAME | NAT | TYPE | '(' term ')' | 'Σ' atom atom
        | '∥' term '∥₁'
TYPE   := 'Type' | 'Type₁'
OP     := '∷' | '++' | '∘' | '∙'
binder := NAME | group
group  := '(' NAME ':' term ')'
```

S3 rewrites at parse time: `l OP r` is `_OP_ l r` (thus `x ∷ xs` is
`_∷_ x xs`); `∥ t ∥₁` is `∥_∥₁ t`; `∃[ x ꞉ A ] B` is
`∃ A (λ (x : A) → B)`, and `B` extends to the right as the body of a λ.
The four operators have one level, between `≡` and `×`, and associate to
the right: `x ∷ y ++ z` is `x ∷ (y ++ z)`. There is no general mixfix.
S3 has no implicit arguments, so a polymorphic operator takes its type
parameters: write `_++_ A xs ys`, or use the infix form in a module
section that gives the parameters.

- A definition is a signature line and one clause line. The clause names
  the parameters: `square n = natMul n n`.
- Precedence, from the loosest to the tightest: `,` and `→` (right
  associative); `≡` (not associative: `a ≡ b ≡ c` is not a term); `×`,
  `∨` and `∧` (right associative); the prefix `~`; application. Thus
  `a , b → c` is `a , (b → c)`, and `~ p i` is `~ (p i)`.
- `let x = t in u` binds one name. The checker finds the type of `x`
  from `t` (else TYPE_INFER). S2 has no type annotation on a `let`. For
  two names, write a `let` in the body of a `let`. The body `u` extends
  to the end of the term.
- `Σ A (λ x → B)` is the dependent pair type. `A × B` is the pair type
  where `B` does not use the first part. `a , b` is a pair, and `fst p`
  and `snd p` are its parts.
- Paths. `PathP L a b` is the type of a path over the line `L` (a
  function from `I` to a type) from `a` to `b`. `a ≡ b` is
  `PathP (λ _ → A) a b`, and the checker finds `A` from `a` (or from
  `b`). A path is `λ i → t` where the type is a `PathP`. TYPE_ENDPOINT
  gives an end that does not agree with the type. `p r` applies the path
  `p` to the interval term `r`. `refl` is the constant path.
- Interval. `I` is the interval. `i0` and `i1` are its ends. `~ r` is
  the reversal, `r ∧ s` the meet and `r ∨ s` the join.
- Kan operations. `primTransp (λ i → A) r u` transports `u` along the
  line `λ i → A`. `primHComp (λ j → λ { (i = i0) → a ; (i = i1) → q j }) u0`
  is the homogeneous composition of the base `u0` with the side. A system
  `λ { ... }` is correct only as this side of `primHComp` (TYPE_SYSTEM).
  A cell with two or more faces, `(i = i1) (j = i0) → t`, has the
  conjunction of its faces.
- Levels. `Level` is the type of levels, with `lzero`, `lsuc` and
  `ℓ-max`. `Type ℓ` is the universe at the level `ℓ`. `ℓ` must have a
  closed normal form, at most 1 (TYPE_UNIVERSE). S2 has no level
  variables.
- Data. The groups before `:` are the parameters. The types before
  `Type` are the indices. A point constructor names each field. Its
  result is the data type, applied to the parameters in order, then to
  one atom for each index. A path constructor has the result `s ≡ t`
  over two point terms (a 1-cell), or `p ≡ q` over two path fields (a
  2-cell). Only a cell signature can have a path constructor (rule R1).
- The checker sorts a program data type in this order (rules R1 and R2):
  1. It has a type parameter (a parameter whose type ends in `Type`): it
     must be a cell signature, else REFUSE_CELL.
  2. It has an index whose type ends in `Type`: REFUSE_CELL.
  3. It has value parameters or indices: an indexed family.
  4. It has no parameters and no indices: REFUSE_DATA. Only
     domain/domain.lang can declare closed data (a base type).
- Records. A record is the named `Σ` type of its fields. `R p` unfolds
  to the `Σ` of the field types, and a value is a pair `a , b , c`. Each
  field name is a global projection. A field type that is a type
  constructor (for example `F : Type → Type`) gives REFUSE_CELL. A
  `coinductive` record gives REFUSE_CELL (rule R1, Q1 (b)). A record
  head with indices gives PARSE_EXPECT.
- Modules. `module M (p : A) where` starts a parameter section. Each
  line of each definition in the section starts with 2 spaces. The
  section ends at the first line at column 1. A section holds only
  definitions (PARSE_EXPECT). In the section, a use of an earlier
  definition of the same section takes the section parameters. Outside
  the section, a definition of the section takes the section parameters
  first, as explicit arguments: `twice₀ ℕ (λ n → suc n) 3`. A module
  name is not a global name. S2 has no qualified names.
- A guest operator name, for example `_∈_`, is not mixfix: S3 has no
  general mixfix. Only the fixed S3 operators `∷`, `++`, `∘` and `∙`
  are infix (O41). Write `_∈_ b bs`.
- A `postulate` gives REFUSE_AXIOM.
- Laws (S4 O64). The keyword `law` before a signature marks the
  definition as a law, at the top level or in a module:
  `law reach-core : (σ : State) → Reach σ → Core σ`. The clause has no
  `law`. A law is discharged when its definition checks: R2 refuses a
  `postulate`, so a checked law has a proof. `langc laws PROG` prints
  `law NAME discharged` (or `open`) for each law in source order, then
  `laws: D of T discharged`. The exit is 0 only when the program
  checks and D = T. The summary of `langc check --json` has
  `"laws":{"discharged":D,"total":T}`. `fmt` prints `law NAME : TYPE`.

## Canonical form

`langc fmt` prints:

- each definition as the signature line, then the clause line;
- at most one blank line between two items, and only where the source
  has a blank line;
- each comment line as it is, at column 1; a comment in a declaration
  moves to the line after the declaration;
- nested λ terms as one λ: `λ x y → t`;
- one name in each binder group, and one group for each `→`;
- `A × B`, `a ≡ b`, `a , b`, `r ∧ s` and `r ∨ s` as infix, and `~ r`
  with one space;
- `_∷_`, `_++_`, `_∘_` and `_∙_` applied to two arguments as infix
  (`x ∷ xs`), and applied to more arguments in prefix form
  (`_∘_ f g n`);
- `∥_∥₁ A` as `∥ A ∥₁`, but a constructor result in prefix form
  (`∣_∣₁ : (a : A) → ∥_∥₁ A`);
- `∃ A (λ (x : A) → B)` as `∃[ x ꞉ A ] B` when the binder type is the
  same term as `A`, else in prefix form;
- parentheses only where the precedence needs them, and on each argument
  of an application that is not an atom;
- a `let` on one line: `let x = t in u`;
- a system on one line: `λ { (i = i0) → a ; (i = i1) → b }`;
- each index type of a data head as an atom: `(A × B) → Type`;
- constructors, record fields, the `coinductive` line, and each line of
  a definition in a module, indented by 2 spaces.

## Spellings that give W_NONCANON

| Input | Canonical |
|---|---|
| `->` | `→` |
| `\` | `λ` |
| `Type 0`, `Type₀`, `Type 1` | `Type`, `Type`, `Type₁` |
| `(x y : A) → B` | `(x : A) → (y : A) → B` |
| `f = λ x → t` | `f x = t` |
| `_∷_ x xs` (also `_++_`, `_∘_`, `_∙_`) | `x ∷ xs` |
| `∃ A (λ (x : A) → B)` | `∃[ x ꞉ A ] B` |

Other text that is not in the canonical form (spaces, line breaks,
indentation, parentheses) also gives W_NONCANON. S2 adds no ASCII
spelling: `×`, `Σ`, `≡`, `∧` and `∨` have no ASCII form. S3 adds no
ASCII spelling: the operators and the notations have no ASCII form.

The S0 keywords `def`, `fun`, `=>`, `:=`, `family`, `axiom`, `Sigma` and
`*` are not accepted. They give PARSE_EXPECT.

## Names

S1 renames the kit names to the design names:

| S0 name | S1 name |
|---|---|
| `Flag`, `flagYes`, `flagNo` | `Bool`, `true`, `false` |
| `Nat` | `ℕ` |
| `Option`, `none`, `some` | `Maybe`, `nothing`, `just` |
| `Prod` | `_×_` (written `A × B`) |
| `family` | `data` |
| `axiom` | `postulate` |
| `Sigma` | `Σ` |

S1 adds `suc n` (that is, `natAdd n 1`).

S2 renames:

| S1 name | S2 name |
|---|---|
| `pair`, `pack` | `_,_` (written `a , b`) |
| `first`, `witness` | `fst` |
| `second`, `payload` | `snd` |
| `Eq` | `_≡_` (written `a ≡ b`), or `PathP` |
| `symm` | `sym`, a guest definition in `examples/paths.lang` |
| `trans`, `cong`, `transport` | guest definitions in `examples/paths.lang` |

An S1 name in the left column gives NAME_UNKNOWN in S2. `refl` stays: it
is the constant path. `_×_` stays: it is a `Σ` type now. These kit names
do not change in S2: `fold`, `map`, `bind`, `pure`, `option`, `flagIf`
and the `nat` operations.

S2 adds the kernel names `I`, `i0`, `i1`, `~_`, `_∧_`, `_∨_`, `PathP`,
`_≡_`, `primTransp`, `primHComp`, `_,_`, `fst`, `snd`, `Level`,
`lzero`, `lsuc` and `ℓ-max`.

S3 adds the kernel names `elim` (the dependent eliminator for closed
data: `elim P c_1 .. c_n x`) and `foldᴮ` (the bag recursor:
`foldᴮ f swap st b xs` for a bag-shaped cell monad, else TYPE_BAG).
`fold` also takes a cell monad with path constructors: one case for each
constructor, in order.

Refused names:

- `List`, `cons`, `nil`, `unfold`: REFUSE_CELL. A cons-form list is not a
  cell monad (rule R1).
- `Sum`, `inl`, `inr`, `either`, `filter`: REFUSE_BASE. They are not in
  the design (rule R2). `filter` is derived:
  `bind m (λ x → flagIf (p x) (just x) nothing)`.
