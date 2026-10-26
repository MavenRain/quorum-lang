# Grammar (S1 surface)

quorum-lang has an Agda-like Unicode surface (ruling Q13 (b),
2026-10-25). Each operation has one canonical spelling. `langc fmt FILE`
prints the canonical text of FILE. `langc check` accepts some other
spellings, and gives the warning W_NONCANON with the canonical text as
`fix` (docs/DIAGNOSTICS.md).

## Lexical rules

- The source is UTF-8. A comment starts with `--` and fills the line.
- A name starts with an ASCII letter, `_` or a byte of 0x80 or more, and
  continues with ASCII letters, digits, `_`, subscript digits `₀`..`₉`
  and bytes of 0x80 or more. The code points `→`, `λ`, `×` and `Σ` are
  symbols, not name characters. Thus `ℕ` is a name.
- A ℕ literal is decimal, from 0 to 2^64 - 1.
- Keywords: `data`, `where`, `postulate`, `Type`. `Type` with subscript
  digits (`Type₁`) is the universe at that level. `Type` is level 0.
- Symbols: `:` `=` `(` `)` `→` `λ` `×` `Σ`.

## Grammar

```
file   := item*
item   := comment | decl
decl   := NAME ':' term NL NAME NAME* '=' term
        | 'postulate' NAME ':' term
        | 'data' NAME group* ':' 'Type' 'where' NL ('  ' ctor NL)+
ctor   := NAME ':' ('(' NAME ':' term ')' '→')* NAME NAME*
term   := 'λ' binder+ '→' term
        | '(' NAME ':' term ')' '→' term
        | 'Σ' atom atom
        | times ('→' term)?
times  := app ('×' times)?
app    := atom atom*
atom   := NAME | NAT | 'Type' | 'Type₁' | '(' term ')'
binder := NAME | '(' NAME ':' term ')'
group  := '(' NAME ':' term ')'
```

- A definition is a signature line and one clause line. The clause names
  the parameters: `square n = natMul n n`.
- `A → B` and `A × B` are right associative. `×` binds tighter than `→`.
- `Σ A (λ x → B)` is the dependent pair type.
- A constructor names each field. Its result is the data type, applied
  to the parameters of the data type in order.
- Only domain/domain.lang can declare a data type (REFUSE_DATA). A
  `postulate` gives REFUSE_AXIOM.

## Canonical form

`langc fmt` prints:

- each definition as the signature line, then the clause line;
- at most one blank line between two items, and only where the source
  has a blank line; each comment line as it is;
- nested λ terms as one λ: `λ x y → t`;
- one name in each binder group, and one group for each `→`;
- `A × B` as infix;
- parentheses on an argument that is an application, a λ, a `→` type or
  a `Σ` type, and on a `→` domain that is a λ, a `→` type or a `Σ` type;
- constructors indented by 2 spaces.

## Spellings that give W_NONCANON

| Input | Canonical |
|---|---|
| `->` | `→` |
| `\` | `λ` |
| `Type 0`, `Type 1` | `Type`, `Type₁` |
| `(x y : A) → B` | `(x : A) → (y : A) → B` |
| `f = λ x → t` | `f x = t` |

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

S1 adds `suc n` (that is, `natAdd n 1`). These kit names do not change in
S1: `pair`, `first`, `second`, `pack`, `witness`, `payload`, `Eq`,
`refl`, `symm`, `trans`, `cong`, `transport`, `fold`, `map`, `bind`,
`pure`, `flagIf` and the `nat` operations.

Refused names:

- `List`, `cons`, `nil`, `unfold`: REFUSE_CELL. A cons-form list is not a
  cell monad (rule R1).
- `Sum`, `inl`, `inr`, `either`, `filter`: REFUSE_BASE. They are not in
  the design (rule R2). `filter` is derived:
  `bind m (λ x → flagIf (p x) (just x) nothing)`.
