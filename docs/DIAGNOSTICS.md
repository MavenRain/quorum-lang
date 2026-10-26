# Diagnostics

Each failure of `langc` has one stable code. This file lists each code,
what it means, how to repair the cause, and the `retry` value of
`langc check --json`. The gate (test/gate.sh) fails when a code in this
file has no fixture, or when a code in src/ has no row here.

## Text form

`langc check FILE` prints `ok` and exits 0, or prints one line
`langc: CODE: WHERE: MESSAGE` on stderr. WHERE is the definition name,
the file position `FILE:LINE:COL`, or `-`. W_NONCANON is a warning: it
comes after any error, and it does not change the exit code.

Exit codes: 0 for success (W_NONCANON alone included); 2 for USAGE, IO,
IO_SIZE and EVAL_ARGS; 1 for the other failures. For EVAL_OVERFLOW,
`langc eval` prints `trap` on stdout and the code on stderr.

## JSON form

`langc check --json FILE` prints one JSON object on stdout for each
diagnostic, then one summary line. The keys come in this order:

```
{"code":C,"span":S,"expected":E,"found":F,"fix":X,"retry":R,"message":M}
{"parsed":P,"typed":T,"laws":{"discharged":0,"total":0}}
```

- `span` is `{"file":F,"line":L,"col":C,"endLine":EL,"endCol":EC}`, or
  `null` when no file position applies (IO, IO_SIZE and USAGE). Lines
  and columns count from 1.
  A column counts code points, not bytes. `endCol` is the column after
  the last code point of the span.
- `expected`, `found` and `fix` are strings or `null`. PARSE_EXPECT gives
  `expected` and `found` (the two tokens). W_NONCANON gives the canonical
  line, the source line and the full canonical text as `fix`.
- `retry` is `true` when the author can repair the program and check
  again: the LEX_, PARSE_, NAME_, TYPE_ and W_ codes. It is `false` for
  the other codes.
- `parsed` is the number of program definitions that parse before the
  first parse error. `typed` is the number of program definitions that
  type check before the first failure. The two counts include only the
  program file, not domain/domain.lang.

Span rules:

- LEX_* and PARSE_EXPECT: the byte or token at the failure.
  PARSE_DEPTH: one point at the token that is too deep.
- NAME_UNKNOWN, REFUSE_BASE, REFUSE_CELL: the name.
- REFUSE_AXIOM, REFUSE_DATA, REFUSE_NAME, REFUSE_REC: one point at the
  start of the declaration.
- TYPE_*: the term that the message names. A type error at an
  application is one point at the application.
- W_NONCANON: from the first column that is not canonical to the end of
  the file (`endLine` is the last line plus 1, `endCol` is 1).

## Codes

| Code | Meaning | Fix | Retry |
|---|---|---|---|
| `LEX_CHAR` | The lexer found a byte that does not start a token. | Remove the byte, or write a token of docs/GRAMMAR.md. | true |
| `LEX_NAT_RANGE` | A ℕ literal is larger than 2^64 - 1. | Write a smaller literal. | true |
| `PARSE_EXPECT` | The parser found a token that is not correct at this position. `expected` and `found` give the two tokens. Examples: a `module` that holds a line that is not a definition indented by 2 spaces, or a `record` head with indices. | Write the expected token. docs/GRAMMAR.md gives each form. A module holds definitions only. | true |
| `PARSE_DEPTH` | Terms nest deeper than 1000 levels. | Move a part of the term into a new definition. | true |
| `NAME_UNKNOWN` | The name is not in the domain, the core table, or a declaration above the use. | Correct the spelling, or declare the name above its use. | true |
| `TYPE_MISMATCH` | The term has a type that is not the expected type. | Change the term or the declared type. The message gives the two types. | true |
| `TYPE_ARITY` | A core operation has a number of arguments that is not correct. | Give the number of arguments that the message states. | true |
| `TYPE_INFER` | The checker cannot find the type of the term. Examples: a λ binder with no type, or `nothing` with no declared type. | Write the binder type, `λ (x : A) → t`, or a type signature. | true |
| `TYPE_NOT_FUNCTION` | A term that is not a function has an argument. | Remove the argument, or apply a function. | true |
| `TYPE_ENDPOINT` | A path `λ i → t` does not have the ends that its type `PathP L a b` needs: `t` at `i0` is not `a`, or `t` at `i1` is not `b`. | Change the body of the path, or change the ends in its type. | true |
| `TYPE_REFL` | `refl` cannot prove the equality: the two sides have different normal forms. | Correct the equality, or prove it with a path from the guest `sym`, `trans`, `cong` or `transport` (`examples/paths.lang`). | true |
| `TYPE_SYSTEM` | A system `λ { ... }` is not correct. Two cells do not agree where their faces meet, a cell at `j = i0` is not the base of `primHComp`, a face names a term that is not a variable of type `I`, or the system is not in the side `λ j → λ { ... }` of `primHComp`. | Change the cells so that they agree on each overlap and at the base, or put the system in the side of `primHComp`. | true |
| `TYPE_UNIVERSE` | The universe level is above the largest level, 1. Or the level `ℓ` of `Type ℓ` is not closed: S2 has no level variables. | Write `Type` or `Type₁`, or a closed level that you make with `lzero`, `lsuc` and `ℓ-max`. | true |
| `REFUSE_AXIOM` | A `postulate` has no proof (rule R2). | Write a definition with a proof term. | false |
| `REFUSE_BASE` | The name is not a base type or an operation of the design (rule R2): `Sum`, `inl`, `inr`, `either`, `filter`. | Write `Maybe` or a domain data type. For `filter`, write the term that the message gives. | false |
| `REFUSE_CELL` | The name makes a type constructor that is not a cell monad (rule R1): `List`, `cons`, `nil`, `unfold`. Or a program data type with a type parameter is not a cell signature (rule R1): a parameter is not a type; a field of a parameter type is not the one field of its constructor; a field is not a type parameter, closed data, the family at its own parameters or a path in the family; a type parameter is in no constructor, or does not have exactly one generator; a path constructor does not have the type `s ≡ t` over two point terms or `p ≡ q` over two path fields of the constructor; a path constructor has a dimension above 2. Or a data type has a type index, for example `data F : Type → Type where`. Or a record field is a type constructor, for example `F : Type → Type`. Or a record is `coinductive`: R1 admits cell monads only (Q1 (b)), and a coinductive record with a type parameter is a cell comonad. | Write `Maybe`, `_×_`, or a domain data type with `fold`. For a data type, give each type parameter one constructor with one field of that type, and make each type argument a parameter, not an index. For a record, give each field a type that is not a type constructor, and remove the `coinductive` line. | false |
| `REFUSE_DATA` | A program declares closed data: a data type with no parameters and no indices (rule R2). A base type comes only from domain/domain.lang. | Use a data type of domain/domain.lang, or give the data type a type parameter (a cell monad, rule R1), a value parameter or a value index (an indexed family). | false |
| `REFUSE_NAME` | The name is reserved (rule R4). Or a constructor field has the name of its constructor, or the name of an earlier field of the same constructor. Or a definition in a `module` uses an earlier definition of the same module at a position where a binder hides a section parameter. | Write a different name. In a module, rename the binder that hides the section parameter. | false |
| `REFUSE_REC` | A definition names itself (rule R3). | Write the recursion with `fold`. | false |
| `REFUSE_RUNTIME_CLOSURE` | `langc ir` or `langc build`: a function value must exist at run time (HOST-LIMIT). | Make the entry return a number, not a function. | false |
| `REFUSE_RUNTIME_TREE` | `langc ir` or `langc build`: a fold over a tree data type must exist at run time (HOST-LIMIT). | Fold over ℕ or a data type without recursive fields in the entry. | false |
| `DOMAIN_FAMILY` | A data type or a `fold` uses a family form that S2 does not have: a `fold` over an indexed family or over a data type with a path constructor (the dependent eliminator comes in S3); a recursive field that is not the family at its own parameters; a path constructor in a data type that is not a cell signature (rule R1). | Fold over a data type with no indices and no path constructors. Write each recursive field as the family at its parameters. Put a path constructor only in a cell signature. | false |
| `EVAL_ARGS` | `langc eval`: an argument is not a Bool (0 or 1) or a ℕ (0 to 2^64 - 1), the number of arguments is not correct, or the definition is not an entry. | Give the arguments that the entry signature declares. | false |
| `EVAL_ENTRY` | `langc eval`: no definition has this name, or the entry did not compute a number. | Name an entry of the file. | false |
| `EVAL_FUEL` | `langc eval`: the evaluation takes more than 20000000 steps. | Make the fold counts smaller. | false |
| `EVAL_DEPTH` | `langc eval` or the lowering: the evaluation nests deeper than 2000 levels. | Make the chain of definitions shorter. | false |
| `EVAL_OVERFLOW` | `langc eval`: a ℕ operation goes above 2^64 - 1, so the result is `trap`. | Use smaller arguments, or test the size before the operation. | false |
| `EVAL_PRINT` | `langc eval`: the normal form is larger than the printer limits. | Evaluate a smaller term. | false |
| `IO` | `langc` cannot open, read or write a file. | Correct the path or the file permissions. | false |
| `IO_SIZE` | The source file is larger than 1048576 bytes. | Make the file smaller. | false |
| `OOM` | The arena limit (1 GiB) is reached, or no memory is available. | Make the evaluation smaller, for example the fold counts. | false |
| `USAGE` | The command line is not correct. | Use a verb and the arguments that AGENTS.md gives. | false |
| `W_NONCANON` | The text is not in the canonical form (docs/GRAMMAR.md). This is a warning. | Replace the file with `fix`, which is the output of `langc fmt FILE`. | true |
