# Token baseline (S9)

This file gives the token cost of 3 tasks in quorum-lang and in 2
general-purpose languages (docs/PLAN.md sec 7, A13). The measure is one
fixed offline proxy, not the tokenizer of a model. Thus each run gives the
same counts.

## The proxy

test/tokproxy.c (`build/tokproxy FILE`) prints the token count of FILE:

- A run of ASCII letters, digits and `_` costs ceil(length / 4).
- Each other ASCII byte that is not white space costs 1.
- Each byte of a non-ASCII UTF-8 character costs 1. Thus `→` (3 bytes)
  costs 3, and its ASCII spelling `->` costs 2.
- White space costs 0.

## The tasks

- T1, certificate check: count the signers of a certificate of 3 members,
  and accept it when at least t members sign.
- T2, cast and tally: cast Bool votes into a bag of counts (yes, no). The
  order of 2 casts does not change the bag.
- T3, amendment check: the amendment of the rules (t, n) adds one member
  and adds 1 to the threshold. The amendment keeps Core.

## The columns

- quorum-lang: the agent example of the task in examples/agent/.
- quorum-lang ASCII: the same file with the ASCII spelling of
  docs/GRAMMAR.md (`->` for `→`, `\` for `λ`). `langc check` accepts it
  with W_NONCANON, and `langc fmt` of it is the quorum-lang file.
- Python and Rust: text samples in test/baseline/. The gate does not run
  them. Each sample uses the operators of its language (`<=`, `and`,
  `+`). The quorum-lang file defines these with `elim`, because a program
  has no imports. The laws of a sample are tests on some values. The laws
  of a quorum-lang file are proofs for each value. Each sample has the
  comments of the quorum-lang file for the names that it has.

## The counts

`make check` makes each count again (test/gate.sh, `tokens: 3 tasks, 12
cells`). Each row is one cell. The gate fails when a count is not the
output of `build/tokproxy FILE`, when a file is missing, when a quorum-lang
file does not check, or when `langc fmt` of an ASCII file is not the
quorum-lang file of its task. When you change a file of this table,
change its count.

| Task | Column | File | Tokens |
|---|---|---|---|
| T1 | quorum-lang | examples/agent/01-certificate.lang | 527 |
| T1 | quorum-lang ASCII | test/baseline/t1-certificate.lang | 505 |
| T1 | Python | test/baseline/t1-certificate.py | 253 |
| T1 | Rust | test/baseline/t1-certificate.rs | 367 |
| T2 | quorum-lang | examples/agent/02-cast-tally.lang | 435 |
| T2 | quorum-lang ASCII | test/baseline/t2-cast-tally.lang | 419 |
| T2 | Python | test/baseline/t2-cast-tally.py | 327 |
| T2 | Rust | test/baseline/t2-cast-tally.rs | 413 |
| T3 | quorum-lang | examples/agent/04-amendment.lang | 688 |
| T3 | quorum-lang ASCII | test/baseline/t3-amendment.lang | 649 |
| T3 | Python | test/baseline/t3-amendment.py | 274 |
| T3 | Rust | test/baseline/t3-amendment.rs | 339 |
