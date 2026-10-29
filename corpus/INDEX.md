# Corpus index

This file gives the labels of each `.lang` program in examples/ and test/
(docs/PLAN.md sec 7, A17). The USER trains a model on the corpus. This
repo does not train a model. The programs stay in examples/ and test/.

Each row has 5 cells:

- Path: the file, from the root of the repo.
- First code: the code of the first diagnostic of `build/langc check
  --json PATH`, or `ok` when there is no diagnostic.
- Parsed and Typed: the counts on the last line of `check --json`.
- Laws: discharged/total, from the same line.

`make check` makes the rows again from `check --json` and compares them
with this table (test/gate.sh, `corpus: N files, 0 mismatches`). A
mismatch is a path with a row that is not the row of `check --json`: a row
without a file, a file without a row, or a row with a stale value. When
you add, remove or change a `.lang` file, change its row.

| Path | First code | Parsed | Typed | Laws |
|---|---|---|---|---|
| examples/agent/01-certificate.lang | ok | 8 | 8 | 3/3 |
| examples/agent/02-cast-tally.lang | ok | 6 | 6 | 2/2 |
| examples/agent/03-threshold-reveal.lang | ok | 7 | 7 | 2/2 |
| examples/agent/04-amendment.lang | ok | 10 | 10 | 2/2 |
| examples/agent/05-replica-merge.lang | ok | 7 | 7 | 4/4 |
| examples/algebra.lang | ok | 2 | 2 | 0/0 |
| examples/bag.lang | ok | 31 | 31 | 0/0 |
| examples/cells.lang | ok | 14 | 14 | 0/0 |
| examples/circuit.lang | ok | 33 | 33 | 0/0 |
| examples/denote.lang | ok | 63 | 63 | 1/1 |
| examples/entries.lang | ok | 10 | 10 | 0/0 |
| examples/equality.lang | ok | 11 | 11 | 0/0 |
| examples/families.lang | ok | 16 | 16 | 0/0 |
| examples/formers.lang | ok | 7 | 7 | 0/0 |
| examples/functions.lang | ok | 9 | 9 | 0/0 |
| examples/hit-fold.lang | ok | 8 | 8 | 0/0 |
| examples/inventory.lang | ok | 9 | 9 | 0/0 |
| examples/laws.lang | ok | 12 | 12 | 0/0 |
| examples/monad.lang | ok | 6 | 6 | 0/0 |
| examples/operators.lang | ok | 21 | 21 | 0/0 |
| examples/paths.lang | ok | 18 | 18 | 0/0 |
| examples/sigma.lang | ok | 4 | 4 | 0/0 |
| examples/threshold.lang | ok | 124 | 124 | 12/12 |
| examples/universes.lang | ok | 3 | 3 | 0/0 |
| test/baseline/t1-certificate.lang | W_NONCANON | 8 | 8 | 3/3 |
| test/baseline/t2-cast-tally.lang | W_NONCANON | 6 | 6 | 2/2 |
| test/baseline/t3-amendment.lang | W_NONCANON | 10 | 10 | 2/2 |
| test/check/arity.lang | TYPE_ARITY | 1 | 0 | 0/0 |
| test/check/axiom.lang | REFUSE_AXIOM | 1 | 0 | 0/0 |
| test/check/bad-refl.lang | TYPE_REFL | 2 | 1 | 0/0 |
| test/check/bag-bad-swap.lang | TYPE_REFL | 2 | 1 | 0/0 |
| test/check/bag-no-comm.lang | TYPE_BAG | 2 | 1 | 0/0 |
| test/check/bag-no-trunc.lang | TYPE_BAG | 2 | 1 | 0/0 |
| test/check/bare-fun.lang | TYPE_INFER | 1 | 0 | 0/0 |
| test/check/cell-alias-index.lang | REFUSE_CELL | 2 | 1 | 0/0 |
| test/check/cell-alias-param.lang | REFUSE_CELL | 2 | 1 | 0/0 |
| test/check/cell-alias-record.lang | REFUSE_CELL | 2 | 1 | 0/0 |
| test/check/cell-cc.lang | REFUSE_CELL | 1 | 0 | 0/0 |
| test/check/cell-fmset-cons.lang | REFUSE_CELL | 1 | 0 | 0/0 |
| test/check/cell-ghost.lang | REFUSE_CELL | 1 | 0 | 0/0 |
| test/check/cell-list.lang | REFUSE_CELL | 1 | 0 | 0/0 |
| test/check/cell-pair.lang | REFUSE_CELL | 1 | 0 | 0/0 |
| test/check/cell-record-field.lang | REFUSE_CELL | 1 | 0 | 0/0 |
| test/check/cell-type-index.lang | REFUSE_CELL | 1 | 0 | 0/0 |
| test/check/circuit-ho.lang | REFUSE_CIRCUIT | 1 | 0 | 0/0 |
| test/check/cons.lang | REFUSE_CELL | 1 | 0 | 0/0 |
| test/check/core-name.lang | REFUSE_NAME | 1 | 0 | 0/0 |
| test/check/data.lang | REFUSE_DATA | 1 | 0 | 0/0 |
| test/check/domain-name.lang | REFUSE_NAME | 1 | 0 | 0/0 |
| test/check/duplicate.lang | REFUSE_NAME | 2 | 1 | 0/0 |
| test/check/either.lang | REFUSE_BASE | 1 | 0 | 0/0 |
| test/check/elim-family.lang | DOMAIN_FAMILY | 1 | 0 | 0/0 |
| test/check/filter.lang | REFUSE_BASE | 1 | 0 | 0/0 |
| test/check/fold-hit-bad.lang | TYPE_REFL | 2 | 1 | 0/0 |
| test/check/foldi-dependent-binder.lang | DOMAIN_FAMILY | 2 | 1 | 0/0 |
| test/check/foldi-dependent.lang | DOMAIN_FAMILY | 4 | 1 | 0/0 |
| test/check/index-fold.lang | DOMAIN_FAMILY | 2 | 1 | 0/0 |
| test/check/index-mismatch.lang | TYPE_MISMATCH | 1 | 0 | 0/0 |
| test/check/inl.lang | REFUSE_BASE | 1 | 0 | 0/0 |
| test/check/inr.lang | REFUSE_BASE | 1 | 0 | 0/0 |
| test/check/later.lang | REFUSE_REC | 2 | 0 | 0/0 |
| test/check/list.lang | REFUSE_CELL | 1 | 0 | 0/0 |
| test/check/mismatch.lang | TYPE_MISMATCH | 1 | 0 | 0/0 |
| test/check/nil.lang | REFUSE_CELL | 1 | 0 | 0/0 |
| test/check/no-type.lang | TYPE_INFER | 1 | 0 | 0/0 |
| test/check/not-function.lang | TYPE_NOT_FUNCTION | 1 | 0 | 0/0 |
| test/check/reserved.lang | REFUSE_NAME | 1 | 0 | 0/0 |
| test/check/seal-data.lang | REFUSE_DATA | 1 | 0 | 0/0 |
| test/check/seal-fold.lang | REFUSE_LAW | 1 | 0 | 0/0 |
| test/check/seal-path-local.lang | REFUSE_LAW | 1 | 0 | 0/0 |
| test/check/seal-path-proj.lang | REFUSE_LAW | 3 | 2 | 0/0 |
| test/check/seal-path-record.lang | REFUSE_LAW | 2 | 1 | 0/0 |
| test/check/seal-path.lang | REFUSE_LAW | 2 | 1 | 0/0 |
| test/check/seal-relay.lang | REFUSE_LAW | 2 | 1 | 1/1 |
| test/check/seal-unseal.lang | REFUSE_LAW | 1 | 0 | 0/0 |
| test/check/self.lang | REFUSE_REC | 1 | 0 | 0/0 |
| test/check/sum.lang | REFUSE_BASE | 1 | 0 | 0/0 |
| test/check/unfold.lang | REFUSE_CELL | 1 | 0 | 0/0 |
| test/check/universe-range.lang | TYPE_UNIVERSE | 1 | 0 | 0/0 |
| test/check/universe.lang | TYPE_MISMATCH | 1 | 0 | 0/0 |
| test/check/unknown.lang | NAME_UNKNOWN | 1 | 0 | 0/0 |
| test/fmt/arrow.lang | W_NONCANON | 1 | 1 | 0/0 |
| test/fmt/backslash.lang | W_NONCANON | 1 | 1 | 0/0 |
| test/fmt/cons-prefix.lang | W_NONCANON | 2 | 2 | 0/0 |
| test/fmt/data-index.lang | W_NONCANON | 1 | 1 | 0/0 |
| test/fmt/exists-lambda.lang | W_NONCANON | 3 | 3 | 0/0 |
| test/fmt/group.lang | W_NONCANON | 1 | 1 | 0/0 |
| test/fmt/lambda-def.lang | W_NONCANON | 1 | 1 | 0/0 |
| test/fmt/law.lang | W_NONCANON | 1 | 1 | 1/1 |
| test/fmt/next.lang | TYPE_MISMATCH | 1 | 0 | 0/0 |
| test/fmt/path-lambda.lang | W_NONCANON | 1 | 1 | 0/0 |
| test/fmt/type-n.lang | W_NONCANON | 1 | 1 | 0/0 |
| test/host-flags.lang | ok | 14 | 14 | 0/0 |
| test/ir/closure.lang | ok | 1 | 1 | 0/0 |
| test/ir/lazy.lang | ok | 1 | 1 | 0/0 |
| test/ir/proof-trap.lang | ok | 10 | 10 | 0/0 |
| test/ir/spine.lang | ok | 2 | 2 | 0/0 |
| test/ir/tree.lang | ok | 1 | 1 | 0/0 |
| test/json/DOMAIN_FAMILY.lang | DOMAIN_FAMILY | 2 | 1 | 0/0 |
| test/json/LEX_CHAR.lang | LEX_CHAR | 0 | 0 | 0/0 |
| test/json/LEX_NAT_RANGE.lang | LEX_NAT_RANGE | 0 | 0 | 0/0 |
| test/json/NAME_UNKNOWN.lang | NAME_UNKNOWN | 1 | 0 | 0/0 |
| test/json/PARSE_DEPTH.lang | PARSE_DEPTH | 0 | 0 | 0/0 |
| test/json/PARSE_EXPECT.lang | PARSE_EXPECT | 0 | 0 | 0/0 |
| test/json/PARSE_law.lang | PARSE_EXPECT | 2 | 0 | 0/1 |
| test/json/REFUSE_AXIOM.lang | REFUSE_AXIOM | 1 | 0 | 0/0 |
| test/json/REFUSE_BASE.lang | REFUSE_BASE | 1 | 0 | 0/0 |
| test/json/REFUSE_CELL.lang | REFUSE_CELL | 1 | 0 | 0/0 |
| test/json/REFUSE_CIRCUIT.lang | REFUSE_CIRCUIT | 1 | 0 | 0/0 |
| test/json/REFUSE_DATA.lang | REFUSE_DATA | 1 | 0 | 0/0 |
| test/json/REFUSE_LAW.lang | REFUSE_LAW | 2 | 1 | 0/0 |
| test/json/REFUSE_NAME.lang | REFUSE_NAME | 1 | 0 | 0/0 |
| test/json/REFUSE_REC.lang | REFUSE_REC | 1 | 0 | 0/0 |
| test/json/TYPE_ARITY.lang | TYPE_ARITY | 1 | 0 | 0/0 |
| test/json/TYPE_BAG.lang | TYPE_BAG | 2 | 1 | 0/0 |
| test/json/TYPE_ENDPOINT.lang | TYPE_ENDPOINT | 2 | 1 | 0/0 |
| test/json/TYPE_INFER.lang | TYPE_INFER | 1 | 0 | 0/0 |
| test/json/TYPE_MISMATCH.lang | TYPE_MISMATCH | 1 | 0 | 0/0 |
| test/json/TYPE_NOT_FUNCTION.lang | TYPE_NOT_FUNCTION | 1 | 0 | 0/0 |
| test/json/TYPE_REFL.lang | TYPE_REFL | 2 | 1 | 0/0 |
| test/json/TYPE_SYSTEM.lang | TYPE_SYSTEM | 1 | 0 | 0/0 |
| test/json/TYPE_UNIVERSE.lang | TYPE_UNIVERSE | 1 | 0 | 0/0 |
| test/json/W_NONCANON.lang | W_NONCANON | 2 | 2 | 0/0 |
| test/json/foldi-safe.lang | ok | 3 | 3 | 1/1 |
| test/json/laws.lang | TYPE_MISMATCH | 2 | 1 | 1/2 |
| test/json/partial.lang | TYPE_MISMATCH | 3 | 2 | 0/0 |
| test/json/seal-safe.lang | ok | 8 | 8 | 0/0 |
| test/parse/bad-char.lang | LEX_CHAR | 0 | 0 | 0/0 |
| test/parse/data-no-type.lang | PARSE_EXPECT | 0 | 0 | 0/0 |
| test/parse/fun-no-binder.lang | PARSE_EXPECT | 0 | 0 | 0/0 |
| test/parse/nat-range.lang | LEX_NAT_RANGE | 0 | 0 | 0/0 |
| test/parse/no-body.lang | PARSE_EXPECT | 0 | 0 | 0/0 |
| test/parse/no-keyword.lang | PARSE_EXPECT | 0 | 0 | 0/0 |
| test/parse/string.lang | LEX_CHAR | 0 | 0 | 0/0 |
| test/parse/unclosed.lang | PARSE_EXPECT | 0 | 0 | 0/0 |
