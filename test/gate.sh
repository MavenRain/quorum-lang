#!/bin/sh
# The kit gate. `make check` runs it from the kit directory after the build.
set -eu
fail=0
count=0
for prog in examples/*.lang; do
  out=$(build/langc check "$prog" 2>&1) || true
  count=$((count + 1))
  if [ "$out" != "ok" ]; then
    echo "FAIL $prog: $out"
    fail=$((fail + 1))
  fi
done
echo "examples: $count checked, $fail failed"

tmp=${TMPDIR:-/tmp}/langc-gate.$$
mkdir -p "$tmp"
awk 'BEGIN { printf "deep : ℕ\ndeep = " } { } END {
  for (i = 0; i < 1100; i++) printf "("; printf "1"; for (i = 0; i < 1100; i++) printf ")"; print "" }' </dev/null >"$tmp/deep.lang"

# refusals DIR LABEL: each line of DIR/expect.txt is `FILE CODE`. `langc check`
# must exit 1 and print `langc: CODE: ...` on stderr.
refusals() {
  checked=0
  while read -r file code; do
    path="$1/$file"
    [ "$file" = "deep.lang" ] && path="$tmp/deep.lang"
    status=0
    build/langc check "$path" 2>"$tmp/err" >/dev/null || status=$?
    first=$(head -n 1 "$tmp/err")
    checked=$((checked + 1))
    case "$status:$first" in
      "1:langc: $code: "*) ;;
      *) echo "FAIL $file: want exit 1 and $code, got exit $status: $first"; fail=$((fail + 1)) ;;
    esac
  done <"$1/expect.txt"
  echo "$2 refusals: $checked checked"
}
refusals test/parse parse
refusals test/check check

# A refl refusal shows both normal forms.
build/langc check test/check/bad-refl.lang 2>"$tmp/err" >/dev/null || true
if ! rg -q -F 'the left side normalizes to 1201, the right side normalizes to 1200' "$tmp/err"; then
  echo "FAIL bad-refl.lang: the message does not show both normal forms"
  fail=$((fail + 1))
fi

# Each line of test/eval/expect.txt is `FILE NAME [ARGS] => OUTPUT`. `langc eval`
# must exit 0 and print OUTPUT. A trap also prints `langc: EVAL_OVERFLOW: NAME: ...`
# on stderr.
evals=0
while IFS= read -r line; do
  want=${line#* => }
  set -- ${line%% => *}
  file=$1
  name=$2
  shift 2
  status=0
  got=$(build/langc eval "examples/$file.lang" "$name" "$@" 2>"$tmp/err") || status=$?
  first=$(head -n 1 "$tmp/err")
  want_err=""
  [ "$want" = "trap" ] && want_err="langc: EVAL_OVERFLOW: $name: "
  evals=$((evals + 1))
  case "$status|$got|$first" in
    "0|$want|$want_err"*) ;;
    *) echo "FAIL eval $file $name: want $want, got exit $status: $got $first"; fail=$((fail + 1)) ;;
  esac
done <test/eval/expect.txt
echo "evals: $evals checked"

# The representation map (O80): `build/tallytool rep` prints an eval line for
# each ballot list of the entries denCount1 to denCount3 of examples/denote.lang
# and each choice, with the count from the ciphertexts. `langc eval` must
# print the same count.
status=0
build/tallytool rep >"$tmp/rep" 2>"$tmp/rep.err" || status=$?
[ "$status" -eq 0 ] || { echo "FAIL tallytool rep: exit $status: $(head -n 1 "$tmp/rep.err")"; fail=$((fail + 1)); }
counts=0
rep_bad=0
while IFS= read -r line; do
  want=${line#* => }
  set -- ${line%% => *}
  file=$1
  name=$2
  shift 2
  status=0
  got=$(build/langc eval "examples/$file.lang" "$name" "$@" 2>"$tmp/err") || status=$?
  counts=$((counts + 1))
  [ "$status|$got" = "0|$want" ] || { echo "FAIL tally $name $*: want $want, got exit $status: $got $(head -n 1 "$tmp/err")"; rep_bad=$((rep_bad + 1)); }
done <"$tmp/rep"
rep_cases=$(rg -c '^denote denCount[0-9] 0 ' "$tmp/rep" || echo 0)
fail=$((fail + rep_bad))
[ "$rep_cases|$counts" = "14|28" ] || { echo "FAIL tally: want 14 cases and 28 counts"; fail=$((fail + 1)); }
echo "tally: $rep_cases cases, $counts counts, $rep_bad mismatches"

# The representation map of `Authorized` (O98): `build/frosttool rep` prints an
# eval line for each signer set of the secp256k1 DKG (t 2 of n 3, denAuth3) and
# of its reshare (t 3 of n 4, denAuth4) of examples/denote.lang, with 1 when
# the FROST signature verifies. `langc eval` must print the same value.
status=0
build/frosttool rep >"$tmp/auth" 2>"$tmp/auth.err" || status=$?
[ "$status" -eq 0 ] || { echo "FAIL frosttool rep: exit $status: $(head -n 1 "$tmp/auth.err")"; fail=$((fail + 1)); }
auth=0
auth_bad=0
while IFS= read -r line; do
  want=${line#* => }
  set -- ${line%% => *}
  file=$1
  name=$2
  shift 2
  status=0
  got=$(build/langc eval "examples/$file.lang" "$name" "$@" 2>"$tmp/err") || status=$?
  auth=$((auth + 1))
  [ "$status|$got" = "0|$want" ] || { echo "FAIL auth $name $*: want $want, got exit $status: $got $(head -n 1 "$tmp/err")"; auth_bad=$((auth_bad + 1)); }
done <"$tmp/auth"
fail=$((fail + auth_bad))
[ "$auth" -eq 24 ] || { echo "FAIL auth: want 24 cases"; fail=$((fail + 1)); }
echo "auth: $auth cases, $auth_bad mismatches"

# eval_refused STATUS CODE NAME [ARGS]: `langc eval examples/entries.lang NAME
# ARGS` must exit STATUS and print `langc: CODE: NAME: ...` on stderr.
eval_refused() {
  want_status=$1
  code=$2
  shift 2
  status=0
  build/langc eval examples/entries.lang "$@" 2>"$tmp/err" >/dev/null || status=$?
  case "$status:$(head -n 1 "$tmp/err")" in
    "$want_status:langc: $code: $1: "*) ;;
    *) echo "FAIL eval $*: want exit $want_status and $code, got exit $status"; fail=$((fail + 1)) ;;
  esac
}
eval_refused 2 EVAL_ARGS addPrice 1
eval_refused 2 EVAL_ARGS addPrice x 1
eval_refused 2 EVAL_ARGS addPrice 18446744073709551616 1
eval_refused 2 EVAL_ARGS pick 2 4 9
eval_refused 1 EVAL_ENTRY nope

# code_line STATUS CODE COMMAND...: COMMAND must exit STATUS and print
# `langc: CODE: ...` on stderr.
code_line() {
  want_status=$1
  code=$2
  shift 2
  status=0
  "$@" 2>"$tmp/err" >/dev/null || status=$?
  first=$(head -n 1 "$tmp/err")
  case "$status:$first" in
    "$want_status:langc: $code: "*) ;;
    *) echo "FAIL $code: want exit $want_status, got exit $status: $first"; fail=$((fail + 1)) ;;
  esac
}
code_line 2 USAGE build/langc
code_line 2 IO build/langc check "$tmp/missing.lang"
head -c 1048577 /dev/zero >"$tmp/big.lang"
code_line 2 IO_SIZE build/langc check "$tmp/big.lang"
printf 'spin : Bool\nspin = fold (λ (acc : Bool) → acc) true 100000000\n' >"$tmp/fuel.lang"
code_line 1 EVAL_FUEL build/langc eval "$tmp/fuel.lang" spin
awk 'BEGIN { print "d0 : ℕ"; print "d0 = 0"
  for (i = 1; i <= 2100; i++) printf "d%d : ℕ\nd%d = suc d%d\n", i, i, i - 1 }' </dev/null >"$tmp/depth.lang"
code_line 1 EVAL_DEPTH build/langc eval "$tmp/depth.lang" d2100
# Each step makes a new ℕ value, so the arena limit (1 GiB) comes before the fuel limit.
printf 'grow : ℕ\ngrow = fold (λ (acc : ℕ) → suc acc) 0 100000000\n' >"$tmp/oom.lang"
code_line 1 OOM build/langc eval "$tmp/oom.lang" grow

# fmt: `langc fmt F` prints F for each committed .lang file. test/parse,
# test/fmt and the lex, parse and W_NONCANON fixtures of test/json are not
# canonical on purpose.
fmts=0
for f in $(rg --files -g '*.lang' -g '!test/parse/**' -g '!test/fmt/**' -g '!test/json/LEX_*' -g '!test/json/PARSE_*' -g '!test/json/W_NONCANON.lang' . | sort); do
  fmts=$((fmts + 1))
  build/langc fmt "$f" 2>/dev/null | cmp -s - "$f" || { echo "FAIL fmt $f: the output is not the file"; fail=$((fail + 1)); }
done
echo "fmt: $fmts files canonical"

# test/fmt: each line of expect.txt is `FILE NEXT`. `langc check --json FILE`
# prints FILE.json. The fix is `langc fmt FILE`: fmt of the fix is the fix,
# and `langc check` of the fix gives exit 0 (NEXT ok) or exit 1 and NEXT.
while read -r file next; do
  path=test/fmt/$file
  build/langc check --json "$path" 2>/dev/null | cmp -s - "${path%.lang}.json" || { echo "FAIL json $path"; fail=$((fail + 1)); }
  build/langc fmt "$path" >"$tmp/fix.lang" 2>/dev/null || { echo "FAIL fmt $path"; fail=$((fail + 1)); continue; }
  build/langc fmt "$tmp/fix.lang" 2>/dev/null | cmp -s - "$tmp/fix.lang" || { echo "FAIL fmt $path: not idempotent"; fail=$((fail + 1)); }
  status=0
  build/langc check "$tmp/fix.lang" 2>"$tmp/err" >/dev/null || status=$?
  first=$(head -n 1 "$tmp/err")
  case "$next:$status:$first" in
    "ok:0:"*|"$next:1:langc: $next: "*) ;;
    *) echo "FAIL fix $path: want $next, got exit $status: $first"; fail=$((fail + 1)) ;;
  esac
done <test/fmt/expect.txt

# test/json: `langc check --json CODE.lang` prints CODE.json byte for byte.
# partial.lang has 2 good definitions, then a type error.
jsons=0
for path in test/json/*.lang; do
  jsons=$((jsons + 1))
  build/langc check --json "$path" 2>/dev/null | cmp -s - "${path%.lang}.json" || { echo "FAIL json $path"; fail=$((fail + 1)); }
done
echo "json: $jsons fixtures"
[ "$(tail -n 1 test/json/partial.json)" = '{"parsed":3,"typed":2,"laws":{"discharged":0,"total":0}}' ] ||
  { echo "FAIL partial.json: want parsed 3 typed 2"; fail=$((fail + 1)); }
[ "$(tail -n 1 test/json/laws.json)" = '{"parsed":2,"typed":1,"laws":{"discharged":1,"total":2}}' ] ||
  { echo "FAIL laws.json: want 1 of 2 laws discharged"; fail=$((fail + 1)); }

# S4 O64: `langc laws` and the `check --json` law counts agree on the 12 laws.
build/langc laws examples/threshold.lang >"$tmp/laws" 2>&1 || { echo "FAIL laws examples/threshold.lang: exit $?"; fail=$((fail + 1)); }
[ "$(tail -n 1 "$tmp/laws")" = 'laws: 12 of 12 discharged' ] || { echo "FAIL laws: want 12 of 12 discharged"; fail=$((fail + 1)); }
build/langc check --json examples/threshold.lang 2>/dev/null | rg -q -F '"laws":{"discharged":12,"total":12}' ||
  { echo "FAIL check --json examples/threshold.lang: want laws 12 of 12"; fail=$((fail + 1)); }
build/langc laws test/json/laws.lang >/dev/null 2>&1 && { echo "FAIL laws test/json/laws.lang: want exit 1"; fail=$((fail + 1)); }
# A parse failure keeps the parsed laws open, with the same counts as JSON.
law_status=0
build/langc laws test/json/PARSE_law.lang >"$tmp/laws-partial" 2>"$tmp/err" || law_status=$?
[ "$law_status" -eq 1 ] || { echo "FAIL laws partial parse: want exit 1, got $law_status"; fail=$((fail + 1)); }
printf 'law identity open\nlaws: 0 of 1 discharged\n' >"$tmp/laws-want"
cmp -s "$tmp/laws-want" "$tmp/laws-partial" || { echo "FAIL laws partial parse: want the open law and summary"; fail=$((fail + 1)); }
rg -q '^langc: PARSE_EXPECT: ' "$tmp/err" || { echo "FAIL laws partial parse: want PARSE_EXPECT"; fail=$((fail + 1)); }
echo "$(tail -n 1 "$tmp/laws")"
# S5 O75: the denotational instances. den-private opens the seal, so it is the one law.
build/langc laws examples/denote.lang >"$tmp/laws-denote" 2>&1 || { echo "FAIL laws examples/denote.lang: exit $?"; fail=$((fail + 1)); }
[ "$(tail -n 1 "$tmp/laws-denote")" = 'laws: 1 of 1 discharged' ] || { echo "FAIL laws denote: want 1 of 1 discharged"; fail=$((fail + 1)); }
build/langc check --json examples/denote.lang 2>/dev/null | rg -q -F '"laws":{"discharged":1,"total":1}' ||
  { echo "FAIL check --json examples/denote.lang: want laws 1 of 1"; fail=$((fail + 1)); }
echo "denote.lang $(tail -n 1 "$tmp/laws-denote")"

# Each code in docs/DIAGNOSTICS.md has a fixture: test/json/CODE.lang or a
# line of this file or test/review.sh that wants `langc: CODE:`. Each code in
# src/ has a row in docs/DIAGNOSTICS.md.
codes=0
missing=0
for code in $(rg -o '^\| `([A-Z][A-Z_]+)` \|' -r '$1' docs/DIAGNOSTICS.md); do
  codes=$((codes + 1))
  [ -f "test/json/$code.lang" ] && continue
  rg -q "(langc: |code_line [0-9] |eval_refused [0-9] )$code[: ]" test/gate.sh test/review.sh ||
    { echo "FAIL $code: no fixture"; missing=$((missing + 1)); }
done
for code in $(rg -o --no-filename '"((LEX|PARSE|NAME|TYPE|REFUSE|EVAL|W)_[A-Z_]+|IO|IO_SIZE|OOM|USAGE)"' -r '$1' src | sort -u); do
  rg -q "^\| \`$code\` \|" docs/DIAGNOSTICS.md || { echo "FAIL $code: no row in docs/DIAGNOSTICS.md"; missing=$((missing + 1)); }
done
fail=$((fail + missing))
echo "diagnostics: $codes codes, $missing without a fixture or a row"

# The IR: each example lowers, with one func line for each entry.
irs=0
for f in examples/*.lang; do
  irs=$((irs + 1))
  status=0
  build/langc ir "$f" > "$tmp/ir.txt" 2> "$tmp/ir.err" || status=$?
  funcs=$(rg -c '^func ' "$tmp/ir.txt" || echo 0)
  entries=$(build/langc abi "$f" | rg -c '.' || echo 0)
  [ "$status" -eq 0 ] && [ "$funcs" -eq "$entries" ] || { echo "FAIL ir $f: exit $status, $funcs funcs for $entries entries: $(head -n 1 "$tmp/ir.err")"; fail=$((fail + 1)); }
done
echo "ir: $irs lowered"
status=0
build/langc check test/ir/closure.lang > /dev/null || status=$?
[ "$status" -eq 0 ] || { echo "FAIL closure.lang: check exit $status"; fail=$((fail + 1)); }
status=0
first=$(build/langc ir test/ir/closure.lang 2>&1 > /dev/null) || status=$?
case "$status:$first" in
  "1:langc: REFUSE_RUNTIME_CLOSURE: "*) ;;
  *) echo "FAIL closure.lang: want exit 1 and REFUSE_RUNTIME_CLOSURE, got exit $status: $first"; fail=$((fail + 1)) ;;
esac
got=$(build/langc eval test/ir/lazy.lang lazy 3 2>&1) || true
[ "$got" = "3" ] || { echo "FAIL lazy.lang: want 3, got $got"; fail=$((fail + 1)); }
build/langc ir test/ir/lazy.lang > /dev/null || { echo "FAIL lazy.lang: ir"; fail=$((fail + 1)); }
for want in "stackSum 3:15" "stackTrap 0:7" "stackTrap 2:5"; do
  call=${want%%:*}
  got=$(build/langc eval test/ir/spine.lang ${call% *} ${call#* } 2>"$tmp/err") || true
  want_err=""
  [ "${want#*:}" = "trap" ] && want_err="langc: EVAL_OVERFLOW: ${call% *}: "
  case "$got|$(head -n 1 "$tmp/err")" in
    "${want#*:}|$want_err"*) ;;
    *) echo "FAIL spine.lang $call: want ${want#*:}, got $got"; fail=$((fail + 1)) ;;
  esac
done
build/langc ir test/ir/spine.lang > /dev/null || { echo "FAIL spine.lang: ir"; fail=$((fail + 1)); }
status=0
build/langc check test/ir/tree.lang > /dev/null || status=$?
[ "$status" -eq 0 ] || { echo "FAIL tree.lang: check exit $status"; fail=$((fail + 1)); }
status=0
first=$(build/langc ir test/ir/tree.lang 2>&1 > /dev/null) || status=$?
case "$status:$first" in
  "1:langc: REFUSE_RUNTIME_TREE: "*) ;;
  *) echo "FAIL tree.lang: want exit 1 and REFUSE_RUNTIME_TREE, got exit $status: $first"; fail=$((fail + 1)) ;;
esac

# The Wasm target: each module builds and is valid. Then the differential: on
# the grid of test/grid.awk, node and `langc eval` give the same result for
# each entry (trap == trap). The stderr of eval is not merged into stdout.
wasms=0
cases=0
mismatches=0
for f in examples/*.lang test/ir/spine.lang test/ir/lazy.lang test/ir/proof-trap.lang; do
  w="$tmp/$(basename "$f" .lang).wasm"
  wasms=$((wasms + 1))
  if ! build/langc build "$f" -o "$w" 2>"$tmp/w.err" || ! wasm-validate "$w" 2>>"$tmp/w.err" ||
    ! wasm-objdump -x "$w" >/dev/null 2>>"$tmp/w.err"; then
    echo "FAIL wasm $f: $(head -n 1 "$tmp/w.err")"
    fail=$((fail + 1))
    continue
  fi
  build/langc ir "$f" | awk -f test/grid.awk >"$tmp/cases.txt"
  : >"$tmp/want.txt"
  while read -r call; do
    status=0
    want=$(build/langc eval "$f" $call 2>/dev/null) || status=$?
    [ "$status" -eq 0 ] || want="eval-exit-$status"
    echo "$want" >>"$tmp/want.txt"
  done <"$tmp/cases.txt"
  if ! node test/run-wasm.mjs "$w" - <"$tmp/cases.txt" >"$tmp/got.txt" 2>"$tmp/w.err"; then
    echo "FAIL node $f: $(head -n 1 "$tmp/w.err")"
    fail=$((fail + 1))
    continue
  fi
  cases=$((cases + $(rg -c '.' "$tmp/cases.txt" || echo 0)))
  paste -d '|' "$tmp/cases.txt" "$tmp/want.txt" "$tmp/got.txt" | awk -F '|' '$2 != $3' >"$tmp/bad.txt"
  bad=$(rg -c '.' "$tmp/bad.txt" || echo 0)
  mismatches=$((mismatches + bad))
  [ "$bad" -eq 0 ] || { echo "FAIL differential $f: $bad mismatches, first $(head -n 1 "$tmp/bad.txt")"; fail=$((fail + 1)); }
done
echo "wasm: $wasms modules valid"
echo "differential: $cases cases, $mismatches mismatches"
# A Flag argument larger than 1 traps (langc eval refuses it with EVAL_ARGS).
got=$(node test/run-wasm.mjs "$tmp/entries.wasm" pick 2 4 9 2>&1) || true
[ "$got" = "trap" ] || { echo "FAIL wasm pick 2 4 9: want trap, got $got"; fail=$((fail + 1)); }
# The host import q_hash2 (O105). langc eval and the Wasm module under
# build/replicatool give the same 4 words. The digest is the SHA-256 of
# the 64 bytes: the word x 8 times, each 8 bytes big endian.
hosts=0
for x in 0 1; do
  want=$(for k in 0 1 2 3; do build/langc eval replica/replica.lang "hash$k" "$x"; done | paste -sd ' ' -)
  sum=$(printf "\\000\\000\\000\\000\\000\\000\\000\\00$x%.0s" 1 2 3 4 5 6 7 8 | shasum -a 256 | awk '{print $1}')
  got=$(build/replicatool hash "$x" 2>&1) || true
  hosts=$((hosts + 1))
  [ "$got" = "$want $sum" ] || { echo "FAIL host hash $x: want $want $sum, got $got"; fail=$((fail + 1)); }
done
got=$(build/replicatool hash 0 2>&1 | awk '{print $5}')
[ "$got" = "f5a5fd42d16a20302798ef6ed309979b43003d2320d9f0e8ea9831a92759fb4b" ] ||
  { echo "FAIL host hash 0: want the known digest, got $got"; fail=$((fail + 1)); }
echo "host: $hosts rows"
# The input entries (O109 (i)). build/replicatool writes a Stack below
# heap_base. langc eval reads the same Stack in the pre-order form.
inputs=0
for xs in "" "5" "3 4" "1 2 3 4 5 6 7"; do
  pre="$(for x in $xs; do printf '1,%s,' "$x"; done)0"
  want=$(for e in total chain0 chain1 chain2 chain3; do build/langc eval replica/replica.lang "$e" "$pre"; done | paste -sd ' ' -)
  got=$(build/replicatool stack $xs 2>&1) || true
  inputs=$((inputs + 1))
  [ "$got" = "$want" ] || { echo "FAIL input stack '$xs': want $want, got $got"; fail=$((fail + 1)); }
done
rc=0
build/langc eval replica/replica.lang total 1,3 > /dev/null 2>&1 || rc=$?
[ "$rc" = 2 ] || { echo "FAIL input: the text 1,3 gave rc $rc, want 2 (EVAL_ARGS)"; fail=$((fail + 1)); }
echo "input: $inputs rows"
# The certificate chain (R-C12) and the merge (R-D8). build/frosttool chain
# writes the 25 lines of test/replica/history.txt: ROW ENTRY WANT X0 .. Y3
# PRE. PRE is one chain text, two (rep_merge, merge_tip), or a state and a
# chain text (step_apply), so $pre is not quoted. langc eval and
# build/replicatool chain give WANT for each line (R-C19).
build/frosttool chain > "$tmp/history.txt" 2>&1 || true
cmp -s "$tmp/history.txt" test/replica/history.txt ||
  { echo "FAIL replica history: build/frosttool chain is not test/replica/history.txt"; fail=$((fail + 1)); }
replicas=0
replica_bad=0
hrows=0
tip=none
refused=0
mrows=0
mtip=none
arows=0
astate=none
while read -r row entry want x0 x1 x2 x3 y0 y1 y2 y3 pre; do
  a=$(build/langc eval replica/replica.lang "$entry" "$x0" "$x1" "$x2" "$x3" "$y0" "$y1" "$y2" "$y3" $pre < /dev/null 2>&1) || true
  b=$(build/replicatool chain "$entry" "$x0" "$x1" "$x2" "$x3" "$y0" "$y1" "$y2" "$y3" $pre < /dev/null 2>&1) || true
  replicas=$((replicas + 1))
  if [ "$a" != "$want" ] || [ "$b" != "$want" ]; then
    echo "FAIL replica $row $entry: want $want, langc eval $a, replicatool $b"
    replica_bad=$((replica_bad + 1))
    fail=$((fail + 1))
  fi
  case "$row $entry" in
    "h"*" rep_tip") hrows=$((hrows + 1)) ;;
    "m"*" merge_tip") mrows=$((mrows + 1)) ;;
    "ap"*" step_apply") arows=$((arows + 1)) ;;
  esac
  case "$row $entry $b" in
    "h4 rep_tip "*) tip=$b ;;
    "mAB merge_tip "*) mtip=$b ;;
    "ap4 step_apply "*) astate=$b ;;
    "badsig cert_verify 1" | "badlink cert_verify 2" | "fork rep_merge 3") refused=$((refused + 1)) ;;
  esac
done < test/replica/history.txt
# The tally route (R-E11, R-E13). build/tallytool lang writes the 19 lines
# of test/replica/tally.txt: ROW ENTRY WANT X0 .. Y3 B P K (B, P and K are
# list texts). langc eval and build/replicatool tally give WANT for each
# line. The WANT of each combine row tcLEN_C is the count of the J = 1 line
# of the same ballots in $tmp/rep (S6, R-E5).
build/tallytool lang > "$tmp/tally.txt" 2>&1 || true
cmp -s "$tmp/tally.txt" test/replica/tally.txt ||
  { echo "FAIL replica tally: build/tallytool lang is not test/replica/tally.txt"; fail=$((fail + 1)); }
routes=0
route_bad=0
tallies=0
tally_bad=0
while read -r row entry want x0 x1 x2 x3 y0 y1 y2 y3 tb tp tk; do
  a=$(build/langc eval replica/replica.lang "$entry" "$x0" "$x1" "$x2" "$x3" "$y0" "$y1" "$y2" "$y3" "$tb" "$tp" "$tk" < /dev/null 2>&1) || true
  b=$(build/replicatool tally "$entry" "$x0" "$x1" "$x2" "$x3" "$y0" "$y1" "$y2" "$y3" "$tb" "$tp" "$tk" < /dev/null 2>&1) || true
  routes=$((routes + 1))
  if [ "$a" != "$want" ] || [ "$b" != "$want" ]; then
    echo "FAIL replica route $row $entry: want $want, langc eval $a, replicatool $b"
    route_bad=$((route_bad + 1))
    fail=$((fail + 1))
  fi
  case "$row $entry" in
    "tc"*" combine")
      tlen=${row#tc}
      tlen=${tlen%_*}
      tcase=${row#*_}
      tkey="denote denCount$tlen 1"
      ti=$tlen
      while [ "$ti" -gt 0 ]; do
        ti=$((ti - 1))
        tkey="$tkey $(( (tcase >> ti) & 1 ))"
      done
      srep=$(awk -v k="$tkey => " 'index($0, k) == 1 { print substr($0, length(k) + 1) }' "$tmp/rep")
      tallies=$((tallies + 1))
      [ "$srep" = "$want" ] ||
        { echo "FAIL replica tally $row: want $want, the S6 rep line gives $srep"; tally_bad=$((tally_bad + 1)); fail=$((fail + 1)); }
      ;;
  esac
  case "$row $entry $b" in
    "badballot ballot_verify 7" | "badpart partial_verify 8") refused=$((refused + 1)) ;;
  esac
done < test/replica/tally.txt
# The amend check (R-E19, R-E20). Each line of test/replica/amend.txt is
# ROW WANT TEXT: TEXT is the eval text of a Stack of opcode words, the
# last opcode first (R-E14). langc eval and build/replicatool amend give
# WANT.
amends=0
accepted=0
while read -r row want text; do
  a=$(build/langc eval replica/replica.lang amend_accept "$text" < /dev/null 2>&1) || true
  b=$(build/replicatool amend "$text" < /dev/null 2>&1) || true
  amends=$((amends + 1))
  if [ "$a" != "$want" ] || [ "$b" != "$want" ]; then
    echo "FAIL replica amend $row: want $want, langc eval $a, replicatool $b"
    fail=$((fail + 1))
  fi
  case "$row $b" in
    "ill 4" | "notfhe 5" | "corebrk 6") refused=$((refused + 1)) ;;
    "accept 0") accepted=$((accepted + 1)) ;;
  esac
done < test/replica/amend.txt
[ "$replicas" = 25 ] || { echo "FAIL replica: $replicas lines, want 25"; fail=$((fail + 1)); }
[ "$tip" = 4 ] || { echo "FAIL replica history: tip $tip, want 4"; fail=$((fail + 1)); }
[ "$mrows $mtip" = "3 4" ] || { echo "FAIL replica merge: $mrows rows, tip $mtip, want 3 rows, tip 4"; fail=$((fail + 1)); }
[ "$arows $astate" = "3 4" ] || { echo "FAIL replica apply: $arows rows, state $astate, want 3 rows, state 4"; fail=$((fail + 1)); }
[ "$routes" = 19 ] || { echo "FAIL replica route: $routes lines, want 19"; fail=$((fail + 1)); }
[ "$tallies" = 14 ] || { echo "FAIL replica tally: $tallies combine rows, want 14"; fail=$((fail + 1)); }
[ "$amends" = 4 ] || { echo "FAIL replica amend: $amends lines, want 4"; fail=$((fail + 1)); }
[ "$accepted" = 1 ] || { echo "FAIL replica accept: $accepted of 1"; fail=$((fail + 1)); }
[ "$refused" = 8 ] || { echo "FAIL replica refusals: $refused of 8"; fail=$((fail + 1)); }
echo "replica: $replicas cases, $replica_bad mismatches"
echo "replica history: $((hrows - 1)) steps, tip $tip"
echo "replica merge: $mrows rows, tip $mtip"
echo "replica apply: $arows rows, state $astate"
echo "replica route: $routes cases, $route_bad mismatches"
echo "replica tally: $tallies cases, $tally_bad mismatches"
echo "replica accept: $accepted of 1"
echo "replica refusals: $refused of 8"
rm -rf "$tmp"

# design/DESIGN.md is verbatim and can hold a dash (as bridge-lang, ruling 2026-10-09).
if rg -n -g '!design/DESIGN.md' '\x{2013}|\x{2014}' . >/dev/null; then
  echo "FAIL: an em-dash or en-dash is in the kit"
  fail=$((fail + 1))
fi
echo "gate: $fail failures"
[ "$fail" -eq 0 ]
