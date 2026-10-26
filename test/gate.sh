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

# S4 O64: `langc laws` and the `check --json` law counts agree on the 7 laws.
build/langc laws examples/threshold.lang >"$tmp/laws" 2>&1 || { echo "FAIL laws examples/threshold.lang: exit $?"; fail=$((fail + 1)); }
[ "$(tail -n 1 "$tmp/laws")" = 'laws: 7 of 7 discharged' ] || { echo "FAIL laws: want 7 of 7 discharged"; fail=$((fail + 1)); }
build/langc check --json examples/threshold.lang 2>/dev/null | rg -q -F '"laws":{"discharged":7,"total":7}' ||
  { echo "FAIL check --json examples/threshold.lang: want laws 7 of 7"; fail=$((fail + 1)); }
build/langc laws test/json/laws.lang >/dev/null 2>&1 && { echo "FAIL laws test/json/laws.lang: want exit 1"; fail=$((fail + 1)); }
# A parse failure keeps the parsed laws open, with the same counts as JSON.
law_status=0
build/langc laws test/json/PARSE_law.lang >"$tmp/laws-partial" 2>"$tmp/err" || law_status=$?
[ "$law_status" -eq 1 ] || { echo "FAIL laws partial parse: want exit 1, got $law_status"; fail=$((fail + 1)); }
printf 'law identity open\nlaws: 0 of 1 discharged\n' >"$tmp/laws-want"
cmp -s "$tmp/laws-want" "$tmp/laws-partial" || { echo "FAIL laws partial parse: want the open law and summary"; fail=$((fail + 1)); }
rg -q '^langc: PARSE_EXPECT: ' "$tmp/err" || { echo "FAIL laws partial parse: want PARSE_EXPECT"; fail=$((fail + 1)); }
echo "$(tail -n 1 "$tmp/laws")"

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
rm -rf "$tmp"

# design/DESIGN.md is verbatim and can hold a dash (as bridge-lang, ruling 2026-10-09).
if rg -n -g '!design/DESIGN.md' '\x{2013}|\x{2014}' . >/dev/null; then
  echo "FAIL: an em-dash or en-dash is in the kit"
  fail=$((fail + 1))
fi
echo "gate: $fail failures"
[ "$fail" -eq 0 ]
