#!/bin/sh
# Regression checks for the staged compiler review.
set -eu
tmp=$(mktemp -d "${TMPDIR:-/tmp}/lang-review.XXXXXX")
trap 'rm -rf "$tmp"' EXIT HUP INT TERM

cat >"$tmp/capture.lang" <<'EOF'
keep : ℕ → ℕ → ℕ
keep x y = x

value : Unit → ℕ → ℕ → ℕ
value u y = keep y
EOF
normal=$(build/langc eval "$tmp/capture.lang" value)
printf 'value : Unit → ℕ → ℕ → ℕ\nvalue = %s\n\nanswer : ℕ\nanswer = value unit 4 9\n' "$normal" >"$tmp/roundtrip.lang"
test "$(build/langc eval "$tmp/roundtrip.lang" answer)" = 4

# Reducing a closure can expose a constructor with the binder's old name.
cat >"$tmp/constructor.lang" <<'EOF'
constant : Unit → Color
constant u = red

value : Unit → Color
value red = constant red
EOF
normal=$(build/langc eval "$tmp/constructor.lang" value)
printf 'value : Unit → Color\nvalue = %s\n\nanswer : ℕ\nanswer = fold 1 2 3 (value unit)\n' "$normal" >"$tmp/roundtrip.lang"
test "$(build/langc eval "$tmp/roundtrip.lang" answer)" = 1

# A generated eta binder must also print as a source identifier.
printf 'value : Unit → ℕ → ℕ → ℕ\nvalue u = natAdd\n' >"$tmp/eta.lang"
normal=$(build/langc eval "$tmp/eta.lang" value)
printf 'value : Unit → ℕ → ℕ → ℕ\nvalue = %s\n\nanswer : ℕ\nanswer = value unit 4 9\n' "$normal" >"$tmp/roundtrip.lang"
test "$(build/langc eval "$tmp/roundtrip.lang" answer)" = 13

# More than 64 live binders used to read past the printer's name table.
awk 'BEGIN {
  printf "value : "; for (i = 0; i < 70; i++) printf "Unit → ";
  printf "Unit\nvalue"; for (i = 0; i < 70; i++) printf " u%d", i;
  print " = u69"
}' >"$tmp/binders.lang"
awk 'BEGIN {
  printf "λ"; for (i = 0; i < 70; i++) printf " u%d", i;
  print " → u69"
}' >"$tmp/want"
build/langc eval "$tmp/binders.lang" value >"$tmp/got"
cmp "$tmp/want" "$tmp/got"

# bind keeps nothing and can change the success type.
cat >"$tmp/maybe.lang" <<'EOF'
input : Maybe ℕ
input = nothing

output : Maybe Bool
output = bind input (λ (x : ℕ) → just true)

right : Maybe ℕ
right = just 7

mapped : Maybe Bool
mapped = bind right (λ (x : ℕ) → just true)
EOF
test "$(build/langc eval "$tmp/maybe.lang" output)" = 'nothing'
test "$(build/langc eval "$tmp/maybe.lang" mapped)" = 'just true'
# A truncated normal form must not be reported as successful evaluation.
printf 'value : Stack\nvalue = fold (λ (s : Stack) → push 0 s) bottom 10000\n' >"$tmp/large.lang"
status=0
build/langc eval "$tmp/large.lang" value >"$tmp/got" 2>"$tmp/err" || status=$?
test "$status" = 1
test ! -s "$tmp/got"
case "$(cat "$tmp/err")" in
  'langc: EVAL_PRINT:'*) ;;
  *) exit 1 ;;
esac
# Compiler-generated exports must not duplicate a source entry name.
for name in memory heap_base; do
  printf '%s : Stack → ℕ\n%s s = fold 0 (λ (x : ℕ) (a : ℕ) → natAdd x a) s\n' "$name" "$name" >"$tmp/export.lang"
  status=0
  build/langc build "$tmp/export.lang" -o "$tmp/export.wasm" >"$tmp/got" 2>"$tmp/err" || status=$?
  test "$status" = 1
  case "$(cat "$tmp/err")" in
    'langc: REFUSE_NAME:'*) ;;
    *) exit 1 ;;
  esac
  # Without the generated exports, both names remain valid entries.
  printf '%s : ℕ → ℕ\n%s x = x\n' "$name" "$name" >"$tmp/export.lang"
  build/langc build "$tmp/export.lang" -o "$tmp/export.wasm"
  test "$(node test/run-wasm.mjs "$tmp/export.wasm" "$name" 7)" = 7
done
echo 'review regressions: passed'
