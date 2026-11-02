# Builds the tcc-wasm kit with TinyCC. See README.md.
TCC ?= tcc
CC ?= cc
CFLAGS = -std=c99 -Wall -Werror -Isrc
CLANG_FLAGS = -std=c99 -Wall -Wextra -Wswitch-enum -Werror -fsyntax-only -Isrc
FRONT = src/front/base.c src/front/lexer.c src/front/parser.c src/front/front.c src/front/print.c src/front/json.c src/front/jsonin.c src/front/eval.c src/front/check.c src/front/lower.c
TARGET = src/wasm.c
SRC = src/main.c src/front/basenames.c $(FRONT) $(TARGET)
FRONT_TOOL = test/fronttool.c $(filter-out src/front/front.c src/front/lower.c,$(FRONT)) $(CRYPTO)
CRYPTO = src/crypto/keccak.c src/crypto/u256.c src/crypto/bn254.c src/crypto/elgamal.c src/crypto/threshold.c src/crypto/sigma.c src/crypto/dkg.c src/crypto/sha256.c src/crypto/xmd.c src/crypto/secp256k1.c src/crypto/frost.c src/crypto/bgw.c src/crypto/secq256k1.c src/crypto/poseidon.c src/crypto/gens.c src/crypto/msm.c src/crypto/r1cs.c src/crypto/poseidongadget.c src/crypto/sha256gadget.c src/crypto/ec7gadget.c src/crypto/stepgadget.c src/crypto/nova.c src/crypto/novagadget.c src/crypto/novaivc.c src/crypto/ipa.c src/crypto/spartan.c src/crypto/novacomp.c
TALLY_TOOL = test/tallytool.c $(CRYPTO)
FROST_TOOL = test/frosttool.c $(CRYPTO)
MPC_TOOL = test/mpctool.c $(CRYPTO)
IVC_TOOL = test/ivccrypto.c $(CRYPTO)
R1CS_TOOL = test/ivcr1cs.c $(CRYPTO)
H4_TOOL = test/ivch4.c $(CRYPTO)
IVC_FIXTURE_TOOL = test/ivctool.c $(CRYPTO)
HEADERS = $(wildcard src/*.h src/front/*.h src/crypto/*.h)

.PHONY: build check check-clang clean ivc-check ivc-ft-verify ivc-h4 ivc-prove ivc-refusals ivc-size \
  ivc-tool-check ivc-verify

build: build/langc build/fronttool build/tallytool build/frosttool build/mpctool build/ivccrypto build/ivcr1cs build/replicatool build/tokproxy

build/domain.c: domain/domain.lang gen/embed.c
	mkdir -p build
	$(TCC) -run gen/embed.c domain/domain.lang build/domain.c

build/prelude.c: lib/prelude.lang gen/embed.c
	mkdir -p build
	$(TCC) -run gen/embed.c lib/prelude.lang build/prelude.c prelude

build/langc: $(SRC) $(CRYPTO) $(HEADERS) build/domain.c build/prelude.c
	$(TCC) $(CFLAGS) -o build/langc $(SRC) $(CRYPTO) build/domain.c build/prelude.c

build/fronttool: $(FRONT_TOOL) $(HEADERS)
	mkdir -p build
	$(TCC) $(CFLAGS) -o build/fronttool $(FRONT_TOOL)

build/tallytool: $(TALLY_TOOL) $(HEADERS)
	mkdir -p build
	$(TCC) $(CFLAGS) -o build/tallytool $(TALLY_TOOL)

build/frosttool: $(FROST_TOOL) $(HEADERS)
	mkdir -p build
	$(TCC) $(CFLAGS) -o build/frosttool $(FROST_TOOL)

build/mpctool: $(MPC_TOOL) $(HEADERS)
	mkdir -p build
	$(TCC) $(CFLAGS) -o build/mpctool $(MPC_TOOL)

# The token proxy of docs/TOKEN-BASELINE.md (O127).
build/tokproxy: test/tokproxy.c
	mkdir -p build
	$(TCC) $(CFLAGS) -o build/tokproxy test/tokproxy.c

# The replica host (O104, O105). langc writes build/replica.wasm, wasm2c
# translates it, and TCC compiles the translation with the shim
# src/w2c-tcc.h: TCC has no __builtin_add_overflow. Only the translation
# gets the shim. The tool compiles with CFLAGS. The wasm2c runtime and the
# link use the stock TCC flags. WABT is the wabt install prefix.
WABT ?= /opt/homebrew
WASM2C_INC = -I$(WABT)/include -I$(WABT)/share/wabt/wasm2c
WASM2C_RT = $(wildcard $(WABT)/share/wabt/wasm2c/*.c)

build/replica.wasm: build/langc replica/replica.lang
	build/langc build replica/replica.lang -o build/replica.wasm

build/replica.c: build/replica.wasm
	wasm2c build/replica.wasm -n replica -o build/replica.c

build/replica.o: build/replica.c src/w2c-tcc.h
	$(TCC) -Isrc -Ibuild $(WASM2C_INC) -include src/w2c-tcc.h -c build/replica.c -o build/replica.o

build/replicatool.o: test/replicatool.c build/replica.c $(HEADERS)
	$(TCC) $(CFLAGS) -Ibuild $(WASM2C_INC) -c test/replicatool.c -o build/replicatool.o

build/replicatool: build/replicatool.o build/replica.o $(CRYPTO)
	$(TCC) -Isrc $(WASM2C_INC) -o build/replicatool build/replicatool.o build/replica.o $(CRYPTO) $(WASM2C_RT) -lm

build/hostflags.wasm: build/langc test/host-flags.lang
	build/langc build test/host-flags.lang -o build/hostflags.wasm

build/hostflags.c: build/hostflags.wasm
	wasm2c build/hostflags.wasm -n hostflags -o build/hostflags.c

build/hostflags.o: build/hostflags.c src/w2c-tcc.h
	$(TCC) -Isrc -Ibuild $(WASM2C_INC) -include src/w2c-tcc.h -c build/hostflags.c -o build/hostflags.o

build/ivccrypto: $(IVC_TOOL) $(HEADERS) test/ivcvectors.h
	mkdir -p build
	$(TCC) $(CFLAGS) -o build/ivccrypto $(IVC_TOOL)

build/ivcr1cs: $(R1CS_TOOL) $(HEADERS) test/stepcase.h
	mkdir -p build
	$(TCC) $(CFLAGS) -o build/ivcr1cs $(R1CS_TOOL)

# One IVC step of h4 on the real F (C4d), P on N_P = 2^19 generators.
# The run takes about 72 minutes with TCC. This time is from a run with
# the mutant runs of build/ivcr1cs in parallel. Thus build/ivch4 is not
# in build or in check: `make ivc-h4` builds and runs it.
build/ivch4: $(H4_TOOL) $(HEADERS) test/stepcase.h
	mkdir -p build
	$(TCC) $(CFLAGS) -o build/ivch4 $(H4_TOOL)

ivc-h4: build/ivch4
	build/ivch4

# The IVC proof file tool of H4b (C2): size, generate, prove, verify and
# refusals for F_t (ft) or the real F (real-f). `ivctool refusals ft`
# takes about 13 minutes with TCC. Thus build/ivctool is not in build:
# `make ivc-tool-check` builds it and runs the 12 refusal rows, and
# ivc-check (below, called by check) calls ivc-tool-check.
# The target passes only on rc 0 and the last line
# `ivc tool: 12 rows, 0 mismatches`.
build/ivctool: $(IVC_FIXTURE_TOOL) $(HEADERS) test/stepcase.h
	mkdir -p build
	$(TCC) $(CFLAGS) -o build/ivctool $(IVC_FIXTURE_TOOL)

ivc-tool-check: build/ivctool
	build/ivctool refusals ft > build/ivctool-refusals.log 2>&1; rc=$$?; \
	cat build/ivctool-refusals.log; test $$rc -eq 0 && \
	test "$$(tail -n 1 build/ivctool-refusals.log)" = "ivc tool: 12 rows, 0 mismatches"

# The routine IVC rows of H4b (C4) on the F_t fixtures of test/ivc/ft/.
# Setup takes about 3 minutes in each ivctool process. Thus one
# `ivctool verify` process (one setup) verifies 10 groups in this order:
# proof-1, -3, -10 and -100 with their public input from chain.txt; the
# negative case (proof-3 with the head zk of proof-10); the verify cases
# of refusal-1.txt to refusal-5.txt. The refusal groups make verify exit
# with rc 1; all 10 verdicts must be present. The public input of each group is a
# set of arguments, separate from the proof bytes. ivc-size, ivc-verify
# and ivc-refusals read the lines of this run. ivc-prove and case 6 of
# ivc-refusals each run one `ivctool prove` process. Each target prints
# its row and passes only on the row below. `check` calls ivc-check
# serially (about 32 minutes with TCC, ivc-tool-check included).
IVC_FT = test/ivc/ft
IVC_REFUSAL_TXT = $(IVC_FT)/refusal-1.txt $(IVC_FT)/refusal-2.txt $(IVC_FT)/refusal-3.txt \
  $(IVC_FT)/refusal-4.txt $(IVC_FT)/refusal-5.txt
IVC_GROUPS_AWK = $$1 == "proof" { p = $$3; s = $$2 } $$1 == "z0" { z = $$2 } $$1 == "zk" { h = $$2 } \
  $$1 == "count" { c = $$2 } \
  $$1 == "pk" && p != "" { print p, z, h, c, $$2; P[s] = p; Z[s] = z; H[s] = h; C[s] = c; K[s] = $$2; p = "" } \
  END { print P[3], Z[3], H[10], C[3], K[3] }
IVC_SIZE_ROW = ivc size: 3 histories (1, 10, 100 steps), 14825 bytes each, 0 size mismatches
IVC_VERIFY_ROW = ivc verify: 4 of 4 (C)
IVC_PROVE_ROW = ivc prove: 3 steps, 0 byte mismatches
IVC_REFUSALS_ROW = ivc refusals: 6 of 6

ivc-ft-verify: build/ivctool
	awk '$(IVC_GROUPS_AWK)' $(IVC_FT)/chain.txt > build/ivc-ft-groups.txt
	awk 'FNR == 2 { print $$3, $$4, $$5, $$6, $$7 }' $(IVC_REFUSAL_TXT) >> build/ivc-ft-groups.txt
	build/ivctool verify ft $$(cat build/ivc-ft-groups.txt) > build/ivc-ft-verify.log 2>&1; rc=$$?; \
	echo "rc $$rc" >> build/ivc-ft-verify.log; cat build/ivc-ft-verify.log; test $$rc -eq 1
	awk 'index($$0, "ivc tool verify ft: ") == 1 { print substr($$0, 21) }' build/ivc-ft-verify.log \
	  > build/ivc-ft-verdicts.txt
	test "$$(wc -l < build/ivc-ft-verdicts.txt)" -eq 10

ivc-size: ivc-ft-verify
	n=$$(awk '$$1 == "ivc" && $$3 == "size" && $$4 == "ft:" { print $$5 }' build/ivc-ft-verify.log); \
	m=0; for steps in 1 10 100; do \
	  size=$$(wc -c < "$(IVC_FT)/proof-$$steps.bin") || exit 1; \
	  test "$$size" -eq "$$n" || m=$$((m + 1)); \
	done; \
	row="ivc size: 3 histories (1, 10, 100 steps), $$n bytes each, $$m size mismatches"; \
	echo "$$row"; test "$$row" = "$(IVC_SIZE_ROW)"

ivc-verify: ivc-ft-verify
	k=$$(awk 'NR <= 4 && $$0 == "ok"' build/ivc-ft-verdicts.txt | wc -l | tr -d ' '); \
	neg=$$(awk 'NR == 5' build/ivc-ft-verdicts.txt); \
	echo "ivc verify: negative case (proof-3 with the head zk of proof-10): $$neg"; \
	row="ivc verify: $$k of 4 (C)"; echo "$$row"; \
	test "$$neg" = "refused public input" && test "$$row" = "$(IVC_VERIFY_ROW)"

ivc-prove: build/ivctool
	rm -f build/ivc-prove-3.bin; \
	build/ivctool prove ft 0 3 build/ivc-prove-3.bin > build/ivc-prove.log 2>&1; rc=$$?; \
	cat build/ivc-prove.log; \
	m=$$(cmp -l build/ivc-prove-3.bin $(IVC_FT)/proof-3.bin 2>&1 | wc -l | tr -d ' '); \
	row="ivc prove: 3 steps, $$m byte mismatches"; echo "$$row"; \
	test $$rc -eq 0 && test "$$row" = "$(IVC_PROVE_ROW)"

ivc-refusals: ivc-ft-verify
	awk 'FNR == 3 { sub(/^result /, ""); print }' $(IVC_REFUSAL_TXT) > build/ivc-ft-expect.txt
	rm -f build/ivc-refusal-6.bin; \
	build/ivctool prove ft 0 10 build/ivc-refusal-6.bin 5 > build/ivc-refusal-6.log 2>&1; rc=$$?; \
	cat build/ivc-refusal-6.log; \
	a=$$(awk 'NR == FNR { e[FNR] = $$0; next } FNR >= 6 && $$0 == e[FNR - 5]' build/ivc-ft-expect.txt \
	  build/ivc-ft-verdicts.txt | wc -l | tr -d ' '); \
	b=0; test $$rc -eq 1 && test ! -e build/ivc-refusal-6.bin && \
	  test "$$(tail -n 2 build/ivc-refusal-6.log)" = \
	  "$$(awk 'FNR >= 4 { sub(/^result /, ""); print }' $(IVC_FT)/refusal-6.txt)" && b=1; \
	row="ivc refusals: $$((a + b)) of 6"; echo "$$row"; test "$$row" = "$(IVC_REFUSALS_ROW)"

ivc-check: ivc-size ivc-verify ivc-prove ivc-refusals ivc-tool-check

build/hostflagtool: test/hostflagtool.c build/hostflags.o
	$(TCC) $(CFLAGS) -Ibuild $(WASM2C_INC) -o build/hostflagtool test/hostflagtool.c build/hostflags.o $(WASM2C_RT) -lm

build/replicaparse: test/replicaparse.c test/replicatool.c build/replica.o $(CRYPTO) $(HEADERS)
	$(TCC) $(CFLAGS) -Ibuild $(WASM2C_INC) -o build/replicaparse test/replicaparse.c build/replica.o $(CRYPTO) $(WASM2C_RT) -lm

check-clang: build/domain.c build/prelude.c build/hostflags.c build/replica.c
	$(CC) $(CLANG_FLAGS) $(SRC) build/domain.c build/prelude.c
	$(CC) $(CLANG_FLAGS) $(FRONT_TOOL)
	$(CC) $(CLANG_FLAGS) $(TALLY_TOOL)
	$(CC) $(CLANG_FLAGS) $(FROST_TOOL)
	$(CC) $(CLANG_FLAGS) $(MPC_TOOL)
	$(CC) $(CLANG_FLAGS) $(IVC_TOOL)
	$(CC) $(CLANG_FLAGS) $(R1CS_TOOL)
	$(CC) $(CLANG_FLAGS) $(H4_TOOL)
	$(CC) $(CLANG_FLAGS) $(IVC_FIXTURE_TOOL)
	$(CC) $(CLANG_FLAGS) test/tokproxy.c
	$(CC) $(CLANG_FLAGS) -Ibuild $(WASM2C_INC) test/hostflagtool.c
	$(CC) $(CLANG_FLAGS) -Ibuild $(WASM2C_INC) test/replicaparse.c

check: build/langc build/fronttool build/tallytool build/frosttool build/mpctool build/ivccrypto build/ivcr1cs build/replicatool build/hostflagtool build/replicaparse build/tokproxy check-clang
	sh test/gate.sh
	sh test/review.sh
	build/fronttool
	build/hostflagtool
	build/replicaparse
	build/tallytool
	build/frosttool
	build/mpctool
	build/ivccrypto
	build/ivcr1cs
	$(MAKE) -j 1 ivc-check

clean:
	rm -rf build
