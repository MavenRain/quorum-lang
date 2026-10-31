# Builds the tcc-wasm kit with TinyCC. See README.md.
TCC ?= tcc
CC ?= cc
CFLAGS = -std=c99 -Wall -Werror -Isrc
CLANG_FLAGS = -std=c99 -Wall -Wextra -Wswitch-enum -Werror -fsyntax-only -Isrc
FRONT = src/front/base.c src/front/lexer.c src/front/parser.c src/front/front.c src/front/print.c src/front/json.c src/front/jsonin.c src/front/eval.c src/front/check.c src/front/lower.c
TARGET = src/wasm.c
SRC = src/main.c src/front/basenames.c $(FRONT) $(TARGET)
FRONT_TOOL = test/fronttool.c $(filter-out src/front/front.c src/front/lower.c,$(FRONT)) $(CRYPTO)
CRYPTO = src/crypto/keccak.c src/crypto/u256.c src/crypto/bn254.c src/crypto/elgamal.c src/crypto/threshold.c src/crypto/sigma.c src/crypto/dkg.c src/crypto/sha256.c src/crypto/xmd.c src/crypto/secp256k1.c src/crypto/frost.c src/crypto/bgw.c src/crypto/secq256k1.c src/crypto/poseidon.c src/crypto/gens.c src/crypto/msm.c src/crypto/r1cs.c src/crypto/poseidongadget.c src/crypto/sha256gadget.c src/crypto/ec7gadget.c src/crypto/stepgadget.c src/crypto/nova.c src/crypto/novagadget.c src/crypto/novaivc.c
TALLY_TOOL = test/tallytool.c $(CRYPTO)
FROST_TOOL = test/frosttool.c $(CRYPTO)
MPC_TOOL = test/mpctool.c $(CRYPTO)
IVC_TOOL = test/ivccrypto.c $(CRYPTO)
R1CS_TOOL = test/ivcr1cs.c $(CRYPTO)
H4_TOOL = test/ivch4.c $(CRYPTO)
HEADERS = $(wildcard src/*.h src/front/*.h src/crypto/*.h)

.PHONY: build check check-clang clean ivc-h4

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
# The run takes about 40 minutes with TCC, thus build/ivch4 is not in
# build or in check: `make ivc-h4` builds and runs it.
build/ivch4: $(H4_TOOL) $(HEADERS) test/stepcase.h
	mkdir -p build
	$(TCC) $(CFLAGS) -o build/ivch4 $(H4_TOOL)

ivc-h4: build/ivch4
	build/ivch4

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

clean:
	rm -rf build
