/* NEW (quorum-lang S11 H5 C3): the IVC host. It holds the circuit selector, the caps, the one static
   key and the check of a compressed proof. test/ivctool.c and the host entry point use it. */
#ifndef LANG_CRYPTO_IVCHOST_H
#define LANG_CRYPTO_IVCHOST_H

#include <stddef.h>
#include <stdint.h>

#include "crypto/bn254.h"
#include "crypto/novacomp.h"
#include "crypto/novaivc.h"
#include "crypto/poseidon.h"
#include "crypto/r1cs.h"
#include "crypto/stepgadget.h"

/* The static storage has the caps of real F (test/ivch4.c). The F_t caps
   are the caps of the IVC and comp rows of test/ivcr1cs.c, or larger. */
#define IVC_PG 524288u
#define IVC_PVARS 524288u
#define IVC_PROWS 524288u
#define IVC_PTERMS 3145728u
#define IVC_PBUCKETS 262144u
#define IVC_SG 65536u
#define IVC_SVARS 65536u
#define IVC_SROWS 65536u
#define IVC_STERMS 524288u
#define IVC_SBUCKETS 65536u
#define IVC_CP 524288u
#define IVC_CPB 262144u
#define IVC_CS 65536u
#define IVC_CSB 16384u
#define IVC_FT_PG 65536u
#define IVC_FT_PVARS 65536u
#define IVC_FT_PROWS 65536u
#define IVC_FT_PTERMS 524288u
#define IVC_FT_PBUCKETS 65536u
#define IVC_FT_CP 65536u
#define IVC_FT_CPB 16384u

/* The circuit selector (the ivctool selector values). */
typedef enum { IVC_FT = 0, IVC_REAL_F = 1 } IvcCircuit;

/* The verdicts. q_ivc_verify (import 12) gives the verdict as a ℕ (S11 H5 C4,
   Q-S11-23 (a)): IVC_BAD_CIRCUIT is a circuit tag above IVC_REAL_F. */
typedef enum {
  IVC_OK, IVC_BAD_READ, IVC_BAD_DECODE, IVC_BAD_PUBLIC, IVC_BAD_PROOF, IVC_BAD_CIRCUIT
} IvcVerdict;

/* The CTX of the step callback: the PoseidonParams of F_t, the case of
   the step (the witness of real F), HEAD (the head before the step) and
   PKB (the group PK, x then y) for the host input check of F_t, and BAD
   (1 for the bad certificate). */
typedef struct {
  const PoseidonParams *params;
  const void *s; /* a StepCase of crypto/stepcase.h */
  const unsigned char *head;
  const unsigned char *pkb;
  int bad;
} IvcCtx;

/* The callback and the caps of one circuit. */
typedef struct {
  NovaStepFn fn;
  size_t p_g;
  size_t p_vars;
  size_t p_rows;
  size_t p_terms;
  size_t p_buckets;
  size_t c_p;
  size_t c_pb;
} IvcCaps;

/* The public input of verify. PK is x, then y. */
typedef struct {
  Fe z0[STEP_GADGET_Z];
  Fe zk[STEP_GADGET_Z];
  uint64_t count;
  Fe pk[2];
} IvcPublic;

/* The callback counters of F_real (the bad witness and the refused certificate). */
extern size_t ivc_host_bad_seen;
extern size_t ivc_host_cert_refused;

/* F_t and F_real (the step callbacks), and the caps of circuit C. */
void ivc_host_ft(R1cs *cs, uint32_t out[STEP_GADGET_Z], const uint32_t in[STEP_GADGET_Z], const void *ctx);
void ivc_host_real(R1cs *cs, uint32_t out[STEP_GADGET_Z], const uint32_t in[STEP_GADGET_Z], const void *ctx);
void ivc_host_caps(IvcCircuit c, IvcCaps *cp);

/* The setup of circuit C (S is a StepCase). A setup for another circuit replaces the one static key. */
int ivc_host_setup(IvcCircuit c, IvcCtx *ctx, const void *s, const unsigned char *head, const unsigned char *pkb);

/* The lazy setup of circuit C on the h4 fixture. It returns 1 when the key of C is ready. */
int ivc_host_ready(IvcCircuit c);

/* The one static key (nova_ivc_prove_step needs it non-const) and the comp key. */
NovaIvcKey *ivc_host_key(void);
const NovaCompKey *ivc_host_ck(void);

/* Decode (the canonical checks), the public compare, then nova_comp_verify. */
IvcVerdict ivc_host_check(const unsigned char *b, size_t len, const IvcPublic *pub);

/* The guest input of q_ivc_verify (import 12): z0 and zk (a W20 each, 5
   values of 32 bytes), PK (a W8, x then y) and the count limit. */
#define IVC_HOST_Z_BYTES (32u * STEP_GADGET_Z)
#define IVC_HOST_PK_BYTES 64u
#define IVC_HOST_COUNT_MAX 1000000u

/* The check of q_ivc_verify (the guest gives the verdict as a ℕ). C above
   IVC_REAL_F: IVC_BAD_CIRCUIT. A value of Z0, ZK or PK not below p (SECP_FP,
   as ivc_fes of test/ivctool.c) or COUNT above IVC_HOST_COUNT_MAX:
   IVC_BAD_PUBLIC.
   For COUNT = 0, the proof is empty (N = 0): Z0 must equal ZK and its PK
   fields must equal PK. This identity case returns before key setup.
   For COUNT > 0, lazily set up C (a failed setup: IVC_BAD_READ), then
   B holds N proof words (8 bytes each, big endian): N not ceil(size / 8) or
   a pad byte not 0: IVC_BAD_READ. Then ivc_host_check. No heap. */
IvcVerdict ivc_host_verify_bytes(uint64_t c, const unsigned char *b, size_t n,
                                 const unsigned char z0[IVC_HOST_Z_BYTES],
                                 const unsigned char zk[IVC_HOST_Z_BYTES], uint64_t count,
                                 const unsigned char pk[IVC_HOST_PK_BYTES]);

/* The prover imports of the wasm host (S11 H5, Q-S11-26 (a)), F_t only.
   q_ivc_start (13) and q_ivc_extend (14) give the handle IVC_HOST_HANDLE +
   gen, or a code below. gen is a static counter: each start, each good
   extend, each failed extend and each ivc_host_setup bump it, thus an old
   handle is stale. A refusal or key setup invalidates the held run;
   guessing the next generation does not resume it. q_ivc_word (15) gives
   word K of the held compressed
   bytes (8 bytes, big endian, as q_ivc_verify reads them), or 0. */
#define IVC_HOST_HANDLE 16u
/* The byte cap of the held compressed proof (1854 words of 8 bytes). */
#define IVC_HOST_RUN_BYTES 14832u

/* The refusal codes of q_ivc_start and q_ivc_extend (1 to 15). */
typedef enum {
  IVC_HOST_BAD_CIRCUIT = 1, /* C is not IVC_FT: real F stays outside the gate */
  IVC_HOST_BAD_READ = 2,    /* a record does not fit (the wasm host) */
  IVC_HOST_BAD_PUBLIC = 3,  /* a value of Z0 or PK is not below p */
  IVC_HOST_BAD_SETUP = 4,   /* the lazy setup of F_t failed */
  IVC_HOST_STALE = 5,       /* no live run or the generation differs */
  IVC_HOST_CERT_REFUSED = 6, /* the native FROST check refused the cert */
  IVC_HOST_FOLD_FAILED = 7,  /* nova_ivc_prove_step failed */
  IVC_HOST_COMP_FAILED = 8   /* the compression failed */
} IvcHostCode;

/* The genesis head (S11 H5-d, Q-S11-33 (a)): the HEAD of ivc_host_start for
   a run from step 1 (the head of ivc_chain of test/ivctool.c). */
void ivc_host_genesis(unsigned char head[32]);

/* Start the held proof at Z0 (k = 0, no bytes). PK (x, then y) and HEAD are
   the group key and the head before step 1, and must match the PK fields
   and head limbs of Z0. */
uint64_t ivc_host_start(uint64_t c, const unsigned char pk[IVC_HOST_PK_BYTES], const unsigned char head[32],
                        const unsigned char z0[IVC_HOST_Z_BYTES]);

/* One step on the held proof of handle H: BODY (a W4) and CERT (a W12: R x,
   R y, z), then the compression of the new proof into the held bytes. */
uint64_t ivc_host_extend(uint64_t h, const unsigned char body[32], const unsigned char cert[96]);

/* Word K of the held bytes of handle H. A stale handle, no bytes or K at or
   past the word count give 0. */
uint64_t ivc_host_word(uint64_t h, uint64_t k);

#endif
