typedef struct secp256k1_context_struct secp256k1_context;

typedef struct {
    unsigned char data[64];
} secp256k1_pubkey;

typedef struct {
    unsigned char data[64];
} secp256k1_ecdsa_signature;

typedef int (*secp256k1_nonce_function)(
    unsigned char *nonce32,
    const unsigned char *msg32,
    const unsigned char *key32,
    const unsigned char *algo16,
    void *data,
    unsigned int attempt
);

#define SECP256K1_FLAGS_TYPE_MASK ...
#define SECP256K1_FLAGS_TYPE_CONTEXT ...
#define SECP256K1_FLAGS_TYPE_COMPRESSION ...
#define SECP256K1_FLAGS_BIT_CONTEXT_VERIFY ...
#define SECP256K1_FLAGS_BIT_CONTEXT_SIGN ...
#define SECP256K1_FLAGS_BIT_COMPRESSION ...

#define SECP256K1_CONTEXT_VERIFY ...
#define SECP256K1_CONTEXT_SIGN ...
#define SECP256K1_CONTEXT_NONE ...

#define SECP256K1_EC_COMPRESSED ...
#define SECP256K1_EC_UNCOMPRESSED ...

secp256k1_context* secp256k1_context_create(
    unsigned int flags
);

secp256k1_context* secp256k1_context_clone(
    const secp256k1_context* ctx
);

void secp256k1_context_destroy(
    secp256k1_context* ctx
);

void secp256k1_context_set_illegal_callback(
    secp256k1_context* ctx,
    void (*fun)(const char* message, void* data),
    const void* data
);

void secp256k1_context_set_error_callback(
    secp256k1_context* ctx,
    void (*fun)(const char* message, void* data),
    const void* data
);

int secp256k1_ec_pubkey_parse(
    const secp256k1_context* ctx,
    secp256k1_pubkey* pubkey,
    const unsigned char *input,
    size_t inputlen
);

int secp256k1_ec_pubkey_serialize(
    const secp256k1_context* ctx,
    unsigned char *output,
    size_t *outputlen,
    const secp256k1_pubkey* pubkey,
    unsigned int flags
);

int secp256k1_ecdsa_signature_parse_compact(
    const secp256k1_context* ctx,
    secp256k1_ecdsa_signature* sig,
    const unsigned char *input64
);

int secp256k1_ecdsa_signature_parse_der(
    const secp256k1_context* ctx,
    secp256k1_ecdsa_signature* sig,
    const unsigned char *input,
    size_t inputlen
);

int secp256k1_ecdsa_signature_serialize_der(
    const secp256k1_context* ctx,
    unsigned char *output,
    size_t *outputlen,
    const secp256k1_ecdsa_signature* sig
);

int secp256k1_ecdsa_signature_serialize_compact(
    const secp256k1_context* ctx,
    unsigned char *output64,
    const secp256k1_ecdsa_signature* sig
);

int secp256k1_ecdsa_verify(
    const secp256k1_context* ctx,
    const secp256k1_ecdsa_signature *sig,
    const unsigned char *msg32,
    const secp256k1_pubkey *pubkey
);

int secp256k1_ecdsa_signature_normalize(
    const secp256k1_context* ctx,
    secp256k1_ecdsa_signature *sigout,
    const secp256k1_ecdsa_signature *sigin
);

int secp256k1_ecdsa_sign(
    const secp256k1_context* ctx,
    secp256k1_ecdsa_signature *sig,
    const unsigned char *msg32,
    const unsigned char *seckey,
    secp256k1_nonce_function noncefp,
    const void *ndata
);

int secp256k1_ec_seckey_verify(
    const secp256k1_context* ctx,
    const unsigned char *seckey
);

int secp256k1_ec_pubkey_create(
    const secp256k1_context* ctx,
    secp256k1_pubkey *pubkey,
    const unsigned char *seckey
);

int secp256k1_ec_privkey_negate(
    const secp256k1_context* ctx,
    unsigned char *seckey
);

int secp256k1_ec_pubkey_negate(
    const secp256k1_context* ctx,
    secp256k1_pubkey *pubkey
);

int secp256k1_ec_privkey_tweak_add(
    const secp256k1_context* ctx,
    unsigned char *seckey,
    const unsigned char *tweak
);

int secp256k1_ec_pubkey_tweak_add(
    const secp256k1_context* ctx,
    secp256k1_pubkey *pubkey,
    const unsigned char *tweak
);

int secp256k1_ec_privkey_tweak_mul(
    const secp256k1_context* ctx,
    unsigned char *seckey,
    const unsigned char *tweak
);

int secp256k1_ec_pubkey_tweak_mul(
    const secp256k1_context* ctx,
    secp256k1_pubkey *pubkey,
    const unsigned char *tweak
);

int secp256k1_context_randomize(
    secp256k1_context* ctx,
    const unsigned char *seed32
);

int secp256k1_ec_pubkey_combine(
		const secp256k1_context* ctx,
		secp256k1_pubkey *out,
		const secp256k1_pubkey * const * ins,
		size_t n
);

int secp256k1_ec_privkey_tweak_inv(
    const secp256k1_context* ctx,
    unsigned char *seckey
);

int secp256k1_ec_privkey_tweak_neg(
    const secp256k1_context* ctx,
    unsigned char *seckey
);

/* This def doesn't work yet - further testing required.
int secp256k1_tagged_sha256(
		const secp256k1_context* ctx,
		unsigned char *hash32,
		const unsigned char *tag,
		size_t taglen,
		const unsigned char *msg,
		size_t msglen
);
*/

typedef struct secp256k1_scratch_space_struct secp256k1_scratch_space;

typedef struct secp256k1_aggsig_context_struct secp256k1_aggsig_context;

typedef struct {
    unsigned char data[32];
}   secp256k1_aggsig_partial_signature;

secp256k1_aggsig_context* secp256k1_aggsig_context_create(
    const secp256k1_context *ctx,
    const secp256k1_pubkey *pubkeys,
    size_t n_pubkeys,
    const unsigned char *seed
);

void secp256k1_aggsig_context_destroy(
    secp256k1_aggsig_context *aggctx
);

int secp256k1_aggsig_generate_nonce(
    const secp256k1_context* ctx,
    secp256k1_aggsig_context* aggctx,
    size_t index
);

int secp256k1_aggsig_partial_sign(
    const secp256k1_context* ctx,
    secp256k1_aggsig_context* aggctx,
    secp256k1_aggsig_partial_signature *partial,
    const unsigned char *msg32,
    const unsigned char *seckey32,
    size_t index
);

int secp256k1_aggsig_combine_signatures(
    const secp256k1_context* ctx,
    secp256k1_aggsig_context* aggctx,
    unsigned char *sig64,
    const secp256k1_aggsig_partial_signature *partial,
    size_t n_sigs
);

int secp256k1_aggsig_add_signatures_single(
    const secp256k1_context* ctx,
    unsigned char *sig64,
    const unsigned char** sigs,
    size_t num_sigs,
    const secp256k1_pubkey* pubnonce_total
);

int secp256k1_aggsig_verify_single(
    const secp256k1_context* ctx,
    const unsigned char *sig64,
    const unsigned char *msg32,
    const secp256k1_pubkey *pubnonce,
    const secp256k1_pubkey *pubkey,
    const secp256k1_pubkey *pubkey_total,
    const secp256k1_pubkey *extra_pubkey,
    const int is_partial
);

int secp256k1_aggsig_export_secnonce_single(
    const secp256k1_context* ctx,
    unsigned char* secnonce32,
    const unsigned char* seed
);

int secp256k1_aggsig_sign_single(
    const secp256k1_context* ctx,
    unsigned char *sig64,
    const unsigned char *msg32,
    const unsigned char *seckey32,
    const unsigned char* secnonce32,
    const unsigned char* extra32,
    const secp256k1_pubkey *pubnonce_for_e,
    const secp256k1_pubkey* pubnonce_total,
    const secp256k1_pubkey* pubkey_for_e,
    const unsigned char* seed
);

int secp256k1_aggsig_verify(
    const secp256k1_context* ctx,
    secp256k1_scratch_space* scratch,
    const unsigned char *sig64,
    const unsigned char *msg32,
    const secp256k1_pubkey *pubkeys,
    size_t n_pubkeys
);


int secp256k1_aggsig_build_scratch_and_verify(
    const secp256k1_context* ctx,
    const unsigned char *sig64,
    const unsigned char *msg32,
    const secp256k1_pubkey *pubkeys,
    size_t n_pubkeys
);

typedef struct {
    unsigned char data[64];
} secp256k1_generator;

int secp256k1_generator_parse(
    const secp256k1_context* ctx,
    secp256k1_generator* commit,
    const unsigned char *input
);

int secp256k1_generator_serialize(
    const secp256k1_context* ctx,
    unsigned char *output,
    const secp256k1_generator* commit
);

int secp256k1_generator_generate(
    const secp256k1_context* ctx,
    secp256k1_generator* gen,
    const unsigned char *seed32
);

int secp256k1_generator_generate_blinded(
    const secp256k1_context* ctx,
    secp256k1_generator* gen,
    const unsigned char *key32,
    const unsigned char *blind32
);

typedef struct {
    unsigned char data[64];
} secp256k1_pedersen_commitment;

int secp256k1_pedersen_commitment_parse(
    const secp256k1_context* ctx,
    secp256k1_pedersen_commitment* commit,
    const unsigned char *input
);

int secp256k1_pedersen_commitment_serialize(
    const secp256k1_context* ctx,
    unsigned char *output,
    const secp256k1_pedersen_commitment* commit
);

int secp256k1_pedersen_commit(
    const secp256k1_context* ctx,
    secp256k1_pedersen_commitment *commit,
    const unsigned char *blind,
    uint64_t value,
    const secp256k1_generator *value_gen,
    const secp256k1_generator *blind_gen
);

int secp256k1_pedersen_blind_commit(
    const secp256k1_context* ctx,
    secp256k1_pedersen_commitment *commit,
    const unsigned char *blind,
    const unsigned char *value,
    const secp256k1_generator *value_gen,
    const secp256k1_generator *blind_gen
);

int secp256k1_pedersen_blind_sum(
    const secp256k1_context* ctx,
    unsigned char *blind_out,
    const unsigned char * const *blinds,
    size_t n,
    size_t npositive
);

int secp256k1_pedersen_commit_sum(
    const secp256k1_context* ctx,
    secp256k1_pedersen_commitment *commit_out,
    const secp256k1_pedersen_commitment * const* commits,
    size_t pcnt,
    const secp256k1_pedersen_commitment * const* ncommits,
    size_t ncnt
);

int secp256k1_pedersen_verify_tally(
    const secp256k1_context* ctx,
    const secp256k1_pedersen_commitment * const* pos,
    size_t n_pos,
    const secp256k1_pedersen_commitment * const* neg,
    size_t n_neg
);

int secp256k1_pedersen_blind_generator_blind_sum(
    const secp256k1_context* ctx,
    const uint64_t *value,
    const unsigned char* const* generator_blind,
    unsigned char* const* blinding_factor,
    size_t n_total,
    size_t n_inputs
);

int secp256k1_blind_switch(
    const secp256k1_context* ctx,
    unsigned char* blind_switch,
    const unsigned char* blind,
    uint64_t value,
    const secp256k1_generator* value_gen,
    const secp256k1_generator* blind_gen,
    const secp256k1_pubkey* switch_pubkey
);

int secp256k1_pedersen_commitment_to_pubkey(
    const secp256k1_context* ctx,
    secp256k1_pubkey* pubkey,
    const secp256k1_pedersen_commitment* commit
);

int secp256k1_pubkey_to_pedersen_commitment(
    const secp256k1_context* ctx,
    secp256k1_pedersen_commitment* commit,
    const secp256k1_pubkey* pubkey
);

typedef struct {
    unsigned char data[64];
} secp256k1_schnorrsig;

int secp256k1_schnorrsig_serialize(
    const secp256k1_context* ctx,
    unsigned char* out64,
    const secp256k1_schnorrsig* sig
);

int secp256k1_schnorrsig_parse(
    const secp256k1_context* ctx,
    secp256k1_schnorrsig* sig,
    const unsigned char* in64
);

int secp256k1_schnorrsig_sign(
    const secp256k1_context* ctx,
    secp256k1_schnorrsig* sig,
    int* nonce_is_negated,
    const unsigned char* msg32,
    const unsigned char* seckey,
    secp256k1_nonce_function noncefp,
    void* ndata
);

int secp256k1_schnorrsig_verify(
    const secp256k1_context* ctx,
    const secp256k1_schnorrsig* sig,
    const unsigned char* msg32,
    const secp256k1_pubkey* pubkey
);

int secp256k1_schnorrsig_verify_batch(
    const secp256k1_context* ctx,
    secp256k1_scratch_space* scratch,
    const secp256k1_schnorrsig* const* sig,
    const unsigned char* const* msg32,
    const secp256k1_pubkey* const* pk,
    size_t n_sigs
);

secp256k1_scratch_space* secp256k1_scratch_space_create(
    const secp256k1_context* ctx,
    size_t max_size
);

void secp256k1_scratch_space_destroy(
    secp256k1_scratch_space* scratch
);

typedef struct secp256k1_bulletproof_generators secp256k1_bulletproof_generators;

#define SECP256K1_BULLETPROOF_MAX_DEPTH ...
#define SECP256K1_BULLETPROOF_MAX_PROOF ...

secp256k1_bulletproof_generators *secp256k1_bulletproof_generators_create(
    const secp256k1_context* ctx,
    const secp256k1_generator *blinding_gen,
    size_t n
);

void secp256k1_bulletproof_generators_destroy(
    const secp256k1_context* ctx,
    secp256k1_bulletproof_generators *gen
);

int secp256k1_bulletproof_rangeproof_verify(
    const secp256k1_context* ctx,
    secp256k1_scratch_space* scratch,
    const secp256k1_bulletproof_generators *gens,
    const unsigned char* proof,
    size_t plen,
    const uint64_t* min_value,
    const secp256k1_pedersen_commitment* commit,
    size_t n_commits,
    size_t nbits,
    const secp256k1_generator* value_gen,
    const unsigned char* extra_commit,
    size_t extra_commit_len
);

int secp256k1_bulletproof_rangeproof_verify_multi(
    const secp256k1_context* ctx,
    secp256k1_scratch_space* scratch,
    const secp256k1_bulletproof_generators *gens,
    const unsigned char* const* proof,
    size_t n_proofs,
    size_t plen,
    const uint64_t* const* min_value,
    const secp256k1_pedersen_commitment* const* commit,
    size_t n_commits,
    size_t nbits,
    const secp256k1_generator* value_gen,
    const unsigned char* const* extra_commit,
    size_t *extra_commit_len
);

int secp256k1_bulletproof_rangeproof_rewind(
    const secp256k1_context* ctx,
    uint64_t* value,
    unsigned char* blind,
    const unsigned char* proof,
    size_t plen,
    uint64_t min_value,
    const secp256k1_pedersen_commitment* commit,
    const secp256k1_generator* value_gen,
    const unsigned char* nonce,
    const unsigned char* extra_commit,
    size_t extra_commit_len,
    unsigned char* message
);

int secp256k1_bulletproof_rangeproof_prove(
    const secp256k1_context* ctx,
    secp256k1_scratch_space* scratch,
    const secp256k1_bulletproof_generators* gens,
    unsigned char* proof,
    size_t* plen,
    unsigned char* tau_x,
    secp256k1_pubkey* t_one,
    secp256k1_pubkey* t_two,
    const uint64_t* value,
    const uint64_t* min_value,
    const unsigned char* const* blind,
    const secp256k1_pedersen_commitment* const* commits,
    size_t n_commits,
    const secp256k1_generator* value_gen,
    size_t nbits,
    const unsigned char* nonce,
    const unsigned char* private_nonce,
    const unsigned char* extra_commit,
    size_t extra_commit_len,
    const unsigned char* message
);
