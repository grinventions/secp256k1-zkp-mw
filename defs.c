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
#define SECP256K1_TAG_PUBKEY_EVEN ...
#define SECP256K1_TAG_PUBKEY_ODD ...
#define SECP256K1_TAG_PUBKEY_UNCOMPRESSED ...
#define SECP256K1_TAG_PUBKEY_HYBRID_EVEN ...
#define SECP256K1_TAG_PUBKEY_HYBRID_ODD ...
#define SECP256K1_BULLETPROOF_MAX_DEPTH ...
#define SECP256K1_BULLETPROOF_MAX_PROOF ...
#define SECP256K1_SURJECTIONPROOF_MAX_N_INPUTS 256
/* CFFI doesn't support preprocessor macros
#define SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES ...*/
#define SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES_MAX ...
#define SECP256K1_WHITELIST_MAX_N_KEYS 256

typedef struct secp256k1_context_struct secp256k1_context;

typedef struct secp256k1_scratch_space_struct secp256k1_scratch_space;

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

typedef struct secp256k1_aggsig_context_struct secp256k1_aggsig_context;

typedef struct {
    unsigned char data[32];
} secp256k1_aggsig_partial_signature;

typedef struct secp256k1_bulletproof_generators secp256k1_bulletproof_generators;

typedef struct {
    unsigned char data[64];
} secp256k1_pedersen_commitment;

typedef struct {
    unsigned char data[64];
} secp256k1_generator;

typedef struct {
    unsigned char data[65];
} secp256k1_ecdsa_recoverable_signature;

typedef struct {
    unsigned char data[64];
} secp256k1_schnorrsig;

typedef struct {
    size_t n_inputs;
    unsigned char used_inputs[SECP256K1_SURJECTIONPROOF_MAX_N_INPUTS / 8];
    unsigned char data[32 * (1 + SECP256K1_SURJECTIONPROOF_MAX_N_INPUTS)];
} secp256k1_surjectionproof;

typedef struct {
    unsigned char data[32];
} secp256k1_fixed_asset_tag;

typedef struct {
    size_t n_keys;
    unsigned char data[32 * (1 + SECP256K1_WHITELIST_MAX_N_KEYS)];
} secp256k1_whitelist_signature;

extern const secp256k1_context *secp256k1_context_no_precomp;
extern const secp256k1_nonce_function secp256k1_nonce_function_rfc6979;
extern const secp256k1_nonce_function secp256k1_nonce_function_default;
extern const secp256k1_generator *secp256k1_generator_h;
extern const secp256k1_generator secp256k1_generator_const_g;
extern const secp256k1_generator secp256k1_generator_const_h;

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

secp256k1_scratch_space* secp256k1_scratch_space_create(
    const secp256k1_context* ctx,
    size_t max_size
);

void secp256k1_scratch_space_destroy(
    secp256k1_scratch_space* scratch
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

/* Libsecp256k1-zkp defines but doesn't implement secp256k1_pedersen_context_initialize
void secp256k1_pedersen_context_initialize(
    secp256k1_context* ctx
);*/

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

int secp256k1_ecdh(
    const secp256k1_context* ctx,
    unsigned char *result,
    const secp256k1_pubkey *pubkey,
    const unsigned char *privkey
);

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

size_t secp256k1_context_preallocated_size(
    unsigned int flags
);

secp256k1_context* secp256k1_context_preallocated_create(
    void* prealloc,
    unsigned int flags
);

size_t secp256k1_context_preallocated_clone_size(
    const secp256k1_context* ctx
);

secp256k1_context* secp256k1_context_preallocated_clone(
    const secp256k1_context* ctx,
    void* prealloc
);

void secp256k1_context_preallocated_destroy(
    secp256k1_context* ctx
);

int secp256k1_rangeproof_verify(
    const secp256k1_context* ctx,
    uint64_t *min_value,
    uint64_t *max_value,
    const secp256k1_pedersen_commitment *commit,
    const unsigned char *proof,
    size_t plen,
    const unsigned char *extra_commit,
    size_t extra_commit_len,
    const secp256k1_generator* gen
);

int secp256k1_rangeproof_rewind(
    const secp256k1_context* ctx,
    unsigned char *blind_out,
    uint64_t *value_out,
    unsigned char *message_out,
    size_t *outlen,
    const unsigned char *nonce,
    uint64_t *min_value,
    uint64_t *max_value,
    const secp256k1_pedersen_commitment *commit,
    const unsigned char *proof,
    size_t plen,
    const unsigned char *extra_commit,
    size_t extra_commit_len,
    const secp256k1_generator *gen
);

int secp256k1_rangeproof_sign(
    const secp256k1_context* ctx,
    unsigned char *proof,
    size_t *plen,
    uint64_t min_value,
    const secp256k1_pedersen_commitment *commit,
    const unsigned char *blind,
    const unsigned char *nonce,
    int exp,
    int min_bits,
    uint64_t value,
    const unsigned char *message,
    size_t msg_len,
    const unsigned char *extra_commit,
    size_t extra_commit_len,
    const secp256k1_generator *gen
);

int secp256k1_rangeproof_info(
    const secp256k1_context* ctx,
    int *exp,
    int *mantissa,
    uint64_t *min_value,
    uint64_t *max_value,
    const unsigned char *proof,
    size_t plen
);

int secp256k1_ecdsa_recoverable_signature_parse_compact(
    const secp256k1_context* ctx,
    secp256k1_ecdsa_recoverable_signature* sig,
    const unsigned char *input64,
    int recid
);

int secp256k1_ecdsa_recoverable_signature_convert(
    const secp256k1_context* ctx,
    secp256k1_ecdsa_signature* sig,
    const secp256k1_ecdsa_recoverable_signature* sigin
);

int secp256k1_ecdsa_recoverable_signature_serialize_compact(
    const secp256k1_context* ctx,
    unsigned char *output64,
    int *recid,
    const secp256k1_ecdsa_recoverable_signature* sig
);

int secp256k1_ecdsa_sign_recoverable(
    const secp256k1_context* ctx,
    secp256k1_ecdsa_recoverable_signature *sig,
    const unsigned char *msg32,
    const unsigned char *seckey,
    secp256k1_nonce_function noncefp,
    const void *ndata
);

int secp256k1_ecdsa_recover(
    const secp256k1_context* ctx,
    secp256k1_pubkey *pubkey,
    const secp256k1_ecdsa_recoverable_signature *sig,
    const unsigned char *msg32
);

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

int secp256k1_surjectionproof_parse(
    const secp256k1_context* ctx,
    secp256k1_surjectionproof *proof,
    const unsigned char *input,
    size_t inputlen
);

int secp256k1_surjectionproof_serialize(
    const secp256k1_context* ctx,
    unsigned char *output,
    size_t *outputlen,
    const secp256k1_surjectionproof *proof
);

size_t secp256k1_surjectionproof_n_total_inputs(
    const secp256k1_context* ctx,
    const secp256k1_surjectionproof* proof
);

size_t secp256k1_surjectionproof_n_used_inputs(
    const secp256k1_context* ctx,
    const secp256k1_surjectionproof* proof
);

size_t secp256k1_surjectionproof_serialized_size(
    const secp256k1_context* ctx,
    const secp256k1_surjectionproof* proof
);

int secp256k1_surjectionproof_initialize(
    const secp256k1_context* ctx,
    secp256k1_surjectionproof* proof,
    size_t *input_index,
    const secp256k1_fixed_asset_tag* fixed_input_tags,
    const size_t n_input_tags,
    const size_t n_input_tags_to_use,
    const secp256k1_fixed_asset_tag* fixed_output_tag,
    const size_t n_max_iterations,
    const unsigned char *random_seed32
);

int secp256k1_surjectionproof_generate(
    const secp256k1_context* ctx,
    secp256k1_surjectionproof* proof,
    const secp256k1_generator* ephemeral_input_tags,
    size_t n_ephemeral_input_tags,
    const secp256k1_generator* ephemeral_output_tag,
    size_t input_index,
    const unsigned char *input_blinding_key,
    const unsigned char *output_blinding_key
);

int secp256k1_surjectionproof_verify(
    const secp256k1_context* ctx,
    const secp256k1_surjectionproof* proof,
    const secp256k1_generator* ephemeral_input_tags,
    size_t n_ephemeral_input_tags,
    const secp256k1_generator* ephemeral_output_tag
);

int secp256k1_whitelist_signature_parse(
    const secp256k1_context* ctx,
    secp256k1_whitelist_signature *sig,
    const unsigned char *input,
    size_t input_len
);

size_t secp256k1_whitelist_signature_n_keys(
    const secp256k1_whitelist_signature *sig
);

int secp256k1_whitelist_signature_serialize(
    const secp256k1_context* ctx,
    unsigned char *output,
    size_t *output_len,
    const secp256k1_whitelist_signature *sig
);

int secp256k1_whitelist_sign(
    const secp256k1_context* ctx,
    secp256k1_whitelist_signature *sig,
    const secp256k1_pubkey *online_pubkeys,
    const secp256k1_pubkey *offline_pubkeys,
    const size_t n_keys,
    const secp256k1_pubkey *sub_pubkey,
    const unsigned char *online_seckey,
    const unsigned char *summed_seckey,
    const size_t index,
    secp256k1_nonce_function noncefp,
    const void *noncedata
);

int secp256k1_whitelist_verify(
    const secp256k1_context* ctx,
    const secp256k1_whitelist_signature *sig,
    const secp256k1_pubkey *online_pubkeys,
    const secp256k1_pubkey *offline_pubkeys,
    const size_t n_keys,
    const secp256k1_pubkey *sub_pubkey
);
