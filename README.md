# secp256k1-zkp-mw

This is an early stage version of Python CFFI wrapper of the [MW fork of secp256k1-zkp](https://github.com/mimblewimble/secp256k1-zkp). It is very much needed to develop the [mimblewimble-py](https://github.com/grinventions/mimblewimble-py). Similar way as it was done with [rust-secp256k1-zkp](https://github.com/mimblewimble/rust-secp256k1-zkp). It is also inspired and partially based on [secp256k1-py](https://github.com/rustyrussell/secp256k1-py). All of the code used here is under the MIT license and there is no license conflict.

For now only few methods are correctly wrapped. My attempts of wrapping more of them results with plenty of C compile errors which I don't always understand so any help is appreciated. Feel free to fork and PR or send me messages with some advices!

## Development setup

First clone this repo and change to its directory, then download the submodule [MW fork of secp256k1-zkp](https://github.com/mimblewimble/secp256k1-zkp) by running

```sh
git submodule init
git submodule update
```

It should create the `secp256k1-zkp` directory. It should be gitignored so you don't need to worry about accidentally committing it to this repo.

## Try it!

### Build

Run the build script to generate Python functions and definitions from C

```sh
python build.py
```

### Try

You may list the definition and run context creating method with

```sh
python run.py
```

and you will get

```
Generated definitions from C

SECP256K1_BULLETPROOF_MAX_DEPTH
SECP256K1_BULLETPROOF_MAX_PROOF
SECP256K1_CONTEXT_NONE
SECP256K1_CONTEXT_SIGN
SECP256K1_CONTEXT_VERIFY
SECP256K1_EC_COMPRESSED
SECP256K1_EC_UNCOMPRESSED
SECP256K1_FLAGS_BIT_COMPRESSION
SECP256K1_FLAGS_BIT_CONTEXT_SIGN
SECP256K1_FLAGS_BIT_CONTEXT_VERIFY
SECP256K1_FLAGS_TYPE_COMPRESSION
SECP256K1_FLAGS_TYPE_CONTEXT
SECP256K1_FLAGS_TYPE_MASK
secp256k1_aggsig_add_signatures_single
secp256k1_aggsig_build_scratch_and_verify
secp256k1_aggsig_combine_signatures
secp256k1_aggsig_context_create
secp256k1_aggsig_context_destroy
secp256k1_aggsig_export_secnonce_single
secp256k1_aggsig_generate_nonce
secp256k1_aggsig_partial_sign
secp256k1_aggsig_sign_single
secp256k1_aggsig_verify
secp256k1_aggsig_verify_single
secp256k1_blind_switch
secp256k1_bulletproof_generators_create
secp256k1_bulletproof_generators_destroy
secp256k1_bulletproof_rangeproof_prove
secp256k1_bulletproof_rangeproof_rewind
secp256k1_bulletproof_rangeproof_verify
secp256k1_bulletproof_rangeproof_verify_multi
secp256k1_context_clone
secp256k1_context_create
secp256k1_context_destroy
secp256k1_context_randomize
secp256k1_context_set_error_callback
secp256k1_context_set_illegal_callback
secp256k1_ec_privkey_negate
secp256k1_ec_privkey_tweak_add
secp256k1_ec_privkey_tweak_inv
secp256k1_ec_privkey_tweak_mul
secp256k1_ec_privkey_tweak_neg
secp256k1_ec_pubkey_combine
secp256k1_ec_pubkey_create
secp256k1_ec_pubkey_negate
secp256k1_ec_pubkey_parse
secp256k1_ec_pubkey_serialize
secp256k1_ec_pubkey_tweak_add
secp256k1_ec_pubkey_tweak_mul
secp256k1_ec_seckey_verify
secp256k1_ecdsa_sign
secp256k1_ecdsa_signature_normalize
secp256k1_ecdsa_signature_parse_compact
secp256k1_ecdsa_signature_parse_der
secp256k1_ecdsa_signature_serialize_compact
secp256k1_ecdsa_signature_serialize_der
secp256k1_ecdsa_verify
secp256k1_generator_generate
secp256k1_generator_generate_blinded
secp256k1_generator_parse
secp256k1_generator_serialize
secp256k1_pedersen_blind_commit
secp256k1_pedersen_blind_generator_blind_sum
secp256k1_pedersen_blind_sum
secp256k1_pedersen_commit
secp256k1_pedersen_commit_sum
secp256k1_pedersen_commitment_parse
secp256k1_pedersen_commitment_serialize
secp256k1_pedersen_commitment_to_pubkey
secp256k1_pedersen_verify_tally
secp256k1_pubkey_to_pedersen_commitment
secp256k1_schnorrsig_parse
secp256k1_schnorrsig_serialize
secp256k1_schnorrsig_sign
secp256k1_schnorrsig_verify
secp256k1_schnorrsig_verify_batch
secp256k1_scratch_space_create
secp256k1_scratch_space_destroy

Running lib.secp256k1_context_create(lib.SECP256K1_CONTEXT_NONE)
...and it returned
<cdata 'struct secp256k1_context_struct *' 0x7fab8b4541a0>
```
