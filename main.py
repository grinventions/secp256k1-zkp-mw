from secp256k1_mw import ffi, lib

SECP256K1_FLAGS_TYPE_MASK = lib.SECP256K1_FLAGS_TYPE_MASK
SECP256K1_FLAGS_TYPE_CONTEXT = lib.SECP256K1_FLAGS_TYPE_CONTEXT
SECP256K1_FLAGS_TYPE_COMPRESSION = lib.SECP256K1_FLAGS_TYPE_COMPRESSION
SECP256K1_FLAGS_BIT_CONTEXT_VERIFY = lib.SECP256K1_FLAGS_BIT_CONTEXT_VERIFY
SECP256K1_FLAGS_BIT_CONTEXT_SIGN = lib.SECP256K1_FLAGS_BIT_CONTEXT_SIGN
SECP256K1_FLAGS_BIT_COMPRESSION = lib.SECP256K1_FLAGS_BIT_COMPRESSION
SECP256K1_CONTEXT_VERIFY = lib.SECP256K1_CONTEXT_VERIFY
SECP256K1_CONTEXT_SIGN = lib.SECP256K1_CONTEXT_SIGN
SECP256K1_CONTEXT_NONE = lib.SECP256K1_CONTEXT_NONE
SECP256K1_EC_COMPRESSED = lib.SECP256K1_EC_COMPRESSED
SECP256K1_EC_UNCOMPRESSED = lib.SECP256K1_EC_UNCOMPRESSED
SECP256K1_TAG_PUBKEY_EVEN = lib.SECP256K1_TAG_PUBKEY_EVEN
SECP256K1_TAG_PUBKEY_ODD = lib.SECP256K1_TAG_PUBKEY_ODD
SECP256K1_TAG_PUBKEY_UNCOMPRESSED = lib.SECP256K1_TAG_PUBKEY_UNCOMPRESSED
SECP256K1_TAG_PUBKEY_HYBRID_EVEN = lib.SECP256K1_TAG_PUBKEY_HYBRID_EVEN
SECP256K1_TAG_PUBKEY_HYBRID_ODD = lib.SECP256K1_TAG_PUBKEY_HYBRID_ODD
SECP256K1_BULLETPROOF_MAX_DEPTH = lib.SECP256K1_BULLETPROOF_MAX_DEPTH
SECP256K1_BULLETPROOF_MAX_PROOF = lib.SECP256K1_BULLETPROOF_MAX_PROOF
SECP256K1_SURJECTIONPROOF_MAX_N_INPUTS = lib.SECP256K1_SURJECTIONPROOF_MAX_N_INPUTS
SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES_MAX = lib.SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES_MAX
SECP256K1_WHITELIST_MAX_N_KEYS = lib.SECP256K1_WHITELIST_MAX_N_KEYS

secp256k1_context_no_precomp = lib.secp256k1_context_no_precomp
secp256k1_nonce_function_rfc6979 = lib.secp256k1_nonce_function_rfc6979
secp256k1_nonce_function_default = lib.secp256k1_nonce_function_default
secp256k1_generator_h = lib.secp256k1_generator_h
secp256k1_generator_const_g = ffi.addressof(lib.secp256k1_generator_const_g)
secp256k1_generator_const_h = ffi.addressof(lib.secp256k1_generator_const_h)

def SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES(n_inputs, n_used_inputs):
    return 2 + (n_inputs + 7) // 8 + 32 * (1 + n_used_inputs)

def secp256k1_context_create(flags):
    ctx = lib.secp256k1_context_create(flags)
    return ctx if ctx != ffi.NULL else None

def secp256k1_context_clone(ctx):
    clone = lib.secp256k1_context_clone(ctx)
    return clone if clone != ffi.NULL else None

def secp256k1_context_destroy(ctx):
    lib.secp256k1_context_destroy(ctx if ctx is not None else ffi.NULL)

def secp256k1_context_set_illegal_callback(ctx, fun, data):
    if not isinstance(data, ffi.CData) and data is not None:
        raise TypeError('CData or None is required')
    lib.secp256k1_context_set_illegal_callback(ctx, fun if fun is not None else ffi.NULL, data if data is not None else ffi.NULL)

def secp256k1_context_set_error_callback(ctx, fun, data):
    if not isinstance(data, ffi.CData) and data is not None:
        raise TypeError('CData or None is required')
    lib.secp256k1_context_set_error_callback(ctx, fun if fun is not None else ffi.NULL, data if data is not None else ffi.NULL)

def secp256k1_scratch_space_create(ctx, max_size):
    scratch = lib.secp256k1_scratch_space_create(ctx, max_size)
    return scratch if scratch != ffi.NULL else None

def secp256k1_scratch_space_destroy(scratch):
    lib.secp256k1_scratch_space_destroy(scratch if scratch is not None else ffi.NULL)

def secp256k1_ec_pubkey_parse(ctx, input):
    if type(input) is not bytes:
        raise TypeError('bytes is required')
    pubkey = ffi.new('secp256k1_pubkey *')
    result = lib.secp256k1_ec_pubkey_parse(ctx, pubkey, input, len(input))
    return pubkey if result == 1 else None

def secp256k1_ec_pubkey_serialize(ctx, pubkey, flags):
    uncompressed_public_key_length = 65
    output = ffi.new('unsigned char []', uncompressed_public_key_length)
    outputlen = ffi.new('size_t *', uncompressed_public_key_length)
    result = lib.secp256k1_ec_pubkey_serialize(ctx, output, outputlen, pubkey, flags)
    return bytes(ffi.buffer(output, outputlen[0])) if result == 1 else None

def secp256k1_ecdsa_signature_parse_compact(ctx, input64):
    if type(input64) is not bytes:
        raise TypeError('bytes is required')
    sig = ffi.new('secp256k1_ecdsa_signature *')
    result = lib.secp256k1_ecdsa_signature_parse_compact(ctx, sig, input64)
    return sig if result == 1 else None

def secp256k1_ecdsa_signature_parse_der(ctx, input):
    if type(input) is not bytes:
        raise TypeError('bytes is required')
    sig = ffi.new('secp256k1_ecdsa_signature *')
    result = lib.secp256k1_ecdsa_signature_parse_der(ctx, sig, input, len(input))
    return sig if result == 1 else None

def secp256k1_ecdsa_signature_serialize_der(ctx, sig):
    der_signature_max_length = 72
    output = ffi.new('unsigned char []', der_signature_max_length)
    outputlen = ffi.new('size_t *', der_signature_max_length)
    result = lib.secp256k1_ecdsa_signature_serialize_der(ctx, output, outputlen, sig)
    return bytes(ffi.buffer(output, outputlen[0])) if result == 1 else None

def secp256k1_ecdsa_signature_serialize_compact(ctx, sig):
    output64 = ffi.new('unsigned char []', 64)
    result = lib.secp256k1_ecdsa_signature_serialize_compact(ctx, output64, sig)
    return bytes(output64) if result == 1 else None

def secp256k1_ecdsa_verify(ctx, sig, msg32, pubkey):
    if type(msg32) is not bytes:
        raise TypeError('bytes is required')
    result = lib.secp256k1_ecdsa_verify(ctx, sig, msg32, pubkey)
    return result == 1

def secp256k1_ecdsa_signature_normalize(ctx, sigin):
    sigout = ffi.new('secp256k1_ecdsa_signature *')
    result = lib.secp256k1_ecdsa_signature_normalize(ctx, sigout, sigin)
    return sigout

def secp256k1_ecdsa_sign(ctx, msg32, seckey, noncefp, ndata):
    if type(msg32) is not bytes:
        raise TypeError('bytes is required')
    if type(seckey) is not bytes:
        raise TypeError('bytes is required')
    if type(ndata) is not bytes and ndata is not None:
        raise TypeError('bytes or None is required')
    sig = ffi.new('secp256k1_ecdsa_signature *')
    result = lib.secp256k1_ecdsa_sign(ctx, sig, msg32, seckey, noncefp if noncefp is not None else ffi.NULL, ndata if ndata is not None else ffi.NULL)
    return sig if result == 1 else None

def secp256k1_ec_seckey_verify(ctx, seckey):
    if type(seckey) is not bytes:
        raise TypeError('bytes is required')
    result = lib.secp256k1_ec_seckey_verify(ctx, seckey)
    return result == 1

def secp256k1_ec_pubkey_create(ctx, seckey):
    if type(seckey) is not bytes:
        raise TypeError('bytes is required')
    pubkey = ffi.new('secp256k1_pubkey *')
    result = lib.secp256k1_ec_pubkey_create(ctx, pubkey, seckey)
    return pubkey if result == 1 else None

def secp256k1_ec_privkey_negate(ctx, seckey):
    if type(seckey) is not bytes:
        raise TypeError('bytes is required')
    new_secret_key = ffi.new('unsigned char [%d]' % len(seckey), seckey)
    result = lib.secp256k1_ec_privkey_negate(ctx, new_secret_key)
    return bytes(new_secret_key) if result == 1 else None

def secp256k1_ec_pubkey_negate(ctx, pubkey):
    if not isinstance(pubkey, ffi.CData) or not ffi.typeof(pubkey) is ffi.typeof('secp256k1_pubkey *'):
        raise TypeError('secp256k1_pubkey * is required')
    new_public_key = ffi.new('secp256k1_pubkey *')
    ffi.memmove(new_public_key, pubkey, ffi.sizeof('secp256k1_pubkey'))
    result = lib.secp256k1_ec_pubkey_negate(ctx, new_public_key)
    return new_public_key if result == 1 else None

def secp256k1_ec_privkey_tweak_add(ctx, seckey, tweak):
    if type(seckey) is not bytes:
        raise TypeError('bytes is required')
    if type(tweak) is not bytes:
        raise TypeError('bytes is required')
    new_secret_key = ffi.new('unsigned char [%d]' % len(seckey), seckey)
    result = lib.secp256k1_ec_privkey_tweak_add(ctx, new_secret_key, tweak)
    return bytes(new_secret_key) if result == 1 else None

def secp256k1_ec_pubkey_tweak_add(ctx, pubkey, tweak):
    if not isinstance(pubkey, ffi.CData) or not ffi.typeof(pubkey) is ffi.typeof('secp256k1_pubkey *'):
        raise TypeError('secp256k1_pubkey * is required')
    if type(tweak) is not bytes:
        raise TypeError('bytes is required')
    new_public_key = ffi.new('secp256k1_pubkey *')
    ffi.memmove(new_public_key, pubkey, ffi.sizeof('secp256k1_pubkey'))
    result = lib.secp256k1_ec_pubkey_tweak_add(ctx, new_public_key, tweak)
    return new_public_key if result == 1 else None

def secp256k1_ec_privkey_tweak_mul(ctx, seckey, tweak):
    if type(seckey) is not bytes:
        raise TypeError('bytes is required')
    if type(tweak) is not bytes:
        raise TypeError('bytes is required')
    new_secret_key = ffi.new('unsigned char [%d]' % len(seckey), seckey)
    result = lib.secp256k1_ec_privkey_tweak_mul(ctx, new_secret_key, tweak)
    return bytes(new_secret_key) if result == 1 else None

def secp256k1_ec_pubkey_tweak_mul(ctx, pubkey, tweak):
    if not isinstance(pubkey, ffi.CData) or not ffi.typeof(pubkey) is ffi.typeof('secp256k1_pubkey *'):
        raise TypeError('secp256k1_pubkey * is required')
    if type(tweak) is not bytes:
        raise TypeError('bytes is required')
    new_public_key = ffi.new('secp256k1_pubkey *')
    ffi.memmove(new_public_key, pubkey, ffi.sizeof('secp256k1_pubkey'))
    result = lib.secp256k1_ec_pubkey_tweak_mul(ctx, new_public_key, tweak)
    return new_public_key if result == 1 else None

def secp256k1_context_randomize(ctx, seed32):
    if type(seed32) is not bytes and seed32 is not None:
        raise TypeError('bytes or None is required')
    new_context = lib.secp256k1_context_clone(ctx)
    assert new_context != ffi.NULL
    result = lib.secp256k1_context_randomize(new_context, seed32 if seed32 is not None else ffi.NULL)
    return new_context if result == 1 else None

def secp256k1_ec_pubkey_combine(ctx, ins):
    if type(ins) is not list:
        raise TypeError('list<secp256k1_pubkey *> is required')
    out = ffi.new('secp256k1_pubkey *')
    result = lib.secp256k1_ec_pubkey_combine(ctx, out, ins, len(ins))
    return out if result == 1 else None

def secp256k1_ec_privkey_tweak_inv(ctx, seckey):
    if type(seckey) is not bytes:
        raise TypeError('bytes is required')
    new_secret_key = ffi.new('unsigned char [%d]' % len(seckey), seckey)
    result = lib.secp256k1_ec_privkey_tweak_inv(ctx, new_secret_key)
    return bytes(new_secret_key) if result == 1 else None

def secp256k1_ec_privkey_tweak_neg(ctx, seckey):
    if type(seckey) is not bytes:
        raise TypeError('bytes is required')
    new_secret_key = ffi.new('unsigned char [%d]' % len(seckey), seckey)
    result = lib.secp256k1_ec_privkey_tweak_neg(ctx, new_secret_key)
    return bytes(new_secret_key) if result == 1 else None

def secp256k1_aggsig_context_create(ctx, pubkeys, seed):
    if type(pubkeys) is not list:
        raise TypeError('list<secp256k1_pubkey *> is required')
    if not all(isinstance(pubkey, ffi.CData) and ffi.typeof(pubkey) is ffi.typeof('secp256k1_pubkey *') for pubkey in pubkeys):
        raise TypeError('list<secp256k1_pubkey *> is required')
    if type(seed) is not bytes:
        raise TypeError('bytes is required')
    public_keys = ffi.new('secp256k1_pubkey []', len(pubkeys))
    for index, pubkey in enumerate(pubkeys):
        ffi.memmove(ffi.addressof(public_keys, index), pubkey, ffi.sizeof('secp256k1_pubkey'))
    result = lib.secp256k1_aggsig_context_create(ctx, public_keys, len(pubkeys), seed)
    return result if result != ffi.NULL else None

def secp256k1_aggsig_context_destroy(aggctx):
    lib.secp256k1_aggsig_context_destroy(aggctx if aggctx is not None else ffi.NULL)

def secp256k1_aggsig_generate_nonce(ctx, aggctx, index):
    result = lib.secp256k1_aggsig_generate_nonce(ctx, aggctx, index)
    return result == 1

def secp256k1_aggsig_export_secnonce_single(ctx, seed):
    if type(seed) is not bytes:
        raise TypeError('bytes is required')
    secnonce32 = ffi.new('unsigned char []', 32)
    result = lib.secp256k1_aggsig_export_secnonce_single(ctx, secnonce32, seed)
    return bytes(secnonce32) if result == 1 else None

def secp256k1_aggsig_sign_single(ctx, msg32, seckey32, secnonce32, extra32, pubnonce_for_e, pubnonce_total, pubkey_for_e, seed):
    if type(msg32) is not bytes:
        raise TypeError('bytes is required')
    if type(seckey32) is not bytes:
        raise TypeError('bytes is required')
    if type(secnonce32) is not bytes and secnonce32 is not None:
        raise TypeError('bytes or None is required')
    if type(extra32) is not bytes and extra32 is not None:
        raise TypeError('bytes or None is required')
    if type(seed) is not bytes:
        raise TypeError('bytes is required')
    sig64 = ffi.new('secp256k1_ecdsa_signature *')
    result = lib.secp256k1_aggsig_sign_single(ctx, ffi.cast('unsigned char *', sig64), msg32, seckey32, secnonce32 if secnonce32 is not None else ffi.NULL, extra32 if extra32 is not None else ffi.NULL, pubnonce_for_e if pubnonce_for_e is not None else ffi.NULL, pubnonce_total if pubnonce_total is not None else ffi.NULL, pubkey_for_e if pubkey_for_e is not None else ffi.NULL, seed)
    return sig64 if result == 1 else None

def secp256k1_aggsig_partial_sign(ctx, aggctx, msg32, seckey32, index):
    if type(msg32) is not bytes:
        raise TypeError('bytes is required')
    if type(seckey32) is not bytes:
        raise TypeError('bytes is required')
    partial = ffi.new('secp256k1_aggsig_partial_signature *')
    result = lib.secp256k1_aggsig_partial_sign(ctx, aggctx, partial, msg32, seckey32, index)
    return partial if result == 1 else None

def secp256k1_aggsig_combine_signatures(ctx, aggctx, partial):
    if type(partial) is not list:
        raise TypeError('list<secp256k1_aggsig_partial_signature *> is required')
    if not all(isinstance(sig, ffi.CData) and ffi.typeof(sig) is ffi.typeof('secp256k1_aggsig_partial_signature *') for sig in partial):
        raise TypeError('list<secp256k1_aggsig_partial_signature *> is required')
    partial_signatures = ffi.new('secp256k1_aggsig_partial_signature []', len(partial))
    for index, sig in enumerate(partial):
        ffi.memmove(ffi.addressof(partial_signatures, index), sig, ffi.sizeof('secp256k1_aggsig_partial_signature'))
    sig64 = ffi.new('secp256k1_ecdsa_signature *')
    result = lib.secp256k1_aggsig_combine_signatures(ctx, aggctx, ffi.cast('unsigned char *', sig64), partial_signatures, len(partial))
    return sig64 if result == 1 else None

def secp256k1_aggsig_add_signatures_single(ctx, sigs, pubnonce_total):
    if type(sigs) is not list:
        raise TypeError('list<secp256k1_ecdsa_signature *> is required')
    if not all(isinstance(sig, ffi.CData) and ffi.typeof(sig) is ffi.typeof('secp256k1_ecdsa_signature *') for sig in sigs):
        raise TypeError('list<secp256k1_ecdsa_signature *> is required')
    sig64 = ffi.new('secp256k1_ecdsa_signature *')
    result = lib.secp256k1_aggsig_add_signatures_single(ctx, ffi.cast('unsigned char *', sig64), list(map(lambda sig : ffi.cast('unsigned char *', sig), sigs)), len(sigs), pubnonce_total)
    return sig64 if result == 1 else None

def secp256k1_aggsig_verify_single(ctx, sig64, msg32, pubnonce, pubkey, pubkey_total, extra_pubkey, is_partial):
    if not isinstance(sig64, ffi.CData) or not ffi.typeof(sig64) is ffi.typeof('secp256k1_ecdsa_signature *'):
        raise TypeError('secp256k1_ecdsa_signature * is required')
    if type(msg32) is not bytes:
        raise TypeError('bytes is required')
    if type(is_partial) is not bool:
        raise TypeError('bool is required')
    result = lib.secp256k1_aggsig_verify_single(ctx, ffi.cast('unsigned char *', sig64), msg32, pubnonce if pubnonce is not None else ffi.NULL, pubkey, pubkey_total if pubkey_total is not None else ffi.NULL, extra_pubkey if extra_pubkey is not None else ffi.NULL, 1 if is_partial else 0)
    return result == 1

def secp256k1_aggsig_verify(ctx, scratch, sig64, msg32, pubkeys):
    if not isinstance(sig64, ffi.CData) or not ffi.typeof(sig64) is ffi.typeof('secp256k1_ecdsa_signature *'):
        raise TypeError('secp256k1_ecdsa_signature * is required')
    if type(msg32) is not bytes:
        raise TypeError('bytes is required')
    if type(pubkeys) is not list:
        raise TypeError('list<secp256k1_pubkey *> is required')
    if not all(isinstance(pubkey, ffi.CData) and ffi.typeof(pubkey) is ffi.typeof('secp256k1_pubkey *') for pubkey in pubkeys):
        raise TypeError('list<secp256k1_pubkey *> is required')
    public_keys = ffi.new('secp256k1_pubkey []', len(pubkeys))
    for index, pubkey in enumerate(pubkeys):
        ffi.memmove(ffi.addressof(public_keys, index), pubkey, ffi.sizeof('secp256k1_pubkey'))
    result = lib.secp256k1_aggsig_verify(ctx, scratch, ffi.cast('unsigned char *', sig64), msg32, public_keys, len(pubkeys))
    return result == 1

def secp256k1_aggsig_build_scratch_and_verify(ctx, sig64, msg32, pubkeys):
    if not isinstance(sig64, ffi.CData) or not ffi.typeof(sig64) is ffi.typeof('secp256k1_ecdsa_signature *'):
        raise TypeError('secp256k1_ecdsa_signature * is required')
    if type(msg32) is not bytes:
        raise TypeError('bytes is required')
    if type(pubkeys) is not list:
        raise TypeError('list<secp256k1_pubkey *> is required')
    if not all(isinstance(pubkey, ffi.CData) and ffi.typeof(pubkey) is ffi.typeof('secp256k1_pubkey *') for pubkey in pubkeys):
        raise TypeError('list<secp256k1_pubkey *> is required')
    public_keys = ffi.new('secp256k1_pubkey []', len(pubkeys))
    for index, pubkey in enumerate(pubkeys):
        ffi.memmove(ffi.addressof(public_keys, index), pubkey, ffi.sizeof('secp256k1_pubkey'))
    result = lib.secp256k1_aggsig_build_scratch_and_verify(ctx, ffi.cast('unsigned char *', sig64), msg32, public_keys, len(pubkeys))
    return result == 1

def secp256k1_bulletproof_generators_create(ctx, blinding_gen, n):
    result = lib.secp256k1_bulletproof_generators_create(ctx, blinding_gen, n)
    return result if result != ffi.NULL else None

def secp256k1_bulletproof_generators_destroy(ctx, gen):
    lib.secp256k1_bulletproof_generators_destroy(ctx, gen if gen is not None else ffi.NULL)

def secp256k1_bulletproof_rangeproof_verify(ctx, scratch, gens, proof, min_value, commit, nbits, value_gen, extra_commit):
    if type(proof) is not bytes:
        raise TypeError('bytes is required')
    if type(min_value) is not list and min_value is not None:
        raise TypeError('list<int> or None is required')
    if type(commit) is not list:
        raise TypeError('list<secp256k1_pedersen_commitment *> is required')
    if not all(isinstance(commitment, ffi.CData) and ffi.typeof(commitment) is ffi.typeof('secp256k1_pedersen_commitment *') for commitment in commit):
        raise TypeError('list<secp256k1_pedersen_commitment *> is required')
    if type(extra_commit) is not bytes and extra_commit is not None:
        raise TypeError('bytes or None is required')
    commits = ffi.new('secp256k1_pedersen_commitment []', len(commit))
    for index, commitment in enumerate(commit):
        ffi.memmove(ffi.addressof(commits, index), commitment, ffi.sizeof('secp256k1_pedersen_commitment'))
    result = lib.secp256k1_bulletproof_rangeproof_verify(ctx, scratch, gens, proof, len(proof), min_value if min_value is not None else ffi.NULL, commits, len(commit), nbits, value_gen, extra_commit if extra_commit is not None else ffi.NULL, len(extra_commit) if extra_commit is not None else 0)
    return result == 1

def secp256k1_bulletproof_rangeproof_verify_multi(ctx, scratch, gens, proof, min_value, commit, nbits, value_gen, extra_commit):
    if type(proof) is not list:
        raise TypeError('list<bytes> is required')
    if not all(type(bulletproof) is bytes for bulletproof in proof):
        raise TypeError('list<bytes> is required')
    if type(min_value) is not list and min_value is not None:
        raise TypeError('list<list<int>> or None is required')
    if type(min_value) is list:
        if not all(type(minimum_value) is list for minimum_value in min_value):
            raise TypeError('list<list<int>> or None is required')
    if type(commit) is not list:
        raise TypeError('list<list<secp256k1_pedersen_commitment *>> is required')
    if not all(type(commitments) is list for commitments in commit):
        raise TypeError('list<list<secp256k1_pedersen_commitment *>> is required')
    if not all(all(isinstance(commitment, ffi.CData) and ffi.typeof(commitment) is ffi.typeof('secp256k1_pedersen_commitment *') for commitment in commits) for commits in commit):
        raise TypeError('list<list<secp256k1_pedersen_commitment *>> is required')
    if type(value_gen) is not list:
        raise TypeError('list<secp256k1_generator *> is required')
    if not all(isinstance(value_generator, ffi.CData) and ffi.typeof(value_generator) is ffi.typeof('secp256k1_generator *') for value_generator in value_gen):
        raise TypeError('list<secp256k1_generator *> is required')
    if type(extra_commit) is not list and extra_commit is not None:
        raise TypeError('list<bytes> or None is required')
    if type(extra_commit) is list:
        if not all(type(extra_commitment) is bytes for extra_commitment in extra_commit):
            raise TypeError('list<bytes> or None is required')
    min_values = list(map(lambda mininum_values : ffi.new('uint64_t []', len(mininum_values)), min_value)) if type(min_value) is list else None
    if type(min_value) is list:
        for group_index, minimum_values in enumerate(min_value):
            for minimum_value_index, minimum_value in enumerate(minimum_values):
                min_values[group_index][minimum_value_index] = minimum_value
    commits = list(map(lambda commitments : ffi.new('secp256k1_pedersen_commitment []', len(commitments)), commit))
    for group_index, commitments in enumerate(commit):
        for commit_index, commitment in enumerate(commitments):
            ffi.memmove(ffi.addressof(commits[group_index], commit_index), commitment, ffi.sizeof('secp256k1_pedersen_commitment'))
    value_gens = ffi.new('secp256k1_generator []', len(value_gen))
    for index, value_generator in enumerate(value_gen):
        ffi.memmove(ffi.addressof(value_gens, index), value_generator, ffi.sizeof('secp256k1_generator'))
    assert len(proof) >= 1
    assert len(commit) >= 1
    result = lib.secp256k1_bulletproof_rangeproof_verify_multi(ctx, scratch, gens, list(map(lambda bulletproof : ffi.from_buffer(bulletproof), proof)), len(proof), len(proof[0]), min_values if min_value is not None else ffi.NULL, commits, len(commit[0]), nbits, value_gens, list(map(lambda extra_commitment : ffi.from_buffer(extra_commitment), extra_commit)) if extra_commit is not None else ffi.NULL, list(map(lambda extra_commitment : len(extra_commitment), extra_commit)) if extra_commit is not None else ffi.NULL)
    return result == 1

def secp256k1_bulletproof_rangeproof_rewind(ctx, proof, min_value, commit, value_gen, nonce, extra_commit):
    if type(proof) is not bytes:
        raise TypeError('bytes is required')
    if type(nonce) is not bytes:
        raise TypeError('bytes is required')
    if type(extra_commit) is not bytes and extra_commit is not None:
        raise TypeError('bytes or None is required')
    value = ffi.new('uint64_t *')
    blind = ffi.new('unsigned char []', 32)
    message = ffi.new('unsigned char []', 20)
    result = lib.secp256k1_bulletproof_rangeproof_rewind(ctx, value, blind, proof, len(proof), min_value, commit, value_gen, nonce, extra_commit if extra_commit is not None else ffi.NULL, len(extra_commit) if extra_commit is not None else 0, message)
    return (value[0], bytes(blind), bytes(message)) if result == 1 else None

def secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, tau_x, t_one, t_two, value, min_value, blind, commits, value_gen, nbits, nonce, private_nonce, extra_commit, message):
    if type(tau_x) is not bytes and tau_x is not None:
        raise TypeError('bytes or None is required')
    if type(value) is not list:
        raise TypeError('list<int> is required')
    if type(min_value) is not list and min_value is not None:
        raise TypeError('list<int> or None is required')
    if type(blind) is not list:
        raise TypeError('list<bytes> is required')
    if not all(type(blinding_factor) is bytes for blinding_factor in blind):
        raise TypeError('list<bytes> is required')
    if type(commits) is not list and commits is not None:
        raise TypeError('list<secp256k1_pedersen_commitment *> or None is required')
    if type(nonce) is not bytes:
        raise TypeError('bytes is required')
    if type(private_nonce) is not bytes and private_nonce is not None:
        raise TypeError('bytes or None is required')
    if type(extra_commit) is not bytes and extra_commit is not None:
        raise TypeError('bytes or None is required')
    if type(message) is not bytes and message is not None:
        raise TypeError('bytes or None is required')
    proof = ffi.new('unsigned char []', SECP256K1_BULLETPROOF_MAX_PROOF)
    plen = ffi.new('size_t *', SECP256K1_BULLETPROOF_MAX_PROOF)
    result = lib.secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, proof, plen, tau_x if tau_x is not None else ffi.NULL, t_one if t_one is not None else ffi.NULL, t_two if t_two is not None else ffi.NULL, value, min_value if min_value is not None else ffi.NULL, list(map(lambda blinding_factor : ffi.from_buffer(blinding_factor), blind)), commits if commits is not None else ffi.NULL, len(value), value_gen, nbits, nonce, private_nonce if private_nonce is not None else ffi.NULL, extra_commit if extra_commit is not None else ffi.NULL, len(extra_commit) if extra_commit is not None else 0, message if message is not None else ffi.NULL)
    return bytes(ffi.buffer(proof, plen[0])) if result == 1 else None

def secp256k1_pedersen_commitment_parse(ctx, input):
    if type(input) is not bytes:
        raise TypeError('bytes is required')
    commit = ffi.new('secp256k1_pedersen_commitment *')
    result = lib.secp256k1_pedersen_commitment_parse(ctx, commit, input)
    return commit if result == 1 else None

def secp256k1_pedersen_commitment_serialize(ctx, commit):
    output = ffi.new('unsigned char []', 33)
    result = lib.secp256k1_pedersen_commitment_serialize(ctx, output, commit)
    return bytes(output) if result == 1 else None

def secp256k1_pedersen_commit(ctx, blind, value, value_gen, blind_gen):
    if type(blind) is not bytes:
        raise TypeError('bytes is required')
    commit = ffi.new('secp256k1_pedersen_commitment *')
    result = lib.secp256k1_pedersen_commit(ctx, commit, blind, value, value_gen, blind_gen)
    return commit if result == 1 else None

def secp256k1_pedersen_blind_commit(ctx, blind, value, value_gen, blind_gen):
    if type(blind) is not bytes :
        raise TypeError('bytes is required')
    if type(value) is not bytes:
        raise TypeError('bytes is required')
    commit = ffi.new('secp256k1_pedersen_commitment *')
    result = lib.secp256k1_pedersen_blind_commit(ctx, commit, blind, value, value_gen, blind_gen)
    return commit if result == 1 else None

def secp256k1_pedersen_blind_sum(ctx, blinds, npositive):
    if type(blinds) is not list:
        raise TypeError('list<bytes> is required')
    if not all(type(blind) is bytes for blind in blinds):
        raise TypeError('list<bytes> is required')
    blind_out = ffi.new('unsigned char []', 32)
    result = lib.secp256k1_pedersen_blind_sum(ctx, blind_out, list(map(lambda blind : ffi.from_buffer(blind), blinds)), len(blinds), npositive)
    return bytes(blind_out) if result == 1 else None

def secp256k1_pedersen_commit_sum(ctx, commits, ncommits):
    if type(commits) is not list:
        raise TypeError('list<secp256k1_pedersen_commitment *> is required')
    if type(ncommits) is not list:
        raise TypeError('list<secp256k1_pedersen_commitment *> is required')
    commit_out = ffi.new('secp256k1_pedersen_commitment *')
    result = lib.secp256k1_pedersen_commit_sum(ctx, commit_out, commits, len(commits), ncommits, len(ncommits))
    return commit_out if result == 1 else None

def secp256k1_pedersen_verify_tally(ctx, pos, neg):
    if type(pos) is not list:
        raise TypeError('list<secp256k1_pedersen_commitment *> is required')
    if type(neg) is not list:
        raise TypeError('list<secp256k1_pedersen_commitment *> is required')
    result = lib.secp256k1_pedersen_verify_tally(ctx, pos, len(pos), neg, len(neg))
    return result == 1

def secp256k1_pedersen_blind_generator_blind_sum(ctx, value, generator_blind, blinding_factor, n_inputs):
    if type(value) is not list:
        raise TypeError('list<int> is required')
    if type(generator_blind) is not list:
        raise TypeError('list<bytes> is required')
    if not all(type(blind) is bytes for blind in generator_blind):
        raise TypeError('list<bytes> is required')
    if type(blinding_factor) is not list:
        raise TypeError('list<bytes> is required')
    if not all(type(blind) is bytes for blind in blinding_factor):
        raise TypeError('list<bytes> is required')
    assert len(blinding_factor) >= 1
    final_blinding_factor = ffi.new('unsigned char []', len(blinding_factor[-1]))
    new_blinding_factor = list(map(lambda blind : ffi.from_buffer(blind), blinding_factor))
    new_blinding_factor[-1] = final_blinding_factor
    result = lib.secp256k1_pedersen_blind_generator_blind_sum(ctx, value, list(map(lambda blind : ffi.from_buffer(blind), generator_blind)), new_blinding_factor, len(blinding_factor), n_inputs)
    return bytes(final_blinding_factor) if result == 1 else None

def secp256k1_blind_switch(ctx, blind, value, value_gen, blind_gen, switch_pubkey):
    if type(blind) is not bytes:
        raise TypeError('bytes is required')
    blind_switch = ffi.new('unsigned char []', 32)
    result = lib.secp256k1_blind_switch(ctx, blind_switch, blind, value, value_gen, blind_gen, switch_pubkey)
    return bytes(blind_switch) if result == 1 else None

def secp256k1_pedersen_commitment_to_pubkey(ctx, commit):
    pubkey = ffi.new('secp256k1_pubkey *')
    result = lib.secp256k1_pedersen_commitment_to_pubkey(ctx, pubkey, commit)
    return pubkey if result == 1 else None

def secp256k1_pubkey_to_pedersen_commitment(ctx, pubkey):
    commit = ffi.new('secp256k1_pedersen_commitment *')
    result = lib.secp256k1_pubkey_to_pedersen_commitment(ctx, commit, pubkey)
    return commit if result == 1 else None

def secp256k1_ecdh(ctx, pubkey, privkey):
    if type(privkey) is not bytes:
        raise TypeError('bytes is required')
    result_key = ffi.new('unsigned char []', 32)
    result = lib.secp256k1_ecdh(ctx, result_key, pubkey, privkey)
    return bytes(result_key) if result == 1 else None

def secp256k1_generator_parse(ctx, input):
    if type(input) is not bytes:
        raise TypeError('bytes is required')
    commit = ffi.new('secp256k1_generator *')
    result = lib.secp256k1_generator_parse(ctx, commit, input)
    return commit if result == 1 else None

def secp256k1_generator_serialize(ctx, commit):
    output = ffi.new('unsigned char []', 33)
    result = lib.secp256k1_generator_serialize(ctx, output, commit)
    return bytes(output) if result == 1 else None

def secp256k1_generator_generate(ctx, seed32):
    if type(seed32) is not bytes:
        raise TypeError('bytes is required')
    gen = ffi.new('secp256k1_generator *')
    result = lib.secp256k1_generator_generate(ctx, gen, seed32)
    return gen if result == 1 else None

def secp256k1_generator_generate_blinded(ctx, key32, blind32):
    if type(key32) is not bytes:
        raise TypeError('bytes is required')
    if type(blind32) is not bytes:
        raise TypeError('bytes is required')
    gen = ffi.new('secp256k1_generator *')
    result = lib.secp256k1_generator_generate_blinded(ctx, gen, key32, blind32)
    return gen if result == 1 else None

def secp256k1_context_preallocated_size(flags):
    result = lib.secp256k1_context_preallocated_size(flags)
    return result

def secp256k1_context_preallocated_create(prealloc, flags):
    result = lib.secp256k1_context_preallocated_create(prealloc, flags)
    return result if result != ffi.NULL else None

def secp256k1_context_preallocated_clone_size(ctx):
    result = lib.secp256k1_context_preallocated_clone_size(ctx)
    return result

def secp256k1_context_preallocated_clone(ctx, prealloc):
    result = lib.secp256k1_context_preallocated_clone(ctx, prealloc)
    return result if result != ffi.NULL else None

def secp256k1_context_preallocated_destroy(ctx):
    lib.secp256k1_context_preallocated_destroy(ctx if ctx is not None else ffi.NULL)

def secp256k1_rangeproof_verify(ctx, commit, proof, extra_commit, gen):
    if type(proof) is not bytes:
        raise TypeError('bytes is required')
    if type(extra_commit) is not bytes and extra_commit is not None:
        raise TypeError('bytes or None is required')
    min_value = ffi.new('uint64_t *')
    max_value = ffi.new('uint64_t *')
    result = lib.secp256k1_rangeproof_verify(ctx, min_value, max_value, commit, proof, len(proof), extra_commit if extra_commit is not None else ffi.NULL, len(extra_commit) if extra_commit is not None else 0, gen)
    return (min_value[0], max_value[0]) if result == 1 else None

def secp256k1_rangeproof_rewind(ctx, nonce, commit, proof, extra_commit, gen):
    if type(nonce) is not bytes:
        raise TypeError('bytes is required')
    if type(proof) is not bytes:
        raise TypeError('bytes is required')
    if type(extra_commit) is not bytes and extra_commit is not None:
        raise TypeError('bytes or None is required')
    blind_out = ffi.new('unsigned char []', 32)
    value_out = ffi.new('uint64_t *')
    message_max_length = 4096
    message_out = ffi.new('unsigned char []', message_max_length)
    outlen = ffi.new('size_t *', message_max_length)
    min_value = ffi.new('uint64_t *')
    max_value = ffi.new('uint64_t *')
    result = lib.secp256k1_rangeproof_rewind(ctx, blind_out, value_out, message_out, outlen, nonce, min_value, max_value, commit, proof, len(proof), extra_commit if extra_commit is not None else ffi.NULL, len(extra_commit) if extra_commit is not None else 0, gen)
    return (bytes(blind_out), value_out[0], bytes(ffi.buffer(message_out, outlen[0])), min_value[0], max_value[0]) if result == 1 else None

def secp256k1_rangeproof_sign(ctx, min_value, commit, blind, nonce, exp, min_bits, value, message, extra_commit, gen):
    if type(blind) is not bytes:
        raise TypeError('bytes is required')
    if type(nonce) is not bytes:
        raise TypeError('bytes is required')
    if type(message) is not bytes and message is not None:
        raise TypeError('bytes or None is required')
    if type(extra_commit) is not bytes and extra_commit is not None:
        raise TypeError('bytes or None is required')
    proof_max_length = 5134
    proof = ffi.new('unsigned char []', proof_max_length)
    plen = ffi.new('size_t *', proof_max_length)
    result = lib.secp256k1_rangeproof_sign(ctx, proof, plen, min_value, commit, blind, nonce, exp, min_bits, value, message if message is not None else ffi.NULL, len(message) if message is not None else 0, extra_commit if extra_commit is not None else ffi.NULL, len(extra_commit) if extra_commit is not None else 0, gen)
    return bytes(ffi.buffer(proof, plen[0])) if result == 1 else None

def secp256k1_rangeproof_info(ctx, proof):
    if type(proof) is not bytes:
        raise TypeError('bytes is required')
    exp = ffi.new('int *')
    mantissa = ffi.new('int *')
    min_value = ffi.new('uint64_t *')
    max_value = ffi.new('uint64_t *')
    result = lib.secp256k1_rangeproof_info(ctx, exp, mantissa, min_value, max_value, proof, len(proof))
    return (exp[0], mantissa[0], min_value[0], max_value[0]) if result == 1 else None

def secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, input64, recid):
    if type(input64) is not bytes:
        raise TypeError('bytes is required')
    sig = ffi.new('secp256k1_ecdsa_recoverable_signature *')
    result = lib.secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, sig, input64, recid)
    return sig if result == 1 else None

def secp256k1_ecdsa_recoverable_signature_convert(ctx, sigin):
    sig = ffi.new('secp256k1_ecdsa_signature *')
    result = lib.secp256k1_ecdsa_recoverable_signature_convert(ctx, sig, sigin)
    return sig if result == 1 else None

def secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, sig):
    output64 = ffi.new('unsigned char []', 64)
    recid = ffi.new('int *')
    result = lib.secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, output64, recid, sig)
    return (bytes(output64), recid[0]) if result == 1 else None

def secp256k1_ecdsa_sign_recoverable(ctx, msg32, seckey, noncefp, ndata):
    if type(msg32) is not bytes:
        raise TypeError('bytes is required')
    if type(seckey) is not bytes:
        raise TypeError('bytes is required')
    if type(ndata) is not bytes and ndata is not None:
        raise TypeError('bytes or None is required')
    sig = ffi.new('secp256k1_ecdsa_recoverable_signature *')
    result = lib.secp256k1_ecdsa_sign_recoverable(ctx, sig, msg32, seckey, noncefp if noncefp is not None else ffi.NULL, ndata if ndata is not None else ffi.NULL)
    return sig if result == 1 else None

def secp256k1_ecdsa_recover(ctx, sig, msg32):
    if type(msg32) is not bytes:
        raise TypeError('bytes is required')
    pubkey = ffi.new('secp256k1_pubkey *')
    result = lib.secp256k1_ecdsa_recover(ctx, pubkey, sig, msg32)
    return pubkey if result == 1 else None

def secp256k1_schnorrsig_serialize(ctx, sig):
    out64 = ffi.new('unsigned char []', 64)
    result = lib.secp256k1_schnorrsig_serialize(ctx, out64, sig)
    return bytes(out64) if result == 1 else None

def secp256k1_schnorrsig_parse(ctx, in64):
    if type(in64) is not bytes:
        raise TypeError('bytes is required')
    sig = ffi.new('secp256k1_schnorrsig *')
    result = lib.secp256k1_schnorrsig_parse(ctx, sig, in64)
    return sig if result == 1 else None

def secp256k1_schnorrsig_sign(ctx, msg32, seckey, noncefp, ndata):
    if type(msg32) is not bytes:
        raise TypeError('bytes is required')
    if type(seckey) is not bytes:
        raise TypeError('bytes is required')
    if type(ndata) is not bytes and ndata is not None:
        raise TypeError('bytes or None is required')
    sig = ffi.new('secp256k1_schnorrsig *')
    nonce_is_negated = ffi.new('int *')
    result = lib.secp256k1_schnorrsig_sign(ctx, sig, nonce_is_negated, msg32, seckey, noncefp if noncefp is not None else ffi.NULL, ndata if ndata is not None else ffi.NULL)
    return (sig, nonce_is_negated[0] == 1) if result == 1 else None

def secp256k1_schnorrsig_verify(ctx, sig, msg32, pubkey):
    if type(msg32) is not bytes:
        raise TypeError('bytes is required')
    result = lib.secp256k1_schnorrsig_verify(ctx, sig, msg32, pubkey)
    return result == 1

def secp256k1_schnorrsig_verify_batch(ctx, scratch, sig, msg32, pk):
    if type(sig) is not list:
        raise TypeError('list<secp256k1_schnorrsig *> is required')
    if type(msg32) is not list:
        raise TypeError('list<bytes> is required')
    if not all(type(message) is bytes for message in msg32):
        raise TypeError('list<bytes> is required')
    if type(pk) is not list:
        raise TypeError('list<secp256k1_pubkey *> is required')
    result = lib.secp256k1_schnorrsig_verify_batch(ctx, scratch, sig, list(map(lambda message : ffi.from_buffer(message), msg32)), pk, len(sig))
    return result == 1

def secp256k1_surjectionproof_parse(ctx, input):
    if type(input) is not bytes:
        raise TypeError('bytes is required')
    proof = ffi.new('secp256k1_surjectionproof *')
    result = lib.secp256k1_surjectionproof_parse(ctx, proof, input, len(input))
    return proof if result == 1 else None

def secp256k1_surjectionproof_serialize(ctx, proof):
    output = ffi.new('unsigned char []', SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES_MAX)
    outputlen = ffi.new('size_t *', SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES_MAX)
    result = lib.secp256k1_surjectionproof_serialize(ctx, output, outputlen, proof)
    return bytes(ffi.buffer(output, outputlen[0])) if result == 1 else None

def secp256k1_surjectionproof_n_total_inputs(ctx, proof):
    result = lib.secp256k1_surjectionproof_n_total_inputs(ctx, proof)
    return result

def secp256k1_surjectionproof_n_used_inputs(ctx, proof):
    result = lib.secp256k1_surjectionproof_n_used_inputs(ctx, proof)
    return result

def secp256k1_surjectionproof_serialized_size(ctx, proof):
    result = lib.secp256k1_surjectionproof_serialized_size(ctx, proof)
    return result

def secp256k1_surjectionproof_initialize(ctx, fixed_input_tags, n_input_tags_to_use, fixed_output_tag, n_max_iterations, random_seed32):
    if type(fixed_input_tags) is not list:
        raise TypeError('list<secp256k1_fixed_asset_tag *> is required')
    if not all(isinstance(fixed_input_tag, ffi.CData) and ffi.typeof(fixed_input_tag) is ffi.typeof('secp256k1_fixed_asset_tag *') for fixed_input_tag in fixed_input_tags):
        raise TypeError('list<secp256k1_fixed_asset_tag *> is required')
    if type(random_seed32) is not bytes:
        raise TypeError('bytes is requires')
    input_tags = ffi.new('secp256k1_fixed_asset_tag []', len(fixed_input_tags))
    for index, fixed_input_tag in enumerate(fixed_input_tags):
        ffi.memmove(ffi.addressof(input_tags, index), fixed_input_tag, ffi.sizeof('secp256k1_fixed_asset_tag'))
    proof = ffi.new('secp256k1_surjectionproof *')
    input_index = ffi.new('size_t *')
    result = lib.secp256k1_surjectionproof_initialize(ctx, proof, input_index, input_tags, len(fixed_input_tags), n_input_tags_to_use, fixed_output_tag, n_max_iterations, random_seed32)
    return (proof, input_index[0]) if result != 0 else None

def secp256k1_surjectionproof_generate(ctx, proof, ephemeral_input_tags, ephemeral_output_tag, input_index, input_blinding_key, output_blinding_key):
    if not isinstance(proof, ffi.CData) or not ffi.typeof(proof) is ffi.typeof('secp256k1_surjectionproof *'):
        raise TypeError('secp256k1_surjectionproof * is required')
    if type(ephemeral_input_tags) is not list:
        raise TypeError('list<secp256k1_generator *> is required')
    if not all(isinstance(ephemeral_input_tag, ffi.CData) and ffi.typeof(ephemeral_input_tag) is ffi.typeof('secp256k1_generator *') for ephemeral_input_tag in ephemeral_input_tags):
        raise TypeError('list<secp256k1_generator *> is required')
    if type(input_blinding_key) is not bytes:
        raise TypeError('bytes is required')
    if type(output_blinding_key) is not bytes:
        raise TypeError('bytes is required')
    input_tags = ffi.new('secp256k1_generator []', len(ephemeral_input_tags))
    for index, ephemeral_input_tag in enumerate(ephemeral_input_tags):
        ffi.memmove(ffi.addressof(input_tags, index), ephemeral_input_tag, ffi.sizeof('secp256k1_generator'))
    new_proof = ffi.new('secp256k1_surjectionproof *')
    ffi.memmove(new_proof, proof, ffi.sizeof('secp256k1_surjectionproof'))
    result = lib.secp256k1_surjectionproof_generate(ctx, new_proof, input_tags, len(ephemeral_input_tags), ephemeral_output_tag, input_index, input_blinding_key, output_blinding_key)
    return new_proof if result == 1 else None

def secp256k1_surjectionproof_verify(ctx, proof, ephemeral_input_tags, ephemeral_output_tag):
    if type(ephemeral_input_tags) is not list:
        raise TypeError('list<secp256k1_generator *> is required')
    if not all(isinstance(ephemeral_input_tag, ffi.CData) and ffi.typeof(ephemeral_input_tag) is ffi.typeof('secp256k1_generator *') for ephemeral_input_tag in ephemeral_input_tags):
        raise TypeError('list<secp256k1_generator *> is required')
    input_tags = ffi.new('secp256k1_generator []', len(ephemeral_input_tags))
    for index, ephemeral_input_tag in enumerate(ephemeral_input_tags):
        ffi.memmove(ffi.addressof(input_tags, index), ephemeral_input_tag, ffi.sizeof('secp256k1_generator'))
    result = lib.secp256k1_surjectionproof_verify(ctx, proof, input_tags, len(ephemeral_input_tags), ephemeral_output_tag)
    return result == 1

def secp256k1_whitelist_signature_parse(ctx, input):
    if type(input) is not bytes:
        raise TypeError('bytes is required')
    sig = ffi.new('secp256k1_whitelist_signature *')
    result = lib.secp256k1_whitelist_signature_parse(ctx, sig, input, len(input))
    return sig if result == 1 else None

def secp256k1_whitelist_signature_n_keys(sig):
    result = lib.secp256k1_whitelist_signature_n_keys(sig)
    return result

def secp256k1_whitelist_signature_serialize(ctx, sig):
    serialized_whitelist_signature_max_length = 8225
    output = ffi.new('unsigned char []', serialized_whitelist_signature_max_length)
    output_len = ffi.new('size_t *', serialized_whitelist_signature_max_length)
    result = lib.secp256k1_whitelist_signature_serialize(ctx, output, output_len, sig)
    return bytes(ffi.buffer(output, output_len[0])) if result == 1 else None

def secp256k1_whitelist_sign(ctx, online_pubkeys, offline_pubkeys, sub_pubkey, online_seckey, summed_seckey, index, noncefp, noncedata):
    if type(online_pubkeys) is not list:
        raise TypeError('list<secp256k1_pubkey *> is required')
    if not all(isinstance(online_pubkey, ffi.CData) and ffi.typeof(online_pubkey) is ffi.typeof('secp256k1_pubkey *') for online_pubkey in online_pubkeys):
        raise TypeError('list<secp256k1_pubkey *> is required')
    if type(offline_pubkeys) is not list:
        raise TypeError('list<secp256k1_pubkey *> is required')
    if not all(isinstance(offline_pubkey, ffi.CData) and ffi.typeof(offline_pubkey) is ffi.typeof('secp256k1_pubkey *') for offline_pubkey in offline_pubkeys):
        raise TypeError('list<secp256k1_pubkey *> is required')
    if type(online_seckey) is not bytes:
        raise TypeError('bytes is required')
    if type(summed_seckey) is not bytes:
        raise TypeError('bytes is required')
    if type(noncedata) is not bytes and noncedata is not None:
        raise TypeError('bytes or None is required')
    online_public_keys = ffi.new('secp256k1_pubkey []', len(online_pubkeys))
    for online_pubkey_index, online_pubkey in enumerate(online_pubkeys):
        ffi.memmove(ffi.addressof(online_public_keys, online_pubkey_index), online_pubkey, ffi.sizeof('secp256k1_pubkey'))
    offline_public_keys = ffi.new('secp256k1_pubkey []', len(offline_pubkeys))
    for offline_pubkey_index, offline_pubkey in enumerate(offline_pubkeys):
        ffi.memmove(ffi.addressof(offline_public_keys, offline_pubkey_index), offline_pubkey, ffi.sizeof('secp256k1_pubkey'))
    sig = ffi.new('secp256k1_whitelist_signature *')
    result = lib.secp256k1_whitelist_sign(ctx, sig, online_public_keys, offline_public_keys, len(online_pubkeys), sub_pubkey, online_seckey, summed_seckey, index, noncefp if noncefp is not None else ffi.NULL, noncedata if noncedata is not None else ffi.NULL)
    return sig if result == 1 else None

def secp256k1_whitelist_verify(ctx, sig, online_pubkeys, offline_pubkeys, sub_pubkey):
    if type(online_pubkeys) is not list:
        raise TypeError('list<secp256k1_pubkey *> is required')
    if not all(isinstance(online_pubkey, ffi.CData) and ffi.typeof(online_pubkey) is ffi.typeof('secp256k1_pubkey *') for online_pubkey in online_pubkeys):
        raise TypeError('list<secp256k1_pubkey *> is required')
    if type(offline_pubkeys) is not list:
        raise TypeError('list<secp256k1_pubkey *> is required')
    if not all(isinstance(offline_pubkey, ffi.CData) and ffi.typeof(offline_pubkey) is ffi.typeof('secp256k1_pubkey *') for offline_pubkey in offline_pubkeys):
        raise TypeError('list<secp256k1_pubkey *> is required')
    online_public_keys = ffi.new('secp256k1_pubkey []', len(online_pubkeys))
    for index, online_pubkey in enumerate(online_pubkeys):
        ffi.memmove(ffi.addressof(online_public_keys, index), online_pubkey, ffi.sizeof('secp256k1_pubkey'))
    offline_public_keys = ffi.new('secp256k1_pubkey []', len(offline_pubkeys))
    for index, offline_pubkey in enumerate(offline_pubkeys):
        ffi.memmove(ffi.addressof(offline_public_keys, index), offline_pubkey, ffi.sizeof('secp256k1_pubkey'))
    result = lib.secp256k1_whitelist_verify(ctx, sig, online_public_keys, offline_public_keys, len(online_pubkeys), sub_pubkey)
    return result == 1
