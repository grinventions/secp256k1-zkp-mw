from secp256k1_zkp_mw import *
import pytest

def test_definitions():
    # Test definitions
    assert SECP256K1_FLAGS_TYPE_MASK == (1 << 8) - 1
    assert SECP256K1_FLAGS_TYPE_CONTEXT == 1 << 0
    assert SECP256K1_FLAGS_TYPE_COMPRESSION == 1 << 1
    assert SECP256K1_FLAGS_BIT_CONTEXT_VERIFY == 1 << 8
    assert SECP256K1_FLAGS_BIT_CONTEXT_SIGN == 1 << 9
    assert SECP256K1_FLAGS_BIT_COMPRESSION == 1 << 8
    assert SECP256K1_CONTEXT_VERIFY == SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_VERIFY
    assert SECP256K1_CONTEXT_SIGN == SECP256K1_FLAGS_TYPE_CONTEXT | SECP256K1_FLAGS_BIT_CONTEXT_SIGN
    assert SECP256K1_CONTEXT_NONE == SECP256K1_FLAGS_TYPE_CONTEXT
    assert SECP256K1_EC_COMPRESSED == SECP256K1_FLAGS_TYPE_COMPRESSION | SECP256K1_FLAGS_BIT_COMPRESSION
    assert SECP256K1_EC_UNCOMPRESSED == SECP256K1_FLAGS_TYPE_COMPRESSION
    assert SECP256K1_TAG_PUBKEY_EVEN == 0x02
    assert SECP256K1_TAG_PUBKEY_ODD == 0x03
    assert SECP256K1_TAG_PUBKEY_UNCOMPRESSED == 0x04
    assert SECP256K1_TAG_PUBKEY_HYBRID_EVEN == 0x06
    assert SECP256K1_TAG_PUBKEY_HYBRID_ODD == 0x07
    assert SECP256K1_BULLETPROOF_MAX_DEPTH == 31
    assert SECP256K1_BULLETPROOF_MAX_PROOF == 160 + 36 * 32 + 7
    assert SECP256K1_SURJECTIONPROOF_MAX_N_INPUTS == 256
    assert SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES(12, 4) == 2 + (12 + 7) // 8 + 32 * (1 + 4)
    assert SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES_MAX == SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES(SECP256K1_SURJECTIONPROOF_MAX_N_INPUTS, SECP256K1_SURJECTIONPROOF_MAX_N_INPUTS)
    assert SECP256K1_WHITELIST_MAX_N_KEYS == 256

def test_constants():
    # Test precomputed context
    assert secp256k1_ec_seckey_verify(secp256k1_context_no_precomp, bytes.fromhex('8c3882fbd7966085e760e000b1ea9eb1ad3df1eec02e720adaa5104c6bd9fd88')) is True

    # Test RFC6967 nonce function
    assert secp256k1_ecdsa_sign(secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN), bytes.fromhex('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'), bytes.fromhex('8c3882fbd7966085e760e000b1ea9eb1ad3df1eec02e720adaa5104c6bd9fd88'), secp256k1_nonce_function_rfc6979, None) is not None

    # Test default nonce function
    assert secp256k1_ecdsa_sign(secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN), bytes.fromhex('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855'), bytes.fromhex('8c3882fbd7966085e760e000b1ea9eb1ad3df1eec02e720adaa5104c6bd9fd88'), secp256k1_nonce_function_default, None) is not None

    # Test generator h
    assert secp256k1_pedersen_commit(secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN), bytes.fromhex('8c3882fbd7966085e760e000b1ea9eb1ad3df1eec02e720adaa5104c6bd9fd88'), 123456789, secp256k1_generator_h, secp256k1_generator_const_g) is not None

    # Test generator const g
    assert secp256k1_pedersen_commit(secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN), bytes.fromhex('8c3882fbd7966085e760e000b1ea9eb1ad3df1eec02e720adaa5104c6bd9fd88'), 123456789, secp256k1_generator_const_h, secp256k1_generator_const_g) is not None

    # Test generator const h
    assert secp256k1_pedersen_commit(secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN), bytes.fromhex('8c3882fbd7966085e760e000b1ea9eb1ad3df1eec02e720adaa5104c6bd9fd88'), 123456789, secp256k1_generator_const_h, secp256k1_generator_const_g) is not None

def test_secp256k1_context_create():
    # Test creating none context
    none_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE)
    assert none_ctx is not None

    # Test creating verify context
    verify_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY)
    assert verify_ctx is not None

    # Test creating sign context
    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN)
    assert sign_ctx is not None

    # Test creating verify and sign context
    verify_and_sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert verify_and_sign_ctx is not None

    # Test creating context with invalid types
    with pytest.raises(TypeError):
        secp256k1_context_create(None)
    with pytest.raises(TypeError):
        secp256k1_context_create('string')

    # Test creating context with invalid values
    with pytest.raises(OverflowError):
        secp256k1_context_create(-1)
    with pytest.raises(OverflowError):
        secp256k1_context_create(0x100000000)

def test_secp256k1_context_clone():
    # Test cloning context
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    clone = secp256k1_context_clone(ctx)
    assert clone is not None

    # Test cloning context with invalid types
    with pytest.raises(TypeError):
        secp256k1_context_clone(None)
    with pytest.raises(TypeError):
        secp256k1_context_clone('string')

def test_secp256k1_context_destroy():
    # Test destroying no context
    secp256k1_context_destroy(None)
    assert True

    # Test destroying context
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    secp256k1_context_destroy(ctx)
    assert True

    # Test destroying context with invalid types
    with pytest.raises(TypeError):
        secp256k1_context_destroy('string')

def test_secp256k1_context_set_illegal_callback():
    # Test setting no illegal callback
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE)
    assert ctx is not None
    secp256k1_context_set_illegal_callback(ctx, None, None)
    assert True

    # Test setting illegal callback without data
    @ffi.callback('void (char *, void *)')
    def fun(message, data):
        if data != ffi.NULL:
            int_data = ffi.cast('int *', data)
            int_data[0] += 1
    secp256k1_context_set_illegal_callback(ctx, fun, None)
    secp256k1_ec_pubkey_create(ctx, bytes(32))
    assert True

    # Test setting illegal callback without function
    data = ffi.new('int *', 0)
    secp256k1_context_set_illegal_callback(ctx, None, data)
    assert True

    # Test setting illegal callback with all
    secp256k1_context_set_illegal_callback(ctx, fun, data)
    secp256k1_ec_pubkey_create(ctx, bytes(32))
    assert data[0] == 1

    # Test setting illegal callback with invalid types
    with pytest.raises(TypeError):
        secp256k1_context_set_illegal_callback(None, None, None)
    with pytest.raises(TypeError):
        secp256k1_context_set_illegal_callback('string', None, None)
    with pytest.raises(TypeError):
        secp256k1_context_set_illegal_callback(ctx, 'string', None)
    with pytest.raises(TypeError):
        secp256k1_context_set_illegal_callback(ctx, None, 'string')

def test_secp256k1_context_set_error_callback():
    # Test setting no error callback
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE)
    assert ctx is not None
    secp256k1_context_set_error_callback(ctx, None, None)
    assert True

    # Test setting error callback without data
    @ffi.callback('void (char *, void *)')
    def fun(message, data):
        if data != ffi.NULL:
            int_data = ffi.cast('int *', data)
            int_data[0] += 1
    secp256k1_context_set_error_callback(ctx, fun, None)
    assert True

    # Test setting error callback without function
    data = ffi.new('int *', 0)
    secp256k1_context_set_error_callback(ctx, None, data)
    assert True

    # Test setting error callback with all
    secp256k1_context_set_error_callback(ctx, fun, data)
    assert True

    # Test setting error callback with invalid types
    with pytest.raises(TypeError):
        secp256k1_context_set_error_callback(None, None, None)
    with pytest.raises(TypeError):
        secp256k1_context_set_error_callback('string', None, None)
    with pytest.raises(TypeError):
        secp256k1_context_set_error_callback(ctx, 'string', None)
    with pytest.raises(TypeError):
        secp256k1_context_set_error_callback(ctx, None, 'string')

def test_secp256k1_scratch_space_create():
    # Test creating scratch space
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    scratch = secp256k1_scratch_space_create(ctx, 30720)
    assert scratch is not None

    # Test creating scratch space with invalid types
    with pytest.raises(TypeError):
        secp256k1_scratch_space_create(None, 30720)
    with pytest.raises(TypeError):
        secp256k1_scratch_space_create('string', 30720)
    with pytest.raises(TypeError):
        secp256k1_scratch_space_create(ctx, None)
    with pytest.raises(TypeError):
        secp256k1_scratch_space_create(ctx, 'string')

    # Test creating scratch space with invalid values
    with pytest.raises(OverflowError):
        secp256k1_scratch_space_create(ctx, -1)
    with pytest.raises(OverflowError):
        secp256k1_scratch_space_create(ctx, 0x10000000000000000)

def test_secp256k1_scratch_space_destroy():
    # Test destroying no scratch space
    secp256k1_scratch_space_destroy(None)
    assert True

    # Test destroying scratch space
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    scratch = secp256k1_scratch_space_create(ctx, 30720)
    assert scratch is not None
    secp256k1_scratch_space_destroy(scratch)
    assert True

    # Test destroying scratch space with invalid types
    with pytest.raises(TypeError):
        secp256k1_scratch_space_destroy('string')

def test_secp256k1_ec_pubkey_parse():
    # Test parsing compressed public key
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    valid_compressed_input = bytes.fromhex('03e7e3dd547cc3171ffdc403824fcc5d5d03712a29f459ca10668c2864c088e951')
    valid_pubkey_from_compressed = secp256k1_ec_pubkey_parse(ctx, valid_compressed_input)
    assert valid_pubkey_from_compressed is not None

    # Test parsing uncompressed public key
    valid_uncompressed_input = bytes.fromhex('04e7e3dd547cc3171ffdc403824fcc5d5d03712a29f459ca10668c2864c088e9518c109ba4721a445bbef6516b94f71ad2f43dff938e0986f3fe371a26d7feec49')
    valid_pubkey_from_uncompressed = secp256k1_ec_pubkey_parse(ctx, valid_uncompressed_input)
    assert valid_pubkey_from_uncompressed is not None

    # Test parsing invalid public key
    invalid_input = bytes.fromhex('e7e3dd547cc3171ffdc403824fcc5d5d03712a29f459ca10668c2864c088e951')
    invalid_pubkey = secp256k1_ec_pubkey_parse(ctx, invalid_input)
    assert invalid_pubkey is None

    # Test parsing public key with invalid types
    with pytest.raises(TypeError):
        secp256k1_ec_pubkey_parse(None, valid_compressed_input)
    with pytest.raises(TypeError):
        secp256k1_ec_pubkey_parse('string', valid_compressed_input)
    with pytest.raises(TypeError):
        secp256k1_ec_pubkey_parse(ctx, None)
    with pytest.raises(TypeError):
        secp256k1_ec_pubkey_parse(ctx, 'string')

def test_secp256k1_ec_pubkey_serialize():
    # Test serializing compressed pubic key
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    input = bytes.fromhex('03e7e3dd547cc3171ffdc403824fcc5d5d03712a29f459ca10668c2864c088e951')
    pubkey = secp256k1_ec_pubkey_parse(ctx, input)
    assert pubkey is not None
    valid_compressed_output = secp256k1_ec_pubkey_serialize(ctx, pubkey, SECP256K1_EC_COMPRESSED)
    assert valid_compressed_output == input

    # Test serializing uncompressed pubic key
    valid_uncompressed_output = secp256k1_ec_pubkey_serialize(ctx, pubkey, SECP256K1_EC_UNCOMPRESSED)
    assert valid_uncompressed_output == bytes.fromhex('04e7e3dd547cc3171ffdc403824fcc5d5d03712a29f459ca10668c2864c088e9518c109ba4721a445bbef6516b94f71ad2f43dff938e0986f3fe371a26d7feec49')

    # Test serializing public key with invalid types
    with pytest.raises(TypeError):
        secp256k1_ec_pubkey_serialize(None, pubkey, SECP256K1_EC_COMPRESSED)
    with pytest.raises(TypeError):
        secp256k1_ec_pubkey_serialize('string', pubkey, SECP256K1_EC_COMPRESSED)
    with pytest.raises(TypeError):
        secp256k1_ec_pubkey_serialize(ctx, None, SECP256K1_EC_COMPRESSED)
    with pytest.raises(TypeError):
        secp256k1_ec_pubkey_serialize(ctx, 'string', SECP256K1_EC_COMPRESSED)
    with pytest.raises(TypeError):
        secp256k1_ec_pubkey_serialize(ctx, pubkey, None)
    with pytest.raises(TypeError):
        secp256k1_ec_pubkey_serialize(ctx, pubkey, 'string')

    # Test serializing public key with invalid values
    with pytest.raises(OverflowError):
        secp256k1_ec_pubkey_serialize(ctx, pubkey, -1)
    with pytest.raises(OverflowError):
        secp256k1_ec_pubkey_serialize(ctx, pubkey, 0x100000000)

def test_secp256k1_ecdsa_signature_parse_compact():
    # Test parsing compact signature
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    valid_input64 = bytes.fromhex('f49afdcc13c16480aff27fc86c5aa640e7072ea062e3d90ccfcbff1620a66cbca142cc953414dd265951eb606cd06609e7051ba3c7144e1919717298d11dc9d7')
    valid_sig = secp256k1_ecdsa_signature_parse_compact(ctx, valid_input64)
    assert valid_sig is not None

    # Test parsing invalid compact signature
    invalid_input64 = bytes.fromhex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
    invalid_sig = secp256k1_ecdsa_signature_parse_compact(ctx, invalid_input64)
    assert invalid_sig is None

    # Test parsing compact signature with invalid types
    with pytest.raises(TypeError):
        secp256k1_ecdsa_signature_parse_compact(None, valid_input64)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_signature_parse_compact('string', valid_input64)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_signature_parse_compact(ctx, None)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_signature_parse_compact(ctx, 'string')

def test_secp256k1_ecdsa_signature_parse_der():
    # Test parsing DER signature
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    valid_input = bytes.fromhex('3046022100f49afdcc13c16480aff27fc86c5aa640e7072ea062e3d90ccfcbff1620a66cbc022100a142cc953414dd265951eb606cd06609e7051ba3c7144e1919717298d11dc9d7')
    valid_sig = secp256k1_ecdsa_signature_parse_der(ctx, valid_input)
    assert valid_sig is not None

    # Test parsing invalid DER signature
    invalid_input = bytes.fromhex('3146022100f49afdcc13c16480aff27fc86c5aa640e7072ea062e3d90ccfcbff1620a66cbc022100a142cc953414dd265951eb606cd06609e7051ba3c7144e1919717298d11dc9d7')
    invalid_sig = secp256k1_ecdsa_signature_parse_der(ctx, invalid_input)
    assert invalid_sig is None

    # Test parsing DER signature with invalid types
    with pytest.raises(TypeError):
        secp256k1_ecdsa_signature_parse_der(None, valid_input)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_signature_parse_der('string', valid_input)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_signature_parse_der(ctx, None)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_signature_parse_der(ctx, 'string')

def test_secp256k1_ecdsa_signature_serialize_der():
    # Test serializing DER signature
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    input = bytes.fromhex('3046022100f49afdcc13c16480aff27fc86c5aa640e7072ea062e3d90ccfcbff1620a66cbc022100a142cc953414dd265951eb606cd06609e7051ba3c7144e1919717298d11dc9d7')
    sig = secp256k1_ecdsa_signature_parse_der(ctx, input)
    assert sig is not None
    output = secp256k1_ecdsa_signature_serialize_der(ctx, sig)
    assert output == input

    # Test serializing DER signature with invalid types
    with pytest.raises(TypeError):
        secp256k1_ecdsa_signature_serialize_der(None, sig)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_signature_serialize_der('string', sig)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_signature_serialize_der(ctx, None)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_signature_serialize_der(ctx, 'string')

def test_secp256k1_ecdsa_signature_serialize_compact():
    # Test serializing compact signature
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    input64 = bytes.fromhex('f49afdcc13c16480aff27fc86c5aa640e7072ea062e3d90ccfcbff1620a66cbca142cc953414dd265951eb606cd06609e7051ba3c7144e1919717298d11dc9d7')
    sig = secp256k1_ecdsa_signature_parse_compact(ctx, input64)
    assert sig is not None
    output64 = secp256k1_ecdsa_signature_serialize_compact(ctx, sig)
    assert output64 == input64

    # Test serializing compact signature with invalid types
    with pytest.raises(TypeError):
        secp256k1_ecdsa_signature_serialize_compact(None, sig)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_signature_serialize_compact('string', sig)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_signature_serialize_compact(ctx, None)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_signature_serialize_compact(ctx, 'string')

def test_secp256k1_ecdsa_verify():
    # Test verifying ECDSA
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    signature_input = bytes.fromhex('3045022100ea4f8b11c7c24cb1688c7f9c4499ec929cf0957c8368fb6bcd437e2685af0d5b022071543d2c077bfac05b74307068b06ed96a08bb4fddccf8a0a5cd13d0d38686bf')
    sig = secp256k1_ecdsa_signature_parse_der(ctx, signature_input)
    assert sig is not None
    valid_msg32 = bytes.fromhex('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    pubkey = secp256k1_ec_pubkey_parse(ctx, bytes.fromhex('03e7e3dd547cc3171ffdc403824fcc5d5d03712a29f459ca10668c2864c088e951'))
    assert pubkey is not None
    result = secp256k1_ecdsa_verify(ctx, sig, valid_msg32, pubkey)
    assert result is True

    # Test verifying invalid ECDSA
    invalid_msg32 = bytes.fromhex('f3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    result = secp256k1_ecdsa_verify(ctx, sig, invalid_msg32, pubkey)
    assert result is False

    # Test verifying ECDSA with invalid types
    with pytest.raises(TypeError):
        secp256k1_ecdsa_verify(None, sig, valid_msg32, pubkey)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_verify('string', sig, valid_msg32, pubkey)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_verify(ctx, None, valid_msg32, pubkey)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_verify(ctx, 'string', valid_msg32, pubkey)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_verify(ctx, sig, None, pubkey)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_verify(ctx, sig, 'string', pubkey)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_verify(ctx, sig, valid_msg32, None)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_verify(ctx, sig, valid_msg32, 'string')

def test_secp256k1_ecdsa_signature_normalize():
    # Test normalizing ECDSA
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    input64 = bytes.fromhex('f49afdcc13c16480aff27fc86c5aa640e7072ea062e3d90ccfcbff1620a66cbca142cc953414dd265951eb606cd06609e7051ba3c7144e1919717298d11dc9d7')
    sigin = secp256k1_ecdsa_signature_parse_compact(ctx, input64)
    assert sigin is not None
    sigout = secp256k1_ecdsa_signature_normalize(ctx, sigin)
    assert sigout is not None
    output = secp256k1_ecdsa_signature_serialize_der(ctx, sigout)
    assert output == bytes.fromhex('3045022100f49afdcc13c16480aff27fc86c5aa640e7072ea062e3d90ccfcbff1620a66cbc02205ebd336acbeb22d9a6ae149f932f99f4d3a9c142e8345222a660ebf3ff18776a')

    # Test normalizing ECDSA with invalid types
    with pytest.raises(TypeError):
        secp256k1_ecdsa_signature_normalize(None, sigin)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_signature_normalize('string', sigin)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_signature_normalize(ctx, None)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_signature_normalize(ctx, 'string')

def test_secp256k1_ecdsa_sign():
    # Test ECDSA signing with no nonce function
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    msg32 = bytes.fromhex('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    valid_seckey = bytes.fromhex('8c3882fbd7966085e760e000b1ea9eb1ad3df1eec02e720adaa5104c6bd9fd88')
    no_nonce_function_sig = secp256k1_ecdsa_sign(ctx, msg32, valid_seckey, None, None)
    assert no_nonce_function_sig is not None
    no_nonce_function_output64 = secp256k1_ecdsa_signature_serialize_compact(ctx, no_nonce_function_sig)
    assert no_nonce_function_output64 == bytes.fromhex('ea4f8b11c7c24cb1688c7f9c4499ec929cf0957c8368fb6bcd437e2685af0d5b71543d2c077bfac05b74307068b06ed96a08bb4fddccf8a0a5cd13d0d38686bf')

    # Test ECDSA signing with default nonce function
    default_nonce_function_sig = secp256k1_ecdsa_sign(ctx, msg32, valid_seckey, secp256k1_nonce_function_default, None)
    assert default_nonce_function_sig is not None
    default_nocne_function_output64 = secp256k1_ecdsa_signature_serialize_compact(ctx, default_nonce_function_sig)
    assert default_nocne_function_output64 == bytes.fromhex('ea4f8b11c7c24cb1688c7f9c4499ec929cf0957c8368fb6bcd437e2685af0d5b71543d2c077bfac05b74307068b06ed96a08bb4fddccf8a0a5cd13d0d38686bf')

    # Test ECDSA signing with RFC6979 nonce function without nonce data
    rfc6979_nonce_function_without_ndata_sig = secp256k1_ecdsa_sign(ctx, msg32, valid_seckey, secp256k1_nonce_function_rfc6979, None)
    assert rfc6979_nonce_function_without_ndata_sig is not None
    rfc6979_nonce_function_without_ndata_output64 = secp256k1_ecdsa_signature_serialize_compact(ctx, rfc6979_nonce_function_without_ndata_sig)
    assert rfc6979_nonce_function_without_ndata_output64 == bytes.fromhex('ea4f8b11c7c24cb1688c7f9c4499ec929cf0957c8368fb6bcd437e2685af0d5b71543d2c077bfac05b74307068b06ed96a08bb4fddccf8a0a5cd13d0d38686bf')

    # Test ECDSA signing with RFC6979 nonce function with nonce data
    ndata = bytes.fromhex('8368fb6bcd437e2685af0d5b71543d2c077bfac05b74307068b06ed96a08bb4f')
    rfc6979_nonce_function_with_ndata_sig = secp256k1_ecdsa_sign(ctx, msg32, valid_seckey, secp256k1_nonce_function_rfc6979, ndata)
    assert rfc6979_nonce_function_with_ndata_sig is not None
    rfc6979_nonce_function_with_ndata_output64 = secp256k1_ecdsa_signature_serialize_compact(ctx, rfc6979_nonce_function_with_ndata_sig)
    assert rfc6979_nonce_function_with_ndata_output64 == bytes.fromhex('31da32d5ee6678fcf340e9f0f84e30ba586fd6c3395da14d66094a1d65ace95d372802b8ca8146ded3360843eaeb69582369eee85760201fb0792efac85e6031')

    # Test invalid ECDSA signing
    invalid_seckey = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
    invalid_sig = secp256k1_ecdsa_sign(ctx, msg32, invalid_seckey, None, None)
    assert invalid_sig is None

    # Test ECDSA signing with invalid types
    with pytest.raises(TypeError):
        secp256k1_ecdsa_sign(None, msg32, valid_seckey, None, None)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_sign('string', msg32, valid_seckey, None, None)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_sign(ctx, None, valid_seckey, None, None)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_sign(ctx, 'string', valid_seckey, None, None)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_sign(ctx, msg32, None, None, None)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_sign(ctx, msg32, 'string', None, None)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_sign(ctx, msg32, valid_seckey, 'string', None)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_sign(ctx, msg32, valid_seckey, None, 'string')

def test_secp256k1_ec_seckey_verify():
    # Test verifying secret key
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    valid_seckey = bytes.fromhex('8c3882fbd7966085e760e000b1ea9eb1ad3df1eec02e720adaa5104c6bd9fd88')
    valid_result = secp256k1_ec_seckey_verify(ctx, valid_seckey)
    assert valid_result is True

    # Test verifying invalid secret key
    invalid_seckey = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
    invalid_result = secp256k1_ec_seckey_verify(ctx, invalid_seckey)
    assert invalid_result is False

    # Test verifying secret key with invalid types
    with pytest.raises(TypeError):
        secp256k1_ec_seckey_verify(None, valid_seckey)
    with pytest.raises(TypeError):
        secp256k1_ec_seckey_verify('string', valid_seckey)
    with pytest.raises(TypeError):
        secp256k1_ec_seckey_verify(ctx, None)
    with pytest.raises(TypeError):
        secp256k1_ec_seckey_verify(ctx, 'string')

def test_secp256k1_ec_pubkey_create():
    # Test creating public key
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    valid_seckey = bytes.fromhex('8c3882fbd7966085e760e000b1ea9eb1ad3df1eec02e720adaa5104c6bd9fd88')
    valid_pubkey = secp256k1_ec_pubkey_create(ctx, valid_seckey)
    assert valid_pubkey is not None
    output = secp256k1_ec_pubkey_serialize(ctx, valid_pubkey, SECP256K1_EC_COMPRESSED)
    assert output == bytes.fromhex('03e7e3dd547cc3171ffdc403824fcc5d5d03712a29f459ca10668c2864c088e951')

    # Test creating invalid public key
    invalid_seckey = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
    invalid_pubkey = secp256k1_ec_pubkey_create(ctx, invalid_seckey)
    assert invalid_pubkey is None

    # Test creating public key with invalid types
    with pytest.raises(TypeError):
        secp256k1_ec_pubkey_create(None, valid_seckey)
    with pytest.raises(TypeError):
        secp256k1_ec_pubkey_create('string', valid_seckey)
    with pytest.raises(TypeError):
        secp256k1_ec_pubkey_create(ctx, None)
    with pytest.raises(TypeError):
        secp256k1_ec_pubkey_create(ctx, 'string')

def test_secp256k1_ec_privkey_negate():
    # Test negating private key
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    seckey = bytes.fromhex('8c3882fbd7966085e760e000b1ea9eb1ad3df1eec02e720adaa5104c6bd9fd88')
    result = secp256k1_ec_privkey_negate(ctx, seckey)
    assert result == bytes.fromhex('73c77d0428699f7a189f1fff4e15614d0d70eaf7ef1a2e30e52d4e40645c43b9')

    # Test negating private key with invalid types
    with pytest.raises(TypeError):
        secp256k1_ec_privkey_negate(None, seckey)
    with pytest.raises(TypeError):
        secp256k1_ec_privkey_negate('string', seckey)
    with pytest.raises(TypeError):
        secp256k1_ec_privkey_negate(ctx, None)
    with pytest.raises(TypeError):
        secp256k1_ec_privkey_negate(ctx, 'string')

def test_secp256k1_ec_pubkey_negate():
    # Test negating public key
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    input = bytes.fromhex('026da3c9181fa2c5b0b5500a4f1f95cc13db7c23b87868c0a7e928e4b981726079')
    pubkey = secp256k1_ec_pubkey_parse(ctx, input)
    assert pubkey is not None
    result = secp256k1_ec_pubkey_negate(ctx, pubkey)
    assert result is not None
    output = secp256k1_ec_pubkey_serialize(ctx, result, SECP256K1_EC_UNCOMPRESSED)
    assert output == bytes.fromhex('046da3c9181fa2c5b0b5500a4f1f95cc13db7c23b87868c0a7e928e4b98172607922f88f6700995389fcaa7274bac608631aac0d4f58e1538df28bb702fd46e07b')

    # Test negating public key with invalid types
    with pytest.raises(TypeError):
        secp256k1_ec_pubkey_negate(None, pubkey)
    with pytest.raises(TypeError):
        secp256k1_ec_pubkey_negate('string', pubkey)
    with pytest.raises(TypeError):
        secp256k1_ec_pubkey_negate(ctx, None)
    with pytest.raises(TypeError):
        secp256k1_ec_pubkey_negate(ctx, 'string')

def test_secp256k1_ec_privkey_tweak_add():
    # Test tweak adding private key
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    seckey = bytes.fromhex('8c3882fbd7966085e760e000b1ea9eb1ad3df1eec02e720adaa5104c6bd9fd88')
    valid_tweak = bytes.fromhex('7f64b1861b9139c0601f637957826da80bb3773adbc8c70265a0c3edb6fda33b')
    valid_result = secp256k1_ec_privkey_tweak_add(ctx, seckey, valid_tweak)
    assert valid_result == bytes.fromhex('0b9d3481f3279a464780437a096d0c5afe428c42ecae98d1807375ad52a15f82')

    # Test invalid tweak adding private key
    invalid_tweak = bytes.fromhex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
    invalid_result = secp256k1_ec_privkey_tweak_add(ctx, seckey, invalid_tweak)
    assert invalid_result is None

    # Test tweak adding private key with invalid types
    with pytest.raises(TypeError):
        secp256k1_ec_privkey_tweak_add(None, seckey, valid_tweak)
    with pytest.raises(TypeError):
        secp256k1_ec_privkey_tweak_add('string', seckey, valid_tweak)
    with pytest.raises(TypeError):
        secp256k1_ec_privkey_tweak_add(ctx, None, valid_tweak)
    with pytest.raises(TypeError):
        secp256k1_ec_privkey_tweak_add(ctx, 'string', valid_tweak)
    with pytest.raises(TypeError):
        secp256k1_ec_privkey_tweak_add(ctx, seckey, None)
    with pytest.raises(TypeError):
        secp256k1_ec_privkey_tweak_add(ctx, seckey, 'string')

def test_secp256k1_ec_pubkey_tweak_add():
    # Test tweak adding public key
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    input = bytes.fromhex('03e7e3dd547cc3171ffdc403824fcc5d5d03712a29f459ca10668c2864c088e951')
    pubkey = secp256k1_ec_pubkey_parse(ctx, input)
    assert pubkey is not None
    valid_tweak = bytes.fromhex('7f64b1861b9139c0601f637957826da80bb3773adbc8c70265a0c3edb6fda33b')
    valid_result = secp256k1_ec_pubkey_tweak_add(ctx, pubkey, valid_tweak)
    assert valid_result is not None
    output = secp256k1_ec_pubkey_serialize(ctx, valid_result, SECP256K1_EC_COMPRESSED)
    assert output == bytes.fromhex('03a04cdf63f8d3667991619a131de99861cfaa54de3c1401a50fd065cbcd468352')

    # Test invalid tweak adding public key
    invalid_tweak = bytes.fromhex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
    invalid_result = secp256k1_ec_pubkey_tweak_add(ctx, pubkey, invalid_tweak)
    assert invalid_result is None

    # Test tweak adding public key with invalid types
    with pytest.raises(TypeError):
        secp256k1_ec_pubkey_tweak_add(None, pubkey, valid_tweak)
    with pytest.raises(TypeError):
        secp256k1_ec_pubkey_tweak_add('string', pubkey, valid_tweak)
    with pytest.raises(TypeError):
        secp256k1_ec_pubkey_tweak_add(ctx, None, valid_tweak)
    with pytest.raises(TypeError):
        secp256k1_ec_pubkey_tweak_add(ctx, 'string', valid_tweak)
    with pytest.raises(TypeError):
        secp256k1_ec_pubkey_tweak_add(ctx, pubkey, None)
    with pytest.raises(TypeError):
        secp256k1_ec_pubkey_tweak_add(ctx, pubkey, 'string')

def test_secp256k1_ec_privkey_tweak_mul():
    # Test tweak multiplying private key
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    seckey = bytes.fromhex('8c3882fbd7966085e760e000b1ea9eb1ad3df1eec02e720adaa5104c6bd9fd88')
    valid_tweak = bytes.fromhex('7f64b1861b9139c0601f637957826da80bb3773adbc8c70265a0c3edb6fda33b')
    valid_result = secp256k1_ec_privkey_tweak_mul(ctx, seckey, valid_tweak)
    assert valid_result == bytes.fromhex('f3b41cadfb1a73adcefabb394f28eb8a8efd618aa6acb99498df9a3eb9447de7')

    # Test invalid tweak multiplying private key
    invalid_tweak = bytes.fromhex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
    invalid_result = secp256k1_ec_privkey_tweak_mul(ctx, seckey, invalid_tweak)
    assert invalid_result is None

    # Test tweak multiplying private key with invalid types
    with pytest.raises(TypeError):
        secp256k1_ec_privkey_tweak_mul(None, seckey, valid_tweak)
    with pytest.raises(TypeError):
        secp256k1_ec_privkey_tweak_mul('string', seckey, valid_tweak)
    with pytest.raises(TypeError):
        secp256k1_ec_privkey_tweak_mul(ctx, None, valid_tweak)
    with pytest.raises(TypeError):
        secp256k1_ec_privkey_tweak_mul(ctx, 'string', valid_tweak)
    with pytest.raises(TypeError):
        secp256k1_ec_privkey_tweak_mul(ctx, seckey, None)
    with pytest.raises(TypeError):
        secp256k1_ec_privkey_tweak_mul(ctx, seckey, 'string')

def test_secp256k1_ec_pubkey_tweak_mul():
    # Test tweak multiplying public key
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    input = bytes.fromhex('03e7e3dd547cc3171ffdc403824fcc5d5d03712a29f459ca10668c2864c088e951')
    pubkey = secp256k1_ec_pubkey_parse(ctx, input)
    assert pubkey is not None
    valid_tweak = bytes.fromhex('7f64b1861b9139c0601f637957826da80bb3773adbc8c70265a0c3edb6fda33b')
    valid_result = secp256k1_ec_pubkey_tweak_mul(ctx, pubkey, valid_tweak)
    assert valid_result is not None
    output = secp256k1_ec_pubkey_serialize(ctx, valid_result, SECP256K1_EC_COMPRESSED)
    assert output == bytes.fromhex('029210ee1fb10b2c0a4519829b11339651ca0986e214e85aa96328b76c169b703a')

    # Test invalid tweak multiplying public key
    invalid_tweak = bytes.fromhex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
    invalid_result = secp256k1_ec_pubkey_tweak_mul(ctx, pubkey, invalid_tweak)
    assert invalid_result is None

    # Test tweak multiplying public key with invalid types
    with pytest.raises(TypeError):
        secp256k1_ec_pubkey_tweak_mul(None, pubkey, valid_tweak)
    with pytest.raises(TypeError):
        secp256k1_ec_pubkey_tweak_mul('string', pubkey, valid_tweak)
    with pytest.raises(TypeError):
        secp256k1_ec_pubkey_tweak_mul(ctx, None, valid_tweak)
    with pytest.raises(TypeError):
        secp256k1_ec_pubkey_tweak_mul(ctx, 'string', valid_tweak)
    with pytest.raises(TypeError):
        secp256k1_ec_pubkey_tweak_mul(ctx, pubkey, None)
    with pytest.raises(TypeError):
        secp256k1_ec_pubkey_tweak_mul(ctx, pubkey, 'string')

def test_secp256k1_context_randomize():
    # Test randomizing context with no seed
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    no_seed_result = secp256k1_context_randomize(ctx, None)
    assert no_seed_result is not None

    # Test randomizing context with seed
    seed32 = bytes.fromhex('7f64b1861b9139c0601f637957826da80bb3773adbc8c70265a0c3edb6fda33b')
    seed_result = secp256k1_context_randomize(ctx, seed32)
    assert seed_result is not None

    # Test randomizing context with invalid types
    with pytest.raises(TypeError):
        secp256k1_context_randomize(None, None)
    with pytest.raises(TypeError):
        secp256k1_context_randomize('string', None)
    with pytest.raises(TypeError):
        secp256k1_context_randomize(ctx, 'string')

def test_secp256k1_ec_pubkey_combine():
    # Test combining public keys
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    ins = [secp256k1_ec_pubkey_parse(ctx, bytes.fromhex('03e7e3dd547cc3171ffdc403824fcc5d5d03712a29f459ca10668c2864c088e951')), secp256k1_ec_pubkey_parse(ctx, bytes.fromhex('033c44db7d8accfb8d89ada18934c4e5daf9902df8638a3e959d8d57aa6ca977cd')), secp256k1_ec_pubkey_parse(ctx, bytes.fromhex('03011d606ad1bd8470d1b6dbf6cb5eae25e42ea1b55915a0899b5a26020c59bd6f'))]
    assert all(pubkey is not None for pubkey in ins)
    out = secp256k1_ec_pubkey_combine(ctx, ins)
    assert out is not None
    output = secp256k1_ec_pubkey_serialize(ctx, out, SECP256K1_EC_COMPRESSED)
    assert output == bytes.fromhex('02fa0b2a4aa3bec764d895f2ac631b7c91ac3696847d08fa1b5ce51aa9df8c1a3e')

    # Test combining public keys with invalid types
    with pytest.raises(TypeError):
        secp256k1_ec_pubkey_combine(None, ins)
    with pytest.raises(TypeError):
        secp256k1_ec_pubkey_combine('string', ins)
    with pytest.raises(TypeError):
        secp256k1_ec_pubkey_combine(ctx, None)
    with pytest.raises(TypeError):
        secp256k1_ec_pubkey_combine(ctx, 'string')
    with pytest.raises(TypeError):
        secp256k1_ec_pubkey_combine(ctx, [1, 2, 3])

def test_secp256k1_ec_privkey_tweak_inv():
    # Test tweak inversing private key
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    valid_seckey = bytes.fromhex('8c3882fbd7966085e760e000b1ea9eb1ad3df1eec02e720adaa5104c6bd9fd88')
    valid_result = secp256k1_ec_privkey_tweak_inv(ctx, valid_seckey)
    assert valid_result == bytes.fromhex('3d1f0b144beb4358b7c78ce8a71b9553a4f212f8b9cebf32617e95d8aac37b29')

    # Test invalid tweak inversing private key
    invalid_seckey = bytes.fromhex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
    invalid_result = secp256k1_ec_privkey_tweak_inv(ctx, invalid_seckey)
    assert invalid_result is None

    # Test tweak inversing private key with invalid types
    with pytest.raises(TypeError):
        secp256k1_ec_privkey_tweak_inv(None, valid_seckey)
    with pytest.raises(TypeError):
        secp256k1_ec_privkey_tweak_inv('string', valid_seckey)
    with pytest.raises(TypeError):
        secp256k1_ec_privkey_tweak_inv(ctx, None)
    with pytest.raises(TypeError):
        secp256k1_ec_privkey_tweak_inv(ctx, 'string')

def test_secp256k1_ec_privkey_tweak_neg():
    # Test tweak negating private key
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    valid_seckey = bytes.fromhex('8c3882fbd7966085e760e000b1ea9eb1ad3df1eec02e720adaa5104c6bd9fd88')
    valid_result = secp256k1_ec_privkey_tweak_neg(ctx, valid_seckey)
    assert valid_result == bytes.fromhex('73c77d0428699f7a189f1fff4e15614d0d70eaf7ef1a2e30e52d4e40645c43b9')

    # Test invalid tweak negating private key
    invalid_seckey = bytes.fromhex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
    invalid_result = secp256k1_ec_privkey_tweak_neg(ctx, invalid_seckey)
    assert invalid_result is None

    # Test tweak negating private key with invalid types
    with pytest.raises(TypeError):
        secp256k1_ec_privkey_tweak_neg(None, valid_seckey)
    with pytest.raises(TypeError):
        secp256k1_ec_privkey_tweak_neg('string', valid_seckey)
    with pytest.raises(TypeError):
        secp256k1_ec_privkey_tweak_neg(ctx, None)
    with pytest.raises(TypeError):
        secp256k1_ec_privkey_tweak_neg(ctx, 'string')

def test_secp256k1_aggsig_context_create():
    # Test creating aggsig context
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    pubkeys = [secp256k1_ec_pubkey_parse(ctx, bytes.fromhex('03e7e3dd547cc3171ffdc403824fcc5d5d03712a29f459ca10668c2864c088e951')), secp256k1_ec_pubkey_parse(ctx, bytes.fromhex('033c44db7d8accfb8d89ada18934c4e5daf9902df8638a3e959d8d57aa6ca977cd')), secp256k1_ec_pubkey_parse(ctx, bytes.fromhex('03011d606ad1bd8470d1b6dbf6cb5eae25e42ea1b55915a0899b5a26020c59bd6f'))]
    assert all(pubkey is not None for pubkey in pubkeys)
    seed = bytes.fromhex('7f64b1861b9139c0601f637957826da80bb3773adbc8c70265a0c3edb6fda33b')
    aggctx = secp256k1_aggsig_context_create(ctx, pubkeys, seed)
    assert aggctx is not None

    # Test creating aggsig context with invalid types
    with pytest.raises(TypeError):
        secp256k1_aggsig_context_create(None, pubkeys, seed)
    with pytest.raises(TypeError):
        secp256k1_aggsig_context_create('string', pubkeys, seed)
    with pytest.raises(TypeError):
        secp256k1_aggsig_context_create(ctx, None, seed)
    with pytest.raises(TypeError):
        secp256k1_aggsig_context_create(ctx, 'string', seed)
    with pytest.raises(TypeError):
        secp256k1_aggsig_context_create(ctx, [1, 2, 3], seed)
    with pytest.raises(TypeError):
        secp256k1_aggsig_context_create(ctx, pubkeys, None)
    with pytest.raises(TypeError):
        secp256k1_aggsig_context_create(ctx, pubkeys, 'string')

def test_secp256k1_aggsig_context_destroy():
    # Test destroying no aggsig context
    secp256k1_aggsig_context_destroy(None)
    assert True

    # Test destroying aggsig context
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    pubkeys = [secp256k1_ec_pubkey_parse(ctx, bytes.fromhex('03e7e3dd547cc3171ffdc403824fcc5d5d03712a29f459ca10668c2864c088e951')), secp256k1_ec_pubkey_parse(ctx, bytes.fromhex('033c44db7d8accfb8d89ada18934c4e5daf9902df8638a3e959d8d57aa6ca977cd')), secp256k1_ec_pubkey_parse(ctx, bytes.fromhex('03011d606ad1bd8470d1b6dbf6cb5eae25e42ea1b55915a0899b5a26020c59bd6f'))]
    assert all(pubkey is not None for pubkey in pubkeys)
    seed = bytes.fromhex('7f64b1861b9139c0601f637957826da80bb3773adbc8c70265a0c3edb6fda33b')
    aggctx = secp256k1_aggsig_context_create(ctx, pubkeys, seed)
    assert aggctx is not None
    secp256k1_aggsig_context_destroy(aggctx)
    assert True

    # Test destroying aggsig context with invalid types
    with pytest.raises(TypeError):
        secp256k1_aggsig_context_destroy('string')

def test_secp256k1_aggsig_generate_nonce():
    # Test generating aggsig nonce
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    pubkeys = [secp256k1_ec_pubkey_parse(ctx, bytes.fromhex('03e7e3dd547cc3171ffdc403824fcc5d5d03712a29f459ca10668c2864c088e951')), secp256k1_ec_pubkey_parse(ctx, bytes.fromhex('033c44db7d8accfb8d89ada18934c4e5daf9902df8638a3e959d8d57aa6ca977cd')), secp256k1_ec_pubkey_parse(ctx, bytes.fromhex('03011d606ad1bd8470d1b6dbf6cb5eae25e42ea1b55915a0899b5a26020c59bd6f'))]
    assert all(pubkey is not None for pubkey in pubkeys)
    seed = bytes.fromhex('7f64b1861b9139c0601f637957826da80bb3773adbc8c70265a0c3edb6fda33b')
    aggctx = secp256k1_aggsig_context_create(ctx, pubkeys, seed)
    assert secp256k1_aggsig_generate_nonce(ctx, aggctx, 0) is True
    assert secp256k1_aggsig_generate_nonce(ctx, aggctx, 1) is True
    assert secp256k1_aggsig_generate_nonce(ctx, aggctx, 2) is True

    # Test generating aggsig nonce with invalid types
    with pytest.raises(TypeError):
        secp256k1_aggsig_generate_nonce(None, aggctx, 0)
    with pytest.raises(TypeError):
        secp256k1_aggsig_generate_nonce('string', aggctx, 0)
    with pytest.raises(TypeError):
        secp256k1_aggsig_generate_nonce(ctx, None, 0)
    with pytest.raises(TypeError):
        secp256k1_aggsig_generate_nonce(ctx, 'string', 0)
    with pytest.raises(TypeError):
        secp256k1_aggsig_generate_nonce(ctx, aggctx, None)
    with pytest.raises(TypeError):
        secp256k1_aggsig_generate_nonce(ctx, aggctx, 'string')

    # Test generating aggsig nonce with invalid values
    with pytest.raises(OverflowError):
        secp256k1_aggsig_generate_nonce(ctx, aggctx, -1)
    with pytest.raises(OverflowError):
        secp256k1_aggsig_generate_nonce(ctx, aggctx, 0x10000000000000000)

def test_secp256k1_aggsig_export_secnonce_single():
    # Test exporting aggsig secnonce single
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    seed = bytes.fromhex('7f64b1861b9139c0601f637957826da80bb3773adbc8c70265a0c3edb6fda33b')
    secnonce32 = secp256k1_aggsig_export_secnonce_single(ctx, seed)
    assert secnonce32 == bytes.fromhex('6c86b63b15001b15eafdd86accf60d3488c0b554f165ff231d7ad33f98b809f4')

   # Test exporting aggsig secnonce single with invalid types
    with pytest.raises(TypeError):
        secp256k1_aggsig_export_secnonce_single(None, seed)
    with pytest.raises(TypeError):
        secp256k1_aggsig_export_secnonce_single('string', seed)
    with pytest.raises(TypeError):
        secp256k1_aggsig_export_secnonce_single(ctx, None)
    with pytest.raises(TypeError):
        secp256k1_aggsig_export_secnonce_single(ctx, 'string')

def test_secp256k1_aggsig_sign_single():
    # Test signing aggsig single without optional
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    msg32 = bytes.fromhex('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    valid_seckey32 = bytes.fromhex('8c3882fbd7966085e760e000b1ea9eb1ad3df1eec02e720adaa5104c6bd9fd88')
    seed = bytes.fromhex('7f64b1861b9139c0601f637957826da80bb3773adbc8c70265a0c3edb6fda33b')
    sig64_without_optional = secp256k1_aggsig_sign_single(ctx, msg32, valid_seckey32, None, None, None, None, None, seed)
    assert sig64_without_optional is not None
    output64_without_optional = secp256k1_ecdsa_signature_serialize_compact(ctx, sig64_without_optional)
    assert output64_without_optional == bytes.fromhex('7cd7098a3e97ff1ee539e58c5d0dbabdc5bb7c770977d9ce0f61964390ccc3d80777b1af982f31b8ecb5814e16ab59bcf5592e7fb81f9a9e775bfdb1ea65cba5')

    # Test signing aggsig single with secnonce
    secnonce32 = bytes.fromhex('f61964390ccc3d80777b1af982f31b8ecb5814e16ab59bcf5592e7fb81f9a9e7')
    sig64_with_secnonce = secp256k1_aggsig_sign_single(ctx, msg32, valid_seckey32, secnonce32, None, None, None, None, seed)
    assert sig64_with_secnonce is not None
    output64_with_secnonce = secp256k1_ecdsa_signature_serialize_compact(ctx, sig64_with_secnonce)
    assert output64_with_secnonce == bytes.fromhex('611c7e42d845d9b97a6862db565dc07501b23352e0f2e2e2e1ed172a74d22184d1e1a5e4a0298d4ed11d1669d828427822ce92602f09d3d472470be1ceac8574')

    # Test signing aggsig single with extra
    extra32 = bytes.fromhex('80777b1af982f31b8ecb5814e16ab59bcf5592e7fb81f9a9e7f61964390ccc3d')
    sig64_with_extra = secp256k1_aggsig_sign_single(ctx, msg32, valid_seckey32, None, extra32, None, None, None, seed)
    assert sig64_with_extra is not None
    output64_with_extra = secp256k1_ecdsa_signature_serialize_compact(ctx, sig64_with_extra)
    assert output64_with_extra == bytes.fromhex('7cd7098a3e97ff1ee539e58c5d0dbabdc5bb7c770977d9ce0f61964390ccc3d80302881870ea54e05a0fbb9a176100d1920f9960cd77652d934e80ab05e14226')

    # Test signing aggsig single with pubnonce for e
    pubnonce_for_e = secp256k1_ec_pubkey_parse(ctx, bytes.fromhex('03e7e3dd547cc3171ffdc403824fcc5d5d03712a29f459ca10668c2864c088e951'))
    assert pubnonce_for_e is not None
    sig64_with_pubnonce_for_e = secp256k1_aggsig_sign_single(ctx, msg32, valid_seckey32, None, None, pubnonce_for_e, None, None, seed)
    assert sig64_with_pubnonce_for_e is not None
    output64_with_pubnonce_for_e = secp256k1_ecdsa_signature_serialize_compact(ctx, sig64_with_pubnonce_for_e)
    assert output64_with_pubnonce_for_e == bytes.fromhex('7cd7098a3e97ff1ee539e58c5d0dbabdc5bb7c770977d9ce0f61964390ccc3d838fc3450e6e2fce026d62245982915a4e23c2609e21e010c6a278432ca3847a6')

    # Test signing aggsig single with pubnonce total
    pubnonce_total = secp256k1_ec_pubkey_parse(ctx, bytes.fromhex('033c44db7d8accfb8d89ada18934c4e5daf9902df8638a3e959d8d57aa6ca977cd'))
    assert pubnonce_total is not None
    sig64_with_pubnonce_total = secp256k1_aggsig_sign_single(ctx, msg32, valid_seckey32, None, None, None, pubnonce_total, None, seed)
    assert sig64_with_pubnonce_total is not None
    output64_with_pubnonce_total = secp256k1_ecdsa_signature_serialize_compact(ctx, sig64_with_pubnonce_total)
    assert output64_with_pubnonce_total == bytes.fromhex('7cd7098a3e97ff1ee539e58c5d0dbabdc5bb7c770977d9ce0f61964390ccc3d80777b1af982f31b8ecb5814e16ab59bcf5592e7fb81f9a9e775bfdb1ea65cba5')

    # Test signing aggsig single with pubkey for e
    pubkey_for_e = secp256k1_ec_pubkey_parse(ctx, bytes.fromhex('03011d606ad1bd8470d1b6dbf6cb5eae25e42ea1b55915a0899b5a26020c59bd6f'))
    assert pubkey_for_e is not None
    sig64_with_pubkey_for_e = secp256k1_aggsig_sign_single(ctx, msg32, valid_seckey32, None, None, None, None, pubkey_for_e, seed)
    assert sig64_with_pubkey_for_e is not None
    output64_with_pubkey_for_e = secp256k1_ecdsa_signature_serialize_compact(ctx, sig64_with_pubkey_for_e)
    assert output64_with_pubkey_for_e == bytes.fromhex('7cd7098a3e97ff1ee539e58c5d0dbabdc5bb7c770977d9ce0f61964390ccc3d8dd4222670b80413a4810fed91d0cb6c2df5968a35a5bdd859cf009db85f54915')

    # Test signing aggsig single with all
    sig64_with_all = secp256k1_aggsig_sign_single(ctx, msg32, valid_seckey32, secnonce32, extra32, pubnonce_for_e, pubnonce_total, pubkey_for_e, seed)
    assert sig64_with_all is not None
    output64_with_all = secp256k1_ecdsa_signature_serialize_compact(ctx, sig64_with_all)
    assert output64_with_all == bytes.fromhex('611c7e42d845d9b97a6862db565dc07501b23352e0f2e2e2e1ed172a74d2218445a863ba64c0a97d152c4d5cd131776655bea993215498a28bc58a80b9eb838a')

    # Test signing invalid aggsig single
    invalid_seckey32 = bytes.fromhex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
    invalid_sig64 = secp256k1_aggsig_sign_single(ctx, msg32, invalid_seckey32, None, None, None, None, None, seed)
    assert invalid_sig64 is None

    # Test signing aggsig single with invalid types
    with pytest.raises(TypeError):
        secp256k1_aggsig_sign_single(None, msg32, valid_seckey32, None, None, None, None, None, seed)
    with pytest.raises(TypeError):
        secp256k1_aggsig_sign_single('string', msg32, valid_seckey32, None, None, None, None, None, seed)
    with pytest.raises(TypeError):
        secp256k1_aggsig_sign_single(ctx, None, valid_seckey32, None, None, None, None, None, seed)
    with pytest.raises(TypeError):
        secp256k1_aggsig_sign_single(ctx, 'string', valid_seckey32, None, None, None, None, None, seed)
    with pytest.raises(TypeError):
        secp256k1_aggsig_sign_single(ctx, msg32, None, None, None, None, None, None, seed)
    with pytest.raises(TypeError):
        secp256k1_aggsig_sign_single(ctx, msg32, 'string', None, None, None, None, None, seed)
    with pytest.raises(TypeError):
        secp256k1_aggsig_sign_single(ctx, msg32, valid_seckey32, 'string', None, None, None, None, seed)
    with pytest.raises(TypeError):
        secp256k1_aggsig_sign_single(ctx, msg32, valid_seckey32, None, 'string', None, None, None, seed)
    with pytest.raises(TypeError):
        secp256k1_aggsig_sign_single(ctx, msg32, valid_seckey32, None, None, 'string', None, None, seed)
    with pytest.raises(TypeError):
        secp256k1_aggsig_sign_single(ctx, msg32, valid_seckey32, None, None, None, 'string', None, seed)
    with pytest.raises(TypeError):
        secp256k1_aggsig_sign_single(ctx, msg32, valid_seckey32, None, None, None, None, 'string', seed)
    with pytest.raises(TypeError):
        secp256k1_aggsig_sign_single(ctx, msg32, valid_seckey32, None, None, None, None, None, None)
    with pytest.raises(TypeError):
        secp256k1_aggsig_sign_single(ctx, msg32, valid_seckey32, None, None, None, None, None, 'string')

def test_secp256k1_aggsig_partial_sign():
    # Test partial signing aggsig
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    pubkeys = [secp256k1_ec_pubkey_parse(ctx, bytes.fromhex('03e7e3dd547cc3171ffdc403824fcc5d5d03712a29f459ca10668c2864c088e951')), secp256k1_ec_pubkey_parse(ctx, bytes.fromhex('033c44db7d8accfb8d89ada18934c4e5daf9902df8638a3e959d8d57aa6ca977cd')), secp256k1_ec_pubkey_parse(ctx, bytes.fromhex('03011d606ad1bd8470d1b6dbf6cb5eae25e42ea1b55915a0899b5a26020c59bd6f'))]
    assert all(pubkey is not None for pubkey in pubkeys)
    seed = bytes.fromhex('7f64b1861b9139c0601f637957826da80bb3773adbc8c70265a0c3edb6fda33b')
    aggctx = secp256k1_aggsig_context_create(ctx, pubkeys, seed)
    assert secp256k1_aggsig_generate_nonce(ctx, aggctx, 0) is True
    assert secp256k1_aggsig_generate_nonce(ctx, aggctx, 1) is True
    assert secp256k1_aggsig_generate_nonce(ctx, aggctx, 2) is True
    msg32 = bytes.fromhex('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    valid_seckey32 = bytes.fromhex('8c3882fbd7966085e760e000b1ea9eb1ad3df1eec02e720adaa5104c6bd9fd88')
    valid_partial = secp256k1_aggsig_partial_sign(ctx, aggctx, msg32, valid_seckey32, 0)
    assert valid_partial is not None

    # Test partial signing invalid aggsig
    invalid_seckey32 = bytes.fromhex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
    invalid_partial = secp256k1_aggsig_partial_sign(ctx, aggctx, msg32, invalid_seckey32, 0)
    assert invalid_partial is None

    # Test partial signing aggsig with invalid types
    with pytest.raises(TypeError):
        secp256k1_aggsig_partial_sign(None, aggctx, msg32, valid_seckey32, 0)
    with pytest.raises(TypeError):
        secp256k1_aggsig_partial_sign('string', aggctx, msg32, valid_seckey32, 0)
    with pytest.raises(TypeError):
        secp256k1_aggsig_partial_sign(ctx, None, msg32, valid_seckey32, 0)
    with pytest.raises(TypeError):
        secp256k1_aggsig_partial_sign(ctx, 'string', msg32, valid_seckey32, 0)
    with pytest.raises(TypeError):
        secp256k1_aggsig_partial_sign(ctx, aggctx, None, valid_seckey32, 0)
    with pytest.raises(TypeError):
        secp256k1_aggsig_partial_sign(ctx, aggctx, 'string', valid_seckey32, 0)
    with pytest.raises(TypeError):
        secp256k1_aggsig_partial_sign(ctx, aggctx, msg32, None, 0)
    with pytest.raises(TypeError):
        secp256k1_aggsig_partial_sign(ctx, aggctx, msg32, 'string', 0)
    with pytest.raises(TypeError):
        secp256k1_aggsig_partial_sign(ctx, aggctx, msg32, valid_seckey32, None)
    with pytest.raises(TypeError):
        secp256k1_aggsig_partial_sign(ctx, aggctx, msg32, valid_seckey32, 'string')

    # Test partial signing aggsig with invalid values
    with pytest.raises(OverflowError):
        secp256k1_aggsig_partial_sign(ctx, aggctx, msg32, valid_seckey32, -1)
    with pytest.raises(OverflowError):
        secp256k1_aggsig_partial_sign(ctx, aggctx, msg32, valid_seckey32, 0x10000000000000000)

def test_secp256k1_aggsig_combine_signatures():
    # Test combining aggsig signatures
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    pubkeys = [secp256k1_ec_pubkey_parse(ctx, bytes.fromhex('03e7e3dd547cc3171ffdc403824fcc5d5d03712a29f459ca10668c2864c088e951')), secp256k1_ec_pubkey_parse(ctx, bytes.fromhex('02c8ffe90871ca63fe168e24c69b1cf2d7cd2dba14a47b3478471144c14e8ee54b'))]
    assert all(pubkey is not None for pubkey in pubkeys)
    seed = bytes.fromhex('7f64b1861b9139c0601f637957826da80bb3773adbc8c70265a0c3edb6fda33b')
    aggctx = secp256k1_aggsig_context_create(ctx, pubkeys, seed)
    assert secp256k1_aggsig_generate_nonce(ctx, aggctx, 0) is True
    assert secp256k1_aggsig_generate_nonce(ctx, aggctx, 1) is True
    msg32 = bytes.fromhex('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    first_seckey32 = bytes.fromhex('8c3882fbd7966085e760e000b1ea9eb1ad3df1eec02e720adaa5104c6bd9fd88')
    first_partial = secp256k1_aggsig_partial_sign(ctx, aggctx, msg32, first_seckey32, 0)
    assert first_partial is not None
    second_seckey32 = bytes.fromhex('0257005b1e1effd53fbec41fb9285f46c71a5c3f61ebaacb3d7f8983ddbd5284')
    second_partial = secp256k1_aggsig_partial_sign(ctx, aggctx, msg32, second_seckey32, 1)
    assert second_partial is not None
    valid_sig64 = secp256k1_aggsig_combine_signatures(ctx, aggctx, [first_partial, second_partial])
    assert valid_sig64 is not None
    sig = secp256k1_ecdsa_signature_serialize_compact(ctx, valid_sig64)
    assert sig == bytes.fromhex('2b71faea55afa7ab586fddabb9132f8a8ae34d0e037f308bf73bd9811be8c67659e2dcda7fdcd678ec450670be4e21fafae07f19e666429f9f555cfa16d9d248')

    # Test combining aggsig invalid signatures
    invalid_sig64 = secp256k1_aggsig_combine_signatures(ctx, aggctx, [])
    assert invalid_sig64 is None

    # Test combining aggsig signatures with invalid types
    with pytest.raises(TypeError):
        secp256k1_aggsig_combine_signatures(None, aggctx, [first_partial, second_partial])
    with pytest.raises(TypeError):
        secp256k1_aggsig_combine_signatures('string', aggctx, [first_partial, second_partial])
    with pytest.raises(TypeError):
        secp256k1_aggsig_combine_signatures(ctx, None, [first_partial, second_partial])
    with pytest.raises(TypeError):
        secp256k1_aggsig_combine_signatures(ctx, 'string', [first_partial, second_partial])
    with pytest.raises(TypeError):
        secp256k1_aggsig_combine_signatures(ctx, aggctx, None)
    with pytest.raises(TypeError):
        secp256k1_aggsig_combine_signatures(ctx, aggctx, 'string')
    with pytest.raises(TypeError):
        secp256k1_aggsig_combine_signatures(ctx, aggctx, [1, 2, 3])

def test_secp256k1_aggsig_add_signatures_single():
    # Test adding aggsig single signatures
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    sigs = [secp256k1_ecdsa_signature_parse_compact(ctx, bytes.fromhex('611c7e42d845d9b97a6862db565dc07501b23352e0f2e2e2e1ed172a74d2218445a863ba64c0a97d152c4d5cd131776655bea993215498a28bc58a80b9eb838a')), secp256k1_ecdsa_signature_parse_compact(ctx, bytes.fromhex('7cd7098a3e97ff1ee539e58c5d0dbabdc5bb7c770977d9ce0f61964390ccc3d80777b1af982f31b8ecb5814e16ab59bcf5592e7fb81f9a9e775bfdb1ea65cba5'))]
    assert all(sig is not None for sig in sigs)
    pubnonce_total = secp256k1_ec_pubkey_parse(ctx, bytes.fromhex('033c44db7d8accfb8d89ada18934c4e5daf9902df8638a3e959d8d57aa6ca977cd'))
    assert pubnonce_total is not None
    sig64 = secp256k1_aggsig_add_signatures_single(ctx, sigs, pubnonce_total)
    assert sig64 is not None
    sig = secp256k1_ecdsa_signature_serialize_compact(ctx, sig64)
    assert sig == bytes.fromhex('cd77a96caa578d9d953e8a63f82d90f9dae5c43489a1ad898dfbcc8a7ddb443c0bdede9970910876c64186fb000022684c18d812da73324103218832a4514f30')

    # Test adding aggsig single signatures with invalid types
    with pytest.raises(TypeError):
        secp256k1_aggsig_add_signatures_single(None, sigs, pubnonce_total)
    with pytest.raises(TypeError):
        secp256k1_aggsig_add_signatures_single('string', sigs, pubnonce_total)
    with pytest.raises(TypeError):
        secp256k1_aggsig_add_signatures_single(ctx, None, pubnonce_total)
    with pytest.raises(TypeError):
        secp256k1_aggsig_add_signatures_single(ctx, 'string', pubnonce_total)
    with pytest.raises(TypeError):
        secp256k1_aggsig_add_signatures_single(ctx, [1, 2, 3], pubnonce_total)
    with pytest.raises(TypeError):
        secp256k1_aggsig_add_signatures_single(ctx, sigs, None)
    with pytest.raises(TypeError):
        secp256k1_aggsig_add_signatures_single(ctx, sigs, 'string')

def test_secp256k1_aggsig_verify_single():
    # Test verifying aggsig single signature without optional
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    sig64_without_optional = secp256k1_ecdsa_signature_parse_compact(ctx, bytes.fromhex('7cd7098a3e97ff1ee539e58c5d0dbabdc5bb7c770977d9ce0f61964390ccc3d80777b1af982f31b8ecb5814e16ab59bcf5592e7fb81f9a9e775bfdb1ea65cba5'))
    assert sig64_without_optional is not None
    valid_msg32 = bytes.fromhex('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    pubkey = secp256k1_ec_pubkey_parse(ctx, bytes.fromhex('03e7e3dd547cc3171ffdc403824fcc5d5d03712a29f459ca10668c2864c088e951'))
    assert pubkey is not None
    result_without_optional = secp256k1_aggsig_verify_single(ctx, sig64_without_optional, valid_msg32, None, pubkey, None, None, False)
    assert result_without_optional is True

    # Test verifying aggsig single signature with pubnonce
    sig64_with_pubnonce = secp256k1_ecdsa_signature_parse_compact(ctx, bytes.fromhex('7cd7098a3e97ff1ee539e58c5d0dbabdc5bb7c770977d9ce0f61964390ccc3d838fc3450e6e2fce026d62245982915a4e23c2609e21e010c6a278432ca3847a6'))
    assert sig64_with_pubnonce is not None
    pubnonce = secp256k1_ec_pubkey_parse(ctx, bytes.fromhex('03e7e3dd547cc3171ffdc403824fcc5d5d03712a29f459ca10668c2864c088e951'))
    assert pubnonce is not None
    result_with_pubnonce = secp256k1_aggsig_verify_single(ctx, sig64_with_pubnonce, valid_msg32, pubnonce, pubkey, None, None, False)
    assert result_with_pubnonce is True

    # Test verifying aggsig single signature with pubkey total
    sig64_with_pubkey_total = secp256k1_ecdsa_signature_parse_compact(ctx, bytes.fromhex('7cd7098a3e97ff1ee539e58c5d0dbabdc5bb7c770977d9ce0f61964390ccc3d8dd4222670b80413a4810fed91d0cb6c2df5968a35a5bdd859cf009db85f54915'))
    assert sig64_with_pubkey_total is not None
    pubkey_total = secp256k1_ec_pubkey_parse(ctx, bytes.fromhex('03011d606ad1bd8470d1b6dbf6cb5eae25e42ea1b55915a0899b5a26020c59bd6f'))
    assert pubkey_total is not None
    result_with_pubkey_total = secp256k1_aggsig_verify_single(ctx, sig64_with_pubkey_total, valid_msg32, None, pubkey, pubkey_total, None, False)
    assert result_with_pubnonce is True

    # Test verifying aggsig single signature with all
    sig64_with_all = secp256k1_ecdsa_signature_parse_compact(ctx, bytes.fromhex('611c7e42d845d9b97a6862db565dc07501b23352e0f2e2e2e1ed172a74d2218445a863ba64c0a97d152c4d5cd131776655bea993215498a28bc58a80b9eb838a'))
    assert sig64_with_all is not None
    result_with_all = secp256k1_aggsig_verify_single(ctx, sig64_with_all, valid_msg32, pubnonce, pubkey, pubkey_total, None, False)
    assert result_with_pubnonce is True

    # Test verifying aggsig invalid single signature
    invalid_msg32 = bytes.fromhex('f3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    invalid_result = secp256k1_aggsig_verify_single(ctx, sig64_without_optional, invalid_msg32, None, pubkey, None, None, False)
    assert invalid_result is False

    # Test verifying aggsig single signature with invalid types
    with pytest.raises(TypeError):
        secp256k1_aggsig_verify_single(None, sig64_without_optional, valid_msg32, None, pubkey, None, None, False)
    with pytest.raises(TypeError):
        secp256k1_aggsig_verify_single('string', sig64_without_optional, valid_msg32, None, pubkey, None, None, False)
    with pytest.raises(TypeError):
        secp256k1_aggsig_verify_single(ctx, None, valid_msg32, None, pubkey, None, None, False)
    with pytest.raises(TypeError):
        secp256k1_aggsig_verify_single(ctx, 'string', valid_msg32, None, pubkey, None, None, False)
    with pytest.raises(TypeError):
        secp256k1_aggsig_verify_single(ctx, sig64_without_optional, None, None, pubkey, None, None, False)
    with pytest.raises(TypeError):
        secp256k1_aggsig_verify_single(ctx, sig64_without_optional, 'string', None, pubkey, None, None, False)
    with pytest.raises(TypeError):
        secp256k1_aggsig_verify_single(ctx, sig64_without_optional, valid_msg32, 'string', pubkey, None, None, False)
    with pytest.raises(TypeError):
        secp256k1_aggsig_verify_single(ctx, sig64_without_optional, valid_msg32, None, None, None, None, False)
    with pytest.raises(TypeError):
        secp256k1_aggsig_verify_single(ctx, sig64_without_optional, valid_msg32, None, 'string', None, None, False)
    with pytest.raises(TypeError):
        secp256k1_aggsig_verify_single(ctx, sig64_without_optional, valid_msg32, None, pubkey, 'string', None, False)
    with pytest.raises(TypeError):
        secp256k1_aggsig_verify_single(ctx, sig64_without_optional, valid_msg32, None, pubkey, None, 'string', False)
    with pytest.raises(TypeError):
        secp256k1_aggsig_verify_single(ctx, sig64_without_optional, valid_msg32, None, pubkey, None, None, None)
    with pytest.raises(TypeError):
        secp256k1_aggsig_verify_single(ctx, sig64_without_optional, valid_msg32, None, pubkey, None, None, 'string')

def test_secp256k1_aggsig_verify():
    # Test verifying aggsig signature
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    scratch = secp256k1_scratch_space_create(ctx, 30720)
    assert scratch is not None
    sig64 = secp256k1_ecdsa_signature_parse_compact(ctx, bytes.fromhex('2b71faea55afa7ab586fddabb9132f8a8ae34d0e037f308bf73bd9811be8c67659e2dcda7fdcd678ec450670be4e21fafae07f19e666429f9f555cfa16d9d248'))
    assert sig64 is not None
    valid_msg32 = bytes.fromhex('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    pubkeys = [secp256k1_ec_pubkey_parse(ctx, bytes.fromhex('03e7e3dd547cc3171ffdc403824fcc5d5d03712a29f459ca10668c2864c088e951')), secp256k1_ec_pubkey_parse(ctx, bytes.fromhex('02c8ffe90871ca63fe168e24c69b1cf2d7cd2dba14a47b3478471144c14e8ee54b'))]
    assert all(pubkey is not None for pubkey in pubkeys)
    valid_result = secp256k1_aggsig_verify(ctx, scratch, sig64, valid_msg32, pubkeys)
    assert valid_result is True

    # Test verifying invalid aggsig signature
    invalid_msg32 = bytes.fromhex('f3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    invalid_result = secp256k1_aggsig_verify(ctx, scratch, sig64, invalid_msg32, pubkeys)
    assert invalid_result is False

    # Test verifying aggsig signature with invalid types
    with pytest.raises(TypeError):
        secp256k1_aggsig_verify(None, scratch, sig64, valid_msg32, pubkeys)
    with pytest.raises(TypeError):
        secp256k1_aggsig_verify('string', scratch, sig64, valid_msg32, pubkeys)
    with pytest.raises(TypeError):
        secp256k1_aggsig_verify(ctx, None, sig64, valid_msg32, pubkeys)
    with pytest.raises(TypeError):
        secp256k1_aggsig_verify(ctx, 'string', sig64, valid_msg32, pubkeys)
    with pytest.raises(TypeError):
        secp256k1_aggsig_verify(ctx, scratch, None, valid_msg32, pubkeys)
    with pytest.raises(TypeError):
        secp256k1_aggsig_verify(ctx, scratch, 'string', valid_msg32, pubkeys)
    with pytest.raises(TypeError):
        secp256k1_aggsig_verify(ctx, scratch, sig64, None, pubkeys)
    with pytest.raises(TypeError):
        secp256k1_aggsig_verify(ctx, scratch, sig64, 'string', pubkeys)
    with pytest.raises(TypeError):
        secp256k1_aggsig_verify(ctx, scratch, sig64, valid_msg32, None)
    with pytest.raises(TypeError):
        secp256k1_aggsig_verify(ctx, scratch, sig64, valid_msg32, 'string')
    with pytest.raises(TypeError):
        secp256k1_aggsig_verify(ctx, scratch, sig64, valid_msg32, [1, 2, 3])

def test_secp256k1_aggsig_build_scratch_and_verify():
    # Test building scratch and verifying aggsig signature
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    sig64 = secp256k1_ecdsa_signature_parse_compact(ctx, bytes.fromhex('2b71faea55afa7ab586fddabb9132f8a8ae34d0e037f308bf73bd9811be8c67659e2dcda7fdcd678ec450670be4e21fafae07f19e666429f9f555cfa16d9d248'))
    assert sig64 is not None
    valid_msg32 = bytes.fromhex('e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    pubkeys = [secp256k1_ec_pubkey_parse(ctx, bytes.fromhex('03e7e3dd547cc3171ffdc403824fcc5d5d03712a29f459ca10668c2864c088e951')), secp256k1_ec_pubkey_parse(ctx, bytes.fromhex('02c8ffe90871ca63fe168e24c69b1cf2d7cd2dba14a47b3478471144c14e8ee54b'))]
    assert all(pubkey is not None for pubkey in pubkeys)
    valid_result = secp256k1_aggsig_build_scratch_and_verify(ctx, sig64, valid_msg32, pubkeys)
    assert valid_result is True

    # Test building scratch and verifying invalid aggsig signature
    invalid_msg32 = bytes.fromhex('f3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855')
    invalid_result = secp256k1_aggsig_build_scratch_and_verify(ctx, sig64, invalid_msg32, pubkeys)
    assert invalid_result is False

    # Test building scratch and verifying aggsig signature with invalid types
    with pytest.raises(TypeError):
        secp256k1_aggsig_build_scratch_and_verify(None, sig64, valid_msg32, pubkeys)
    with pytest.raises(TypeError):
        secp256k1_aggsig_build_scratch_and_verify('string', sig64, valid_msg32, pubkeys)
    with pytest.raises(TypeError):
        secp256k1_aggsig_build_scratch_and_verify(ctx, None, valid_msg32, pubkeys)
    with pytest.raises(TypeError):
        secp256k1_aggsig_build_scratch_and_verify(ctx, 'string', valid_msg32, pubkeys)
    with pytest.raises(TypeError):
        secp256k1_aggsig_build_scratch_and_verify(ctx, sig64, None, pubkeys)
    with pytest.raises(TypeError):
        secp256k1_aggsig_build_scratch_and_verify(ctx, sig64, 'string', pubkeys)
    with pytest.raises(TypeError):
        secp256k1_aggsig_build_scratch_and_verify(ctx, sig64, valid_msg32, None)
    with pytest.raises(TypeError):
        secp256k1_aggsig_build_scratch_and_verify(ctx, sig64, valid_msg32, 'string')
    with pytest.raises(TypeError):
        secp256k1_aggsig_build_scratch_and_verify(ctx, sig64, valid_msg32, [1, 2, 3])

def test_secp256k1_bulletproof_generators_create():
    # Test creating Bulletproof generators
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    gen = secp256k1_bulletproof_generators_create(ctx, secp256k1_generator_const_g, 256)
    assert gen is not None

    # Test creating Bulletproof generators with invalid types
    with pytest.raises(TypeError):
        secp256k1_bulletproof_generators_create(None, secp256k1_generator_const_g, 256)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_generators_create('string', secp256k1_generator_const_g, 256)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_generators_create(ctx, None, 256)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_generators_create(ctx, 'string', 256)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_generators_create(ctx, secp256k1_generator_const_g, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_generators_create(ctx, secp256k1_generator_const_g, 'string')

    # Test creating Bulletproof generators with invalid values
    with pytest.raises(OverflowError):
        secp256k1_bulletproof_generators_create(ctx, secp256k1_generator_const_g, -1)
    with pytest.raises(OverflowError):
        secp256k1_bulletproof_generators_create(ctx, secp256k1_generator_const_g, 0x10000000000000000)

def test_secp256k1_bulletproof_generators_destroy():
    # Test destroying no Bulletproof generator
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    secp256k1_bulletproof_generators_destroy(ctx, None)
    assert True

    # Test destroying Bulletproof generator
    gen = secp256k1_bulletproof_generators_create(ctx, secp256k1_generator_const_g, 256)
    assert gen is not None
    secp256k1_bulletproof_generators_destroy(ctx, gen)

    # Test destroying Bulletproof generator with invalid types
    with pytest.raises(TypeError):
        secp256k1_bulletproof_generators_destroy(None, gen)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_generators_destroy('string', gen)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_generators_destroy(ctx, 'string')

def test_secp256k1_bulletproof_rangeproof_verify():
    # Test verifying Bulletproof without optional
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    scratch = secp256k1_scratch_space_create(ctx, 30720)
    assert scratch is not None
    gens = secp256k1_bulletproof_generators_create(ctx, secp256k1_generator_const_g, 256)
    assert gens is not None
    value = [123456789]
    blind = [bytes.fromhex('59e721189cf77b5fcd6c7247ef8b997f66379e85218c2115f25d8cdbb50faa1a')]
    proof_without_optional = bytes.fromhex('06c8d2140622ecdccad4a2810d4ec58939852e41606b456cf0fb34933e330dbe41890912a82a2d2bce57526df7988be80090a93f17ed093392d3c660aabae6880f5a35bd7843cd92b90b235eee1c886e6b294e4bfb84d1e932f464e693a0e74fdcb38908f46cfb166a26ce8ef64bc82b04b8906b43c8ee545f7f488c641997abb1b05d571bd913884b44d1954e42bfed4c743d93efb9e5c11e7f8983bf5e74f80070230676af6ef835023c9b42074d0404c69471d14b1b70e881e57d0c7edc5bad81904085700a11966c2017920dc4b0e443c0eec2c70ca5c9f2440457e36ed4bc77d9a0a995cc4d2503f8dded0db4031a8dcba32f5532598084b445aa081bd77c6a92cb77bb4b9fa72da67cce6ef2c95cc8a6cead1b1ae211d81964085f957f3d06f6a90a6a87f71ccc2cfabf2e5af741c24abf5cec063883909c3394d6967b419bf8f80132cf636c3c9b5afec6351dd18b85f556cbe560fd7ca4c359202948dc3902fa6abf8a55a65ce7cf28b91b2f107daf1fe37b9e9195fdf56fd7ba4c146fe9f4cf538b4666e47f594f81567ce4fdf2842b71be8618af11e6881e328c52a7fa3d874a138ee62ac2bfc23a6e82e6982901751277843f0f03bb40e99eb02b0a87d3768409603cd2fa24255d2765a27774cce3bffd2a0f76e903bfae9ff0de19ecd0e6d92b590f1ff7c648a2c0685834af56d23b45465fc893728326c524c2c50abbbb1b506159a7a7098061ccf3972d5df786538589f5921a1922c44ac329734bfa3821e39ecc93f7f1a9cb8a0f9fb5165df024e001ebb9107b04f5889799fe0ecf6fe2190c70b524a6f843a280992148031349aef170a684bf2c8ca424e68d9a99a96af130de9ce97285490358d75e188e6a0f53af4651626bbab059825f8812b669a44604eaa8d7dc8b3d646b2eb7601c7e1e4fb62b0b83490d78ed4d30255c2d')
    commit = [secp256k1_pedersen_commit(ctx, blind[0], value[0], secp256k1_generator_const_h, secp256k1_generator_const_g)]
    assert all(commitment is not None for commitment in commit)
    result_without_optional = secp256k1_bulletproof_rangeproof_verify(ctx, scratch, gens, proof_without_optional, None, commit, 64, secp256k1_generator_const_h, None)
    assert result_without_optional is True

    # Test verifying Bulletproof with min value
    min_value = [123]
    proof_with_min_value = bytes.fromhex('fd0c2425873f3e2c6a1179c0ee14854089fa018c632ad21623e848b141cf4bf97ee1e7e72c7bc8562c9f530988d7c0c8eb631f08ea9b8cd5a24de2dde33d4eff07ad313720393e57b84c8724dd2d281ed60b0ad1c2e4754b1426e3fcfdea99338db38908f46cfb166a26ce8ef64bc82b04b8906b43c8ee545f7f488c641997abb1ffebfe8cde7d9beedc473afa9af14824f4dbc42464894580cae487fe65cda1511ad1bbd49f580f6951d1adde3f4a9708168ac179eea55f71b72eb6061e7c508482106c1eb365343e0df725203088472cb12f34357ee3760315704c5f949876a765cfc9915a577cd6270e8989c4c74d258d2e7bcaacd4fa9976686ffe72a0b27053a34d1b3e13071144bc32290422ec9430419a20e7465a5ea6b9b1a37b06232e6866869d1d762dbceead851aced160a1709c7db579094a83d3c5a045738bb246b626ac5b99bd0933cdd3d88c9d09562fd971ceed6cb8bd599901422e16ecee02bc013ac6fba47db5497591c55c34e74f40e1bbd0590e1124baea042b85c4fbcd62a5f0d595c21ac5f308a04496091f85bbe03789a98e1f6ad1001b5385f075db00df75e3df5c5b93ff52f70132c1bc0350b453dcae3cf1b205cb1ba5fc6d29be107e29e20cfba13b7eb816be6a13697944500fee6eb8fe27b1e179174304020f817fd99086c14948b2ac93cddbea61337ae4a164bf4a60b133258b28f71d69e881901efd034a36655fc614315f21ccc97f129f0842303b51d46126c56468f8210eec9ecde6dd58991bb21e171048b27f5eaefeb306d39dce7fc89db43036dedf9049023e5366489c6a7af4ee646ec6ed65e2e79df7182a98fd17d27e6ad438387853b595481a12e1db328453b54fe548ee2336e3ebeec5b6a9b7a450879e949f6fa035db4ff51457bf8bb49c15c764601666e3536ac62f9aae504118dd414f6161e6')
    result_with_min_value = secp256k1_bulletproof_rangeproof_verify(ctx, scratch, gens, proof_with_min_value, min_value, commit, 64, secp256k1_generator_const_h, None)
    assert result_with_min_value is True

    # Test verifying Bulletproof with extra commit
    extra_commit = bytes.fromhex('060708090a')
    proof_with_extra_commit = bytes.fromhex('0251e002750d5d48327b04ea82b8249ad3e25068dc1a5cda47f46baf3fe0f5052f81130bf2f1cf44cdab9a1b21ba17b3bf7a77dca77c450fd728ea47fb8ec42a0f5a35bd7843cd92b90b235eee1c886e6b294e4bfb84d1e932f464e693a0e74fdcb38908f46cfb166a26ce8ef64bc82b04b8906b43c8ee545f7f488c641997abb14243b252262a2daee092fc6bd1b3a039dffdaaf6826affcbaf57194a41b60fb04ec4c81f1d3e215cef3be8961f8947651b2c254ce5736f1a6d8448f896b729db09ef59acd164be40de422644263b7ab9a668cbb819c154b7c34b85c7339ee91071335f56959b086a856e885a69140d6e675522d31918e086744e098c60b5cdad729d6e5f9959be4d99c14cb46083cd27caad7644c1803bf809d4ca256a11083045d876fa84b8d9ae7a0570d44b1dd82b16d0b8c8f77207d050b13c83a591df3634b53d6584302897cf0b9f82a3a1cc00cd34c5855f6b043d334aa4be1ea6fac80801b0f829e5aa2c9cad2c1f7b9958cb435a8aa1ee08b5e541bf55e607a0dc3137a399d362fb1a98b86fe1d16907b25dd5f4a943217b0015709233c01dc63f62814e60269cf2ca27b32c10bc988e3c7de52d0d04e3889266bb780adad315376a10c4e40aa814a82dfc93735db829353af33c138ea25a6857c9f0ef59831145c15155d4d448b35f02ba92e24940187f4f37695155ef943dd1f55474d9e63993b6a5bc13073e05260187fc9db14df2500e476de97e673b9e498d552f752cb573191888d5560a1c054f93c5950e6fecbb1808f34fa9ab00be3d4cfa6f4363c4df3dea72beaa00bdd8ad02235a79cbe238c69dc05e6cfc69c6578cd8bc95cd45d69ff76b472ee6babe9d119835d67bce6515d22b39e3d6950d06c8054df7c986e9da4764c6c44fe1e0c4f5ca16b63567e61b6f0d4e57fa4360884bd5c60b1a9a42d28055')
    result_with_extra_commit = secp256k1_bulletproof_rangeproof_verify(ctx, scratch, gens, proof_with_extra_commit, None, commit, 64, secp256k1_generator_const_h, extra_commit)
    assert result_with_extra_commit is True

    # Test verifying Bulletproof with all
    proof_with_all = bytes.fromhex('95f292afea38c42d053e503b46a9600d1d44f2cd566a9e030a62960f260b89a8aaaa386827f063738167d916015341663b532c59d5aa1a6713608302280658e30eb492e9bab887066e0aceaa501f716ba9df4081d9ba497460b398b9bc6167e95bb38908f46cfb166a26ce8ef64bc82b04b8906b43c8ee545f7f488c641997abb1dd9d24a3fe1dc9b88ca2fe8c98d692176fae8c11d731ab9c7e5b3eaf9086d2de378f5dc3e07fca8b0aa09fee3ed3a0f862a1ccbebeeaf73b88e58f4571fd30b17c557f8a177c8cb9280f9abfc1097ba05c942122f4cce2fc9b5251e53c8bbf8a061fef8de33b01ab889687e97d543b6b85e7025ae1c309236904b095c5066da7991fce135bd89752e313e042e93f123f676a2dd7cc74c09963dd6838bfcb17ea40230d733a23ec8c75e43192d8072815068ec2a4ed57916e1be64218ce3bf27fc417c5385f37623cf38135e5ed8d42a728be2ef8688f4e02e68f885954507e5c0a03b43bc0fc5c5582be00e1eae5a5570c38d053712ba6e5cafb15e81e6469f4506634d1ea9748678b66cfe3617ade01125dae972e06c79f6113048f2270023a4c2b46c918b594cce02f8e4f43daef8682c2bb8ca8a7640ced2ad7e8fcd2291eb5c316c7944ea8906decba92c0275accc1480a1508133558b9a9af9f8654b87b6e3590892887cbd77a350ce047e693e746edde2288d620070d2f73cd669ddabb7542b6a8194d1d509a04055a11cf08bb3cf83771f1967399fb6a9a43ab220025eae94935f78501da2a41262700c9f0b2c49c787e30cd71e6edea72e2f92063922235b17ffa7093ed6cc34910011e33596c5ecd69e15599a83914205ef02011af2d8ef6d6fc42abe399758306a2211dd58773799b7eea354e747442a999f7c772d6c92e75b0f2779c720f70a29adab0d432b04d4f10113d8e4aeb6ff86a679a84c38a')
    result_with_all = secp256k1_bulletproof_rangeproof_verify(ctx, scratch, gens, proof_with_all, min_value, commit, 64, secp256k1_generator_const_h, extra_commit)
    assert result_with_all is True

    # Test verifying invalid Bulletproof
    invalid_proof = bytes.fromhex('e679da5ef802338b14cac935ea99def5dc0d399db1435ac429863c9eb5b46b10682aaa885cbeb0e24846563a0093f35c75825da857145055259da7e3578492f2073af8080a30bc542f4293c15ecc522afd249b3b6ee2506f21b019653ad919a6b5b38908f46cfb166a26ce8ef64bc82b04b8906b43c8ee545f7f488c641997abb15ead216511e600f5c48eb55e1c7ab865e79282f0978b50d720e37bbba46786f91c28f8b5abf8127c0743b9adcb6bab89f6007af97802c7a97bfd997753e29cf1716245df5def5e5a50ff9aecebc9d8061e4d1137a9ff344be842451d29bd438c35c03827e4c6bfe144b333c557139b71fe6b94117cf8cc2c77848cb05953d4bf2fd0563a07bf140e968c0fcfbc0ec111f87b1b9317db3a09ab18beba67138b71c84fd7943cfa5164f088544077e27c8cd759dc5792d457795cd29abc8335f293c2f1d5090963e9d353be19b2e689099f84fdbbfae413c15ca5239e5b7886a7b11601c2ced7f23e2f4042fd1ec9b6c3445a61c35d04a74f64166e36abb5f016b47d5ca7ad8c9864e677109d0217437dc20a7be40af4d165b5e0c4aa031bc8374218f99591b4dcfd2e08702b367c1fa63aed73a9a2c39eed17494c582ced3f699183a3bacbb1147b7a61ec35d847f1644737650f9bfa82b4061b63ef6a85eee6f471b6bedc9aeacbe2049664c97774d75c64e807e5c4cef1d20c34b0bf1baddd32ee8dd4d48a4cec1df83409156744c2debf3dc0879bc1e3b4b84bb2bc7b05ac4039b685facd66a6b518c60d85d8a29beef645ab8bda8dae048336c5bfb6382b8edbc6b539e3a935cb892ae3cdaf314222d105f4f007b040eb9b7add48369e17700f0993379064b616a97df576e027c6d2f5eccb3b12543e3f1287595a390710c07dc5982aceb0c71ec2042505c3de900a7a47a06eaffd0134db9b879ac9dddf6676e0')
    invalid_result = secp256k1_bulletproof_rangeproof_verify(ctx, scratch, gens, invalid_proof, None, commit, 64, secp256k1_generator_const_h, None)
    assert invalid_result is False

    # Test verifying Bulletproof with invalid types
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify(None, scratch, gens, proof_without_optional, None, commit, 64, secp256k1_generator_const_h, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify('string', scratch, gens, proof_without_optional, None, commit, 64, secp256k1_generator_const_h, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify(ctx, None, gens, proof_without_optional, None, commit, 64, secp256k1_generator_const_h, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify(ctx, 'string', gens, proof_without_optional, None, commit, 64, secp256k1_generator_const_h, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify(ctx, scratch, None, proof_without_optional, None, commit, 64, secp256k1_generator_const_h, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify(ctx, scratch, 'string', proof_without_optional, None, commit, 64, secp256k1_generator_const_h, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify(ctx, scratch, gens, None, None, commit, 64, secp256k1_generator_const_h, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify(ctx, scratch, gens, 'string', None, commit, 64, secp256k1_generator_const_h, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify(ctx, scratch, gens, proof_without_optional, 'string', commit, 64, secp256k1_generator_const_h, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify(ctx, scratch, gens, proof_without_optional, ['1', '2', '3'], commit, 64, secp256k1_generator_const_h, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify(ctx, scratch, gens, proof_without_optional, None, None, 64, secp256k1_generator_const_h, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify(ctx, scratch, gens, proof_without_optional, None, 'string', 64, secp256k1_generator_const_h, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify(ctx, scratch, gens, proof_without_optional, None, [1, 2, 3], 64, secp256k1_generator_const_h, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify(ctx, scratch, gens, proof_without_optional, None, commit, None, secp256k1_generator_const_h, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify(ctx, scratch, gens, proof_without_optional, None, commit, 'string', secp256k1_generator_const_h, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify(ctx, scratch, gens, proof_without_optional, None, commit, 64, None, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify(ctx, scratch, gens, proof_without_optional, None, commit, 64, 'string', None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify(ctx, scratch, gens, proof_without_optional, None, commit, 64, secp256k1_generator_const_h, 'string')

    # Test verifying Bulletproof with invalid values
    with pytest.raises(OverflowError):
        secp256k1_bulletproof_rangeproof_verify(ctx, scratch, gens, proof_without_optional, [-1], commit, 64, secp256k1_generator_const_h, None)
    with pytest.raises(OverflowError):
        secp256k1_bulletproof_rangeproof_verify(ctx, scratch, gens, proof_without_optional, [0x10000000000000000], commit, 64, secp256k1_generator_const_h, None)
    with pytest.raises(OverflowError):
        secp256k1_bulletproof_rangeproof_verify(ctx, scratch, gens, proof_without_optional, None, commit, -1, secp256k1_generator_const_h, None)
    with pytest.raises(OverflowError):
        secp256k1_bulletproof_rangeproof_verify(ctx, scratch, gens, proof_without_optional, None, commit, 0x10000000000000000, secp256k1_generator_const_h, None)

def test_secp256k1_bulletproof_rangeproof_verify_multi():
    # Test verifying multiple Bulletproofs without optional
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    scratch = secp256k1_scratch_space_create(ctx, 30720)
    assert scratch is not None
    gens = secp256k1_bulletproof_generators_create(ctx, secp256k1_generator_const_g, 256)
    assert gens is not None
    value = [123456789, 98242]
    blind = [bytes.fromhex('59e721189cf77b5fcd6c7247ef8b997f66379e85218c2115f25d8cdbb50faa1a'), bytes.fromhex('e7a09cd3295f22d4def2b6195d40a9ca8408170ac65e4b0efb265b0bf43679f3')]
    proof_without_optional = [bytes.fromhex('06c8d2140622ecdccad4a2810d4ec58939852e41606b456cf0fb34933e330dbe41890912a82a2d2bce57526df7988be80090a93f17ed093392d3c660aabae6880f5a35bd7843cd92b90b235eee1c886e6b294e4bfb84d1e932f464e693a0e74fdcb38908f46cfb166a26ce8ef64bc82b04b8906b43c8ee545f7f488c641997abb1b05d571bd913884b44d1954e42bfed4c743d93efb9e5c11e7f8983bf5e74f80070230676af6ef835023c9b42074d0404c69471d14b1b70e881e57d0c7edc5bad81904085700a11966c2017920dc4b0e443c0eec2c70ca5c9f2440457e36ed4bc77d9a0a995cc4d2503f8dded0db4031a8dcba32f5532598084b445aa081bd77c6a92cb77bb4b9fa72da67cce6ef2c95cc8a6cead1b1ae211d81964085f957f3d06f6a90a6a87f71ccc2cfabf2e5af741c24abf5cec063883909c3394d6967b419bf8f80132cf636c3c9b5afec6351dd18b85f556cbe560fd7ca4c359202948dc3902fa6abf8a55a65ce7cf28b91b2f107daf1fe37b9e9195fdf56fd7ba4c146fe9f4cf538b4666e47f594f81567ce4fdf2842b71be8618af11e6881e328c52a7fa3d874a138ee62ac2bfc23a6e82e6982901751277843f0f03bb40e99eb02b0a87d3768409603cd2fa24255d2765a27774cce3bffd2a0f76e903bfae9ff0de19ecd0e6d92b590f1ff7c648a2c0685834af56d23b45465fc893728326c524c2c50abbbb1b506159a7a7098061ccf3972d5df786538589f5921a1922c44ac329734bfa3821e39ecc93f7f1a9cb8a0f9fb5165df024e001ebb9107b04f5889799fe0ecf6fe2190c70b524a6f843a280992148031349aef170a684bf2c8ca424e68d9a99a96af130de9ce97285490358d75e188e6a0f53af4651626bbab059825f8812b669a44604eaa8d7dc8b3d646b2eb7601c7e1e4fb62b0b83490d78ed4d30255c2d'), bytes.fromhex('0f424a2628c6688ccdb9b0afc79e228c3bf58362e73f127ec8f1910575cbd24dd73053817d05eb63fcc9c1975f13022cc50ddb431c50565774dca2d37795a69d098a8c1b36993fcf417f16752cef6fa47bd1eb87a26cf08756549b5020ab2411a35663ab8ee1e485ce40d88d1eb37734cae1cd00076814e4cf7156f74821be5cc8664bc738dd1bed2d95054d880a5703d06507265b1aabcc484c1994af6ed4b3ecaee13a29d8db6fdac546aa6bdd117872ab3527b3215de273d22b2d53d1b75ed65f5230a82cade55f1ae797d3e317bb9cdf4c01d5f5d5e45ea667373cbb144742e83842304dfb7c968462a15d8d9e8332940d3346cbdde1348944a92a2bd7e89b0270791b63d958eb4aebb1af14b57662b6303ba88c37db2cb88a9644a42b7ece4ef173fc9f0b14b07fd94ba43229f3d472b8049d13c927319873ffa3e84710ca533c768051a5bf6f92660045416791c78378761009ee69e190a6aee8b0673b28a103f8fa39bc56810991dabc3c6f1d22165cd41be0e5c6d467056a574a885612d9352f62f9afd1e8a5385e2bd0e01e68f77be13041fcc020beeb81ba4fb4e677d50f03a1667002f9941d86ba2c349e8b6b8b12737080e0f0cb2ce14d42295b0912ba85f7623d691a8f0e06199686b961f3716439c985aabdcc0defddd23a1b084daa0824916937034d3ebad663265213a02c55a3f4402b063f9c566a2ac2af08d8bd018a33c4a4d36577e5cc472e0c12eed9743ee343985bcdb97de829b8b16294b5afd754f9ff3d2527c75a725adf02a6b64c5091f8dce7ffc32dff0cc5114e80421e21deb35cae6a47f0f5618895cacd538110551ccfd1557646aa55e283f017cb719e3bf5c45fb547cb9bae81a886e55b14ba81d9769d433e152b5518c949d0cf5dec9eadccaffc1082cf8b5fd378459b2ad24c1d5d01ac5ac7dce0d4d7471719')]
    commit = [[secp256k1_pedersen_commit(ctx, blind[0], value[0], secp256k1_generator_const_h, secp256k1_generator_const_g)], [secp256k1_pedersen_commit(ctx, blind[1], value[1], secp256k1_generator_const_h, secp256k1_generator_const_g)]]
    assert all(all(commitment is not None for commitment in commitments) for commitments in commit)
    result_without_optional = secp256k1_bulletproof_rangeproof_verify_multi(ctx, scratch, gens, proof_without_optional, None, commit, 64, [secp256k1_generator_const_h, secp256k1_generator_const_h], None)
    assert result_without_optional is True

    # Test verifying multiple Bulletproofs with min value
    min_value = [[123], [456]]
    proof_with_min_value = [bytes.fromhex('fd0c2425873f3e2c6a1179c0ee14854089fa018c632ad21623e848b141cf4bf97ee1e7e72c7bc8562c9f530988d7c0c8eb631f08ea9b8cd5a24de2dde33d4eff07ad313720393e57b84c8724dd2d281ed60b0ad1c2e4754b1426e3fcfdea99338db38908f46cfb166a26ce8ef64bc82b04b8906b43c8ee545f7f488c641997abb1ffebfe8cde7d9beedc473afa9af14824f4dbc42464894580cae487fe65cda1511ad1bbd49f580f6951d1adde3f4a9708168ac179eea55f71b72eb6061e7c508482106c1eb365343e0df725203088472cb12f34357ee3760315704c5f949876a765cfc9915a577cd6270e8989c4c74d258d2e7bcaacd4fa9976686ffe72a0b27053a34d1b3e13071144bc32290422ec9430419a20e7465a5ea6b9b1a37b06232e6866869d1d762dbceead851aced160a1709c7db579094a83d3c5a045738bb246b626ac5b99bd0933cdd3d88c9d09562fd971ceed6cb8bd599901422e16ecee02bc013ac6fba47db5497591c55c34e74f40e1bbd0590e1124baea042b85c4fbcd62a5f0d595c21ac5f308a04496091f85bbe03789a98e1f6ad1001b5385f075db00df75e3df5c5b93ff52f70132c1bc0350b453dcae3cf1b205cb1ba5fc6d29be107e29e20cfba13b7eb816be6a13697944500fee6eb8fe27b1e179174304020f817fd99086c14948b2ac93cddbea61337ae4a164bf4a60b133258b28f71d69e881901efd034a36655fc614315f21ccc97f129f0842303b51d46126c56468f8210eec9ecde6dd58991bb21e171048b27f5eaefeb306d39dce7fc89db43036dedf9049023e5366489c6a7af4ee646ec6ed65e2e79df7182a98fd17d27e6ad438387853b595481a12e1db328453b54fe548ee2336e3ebeec5b6a9b7a450879e949f6fa035db4ff51457bf8bb49c15c764601666e3536ac62f9aae504118dd414f6161e6'), bytes.fromhex('1c82ac24335d69ca3b2bd82e5375e156b5ce0d76749853dd9f99f1a66ed8a593f27af9a4fa95353af892b0e80b2d76cd97dc5f9bd71aee02eb53fcbdf48c46e609810c3b0126ae235b07614e5049f007cbcfe0d592ea38ed3c905a199b6c0caa0c5663ab8ee1e485ce40d88d1eb37734cae1cd00076814e4cf7156f74821be5cc889f82addbf5708a648c386bcdc106993e5cf3cddea0b1491e6889eace63fc1b14b13e61ff8819b018b4ad5fafab9bc2bab010926b6e8a90446429cb2be2c1d4858f0e666d8dc99d986e55a1bda6367b0eeb5474b28040741a252dbbfa4eae66462808d580572029b52780649c8224e4acc073eb8b787e08443eeccedace5ed521702c9c1bef63b50e4f4b07c1525753f813e3c044f4a6bba33836bb6c93447619ffc445dbcb2d601be7b8fd7ddabd9fdec7dbb5f88eb8c6dcc82ee4f1c21db8072da17e3d5a1ba3877f9de999623ab49da8a8a39d431d5923d517093d04c46152300a7c8e834e28ce90adb9e9e65241ecb7f2a0bec2bc251b0c2a0407bf48548cb75a2e3d0411e6434a9e4049ba592952fe44acb02fe7e525e1f9ae0cf5f2078842d7a3095cdba6a250aeccd60593e078475919e55ccdf313584d55a6e19661e40bc93902dc7df789ceef0e78bc591d345d7f50e5cc2d712ab3e7b1de914bf5a023a87713ae81b0b56704d1f13e029e19e42330c3335814f21c0effafb6215f0c7e76beb0c3572d0354460968998a736c3bc37aa372cfc24172a067dd7f695685a9e7c34353826605380d465a5882a31470c0a25ff8ba7253d0191910366db75391db86306f2d320b5aad9abca5f495c5472be0be34b576870818122bd08dae8751b3e5f10c7712d838ffb9514e257e948593ff0fe867df007547d4fd4caeaa86604d1d31d4a4772371b6d419b8e14d5feda2d7152ed0694a2da40f37d58923997e9')]
    result_with_min_value = secp256k1_bulletproof_rangeproof_verify_multi(ctx, scratch, gens, proof_with_min_value, min_value, commit, 64, [secp256k1_generator_const_h, secp256k1_generator_const_h], None)
    assert result_with_min_value is True

    # Test verifying multiple Bulletproofs with extra commit
    extra_commit = [bytes.fromhex('060708090a'), bytes.fromhex('ff6798')]
    proof_with_extra_commit = [bytes.fromhex('0251e002750d5d48327b04ea82b8249ad3e25068dc1a5cda47f46baf3fe0f5052f81130bf2f1cf44cdab9a1b21ba17b3bf7a77dca77c450fd728ea47fb8ec42a0f5a35bd7843cd92b90b235eee1c886e6b294e4bfb84d1e932f464e693a0e74fdcb38908f46cfb166a26ce8ef64bc82b04b8906b43c8ee545f7f488c641997abb14243b252262a2daee092fc6bd1b3a039dffdaaf6826affcbaf57194a41b60fb04ec4c81f1d3e215cef3be8961f8947651b2c254ce5736f1a6d8448f896b729db09ef59acd164be40de422644263b7ab9a668cbb819c154b7c34b85c7339ee91071335f56959b086a856e885a69140d6e675522d31918e086744e098c60b5cdad729d6e5f9959be4d99c14cb46083cd27caad7644c1803bf809d4ca256a11083045d876fa84b8d9ae7a0570d44b1dd82b16d0b8c8f77207d050b13c83a591df3634b53d6584302897cf0b9f82a3a1cc00cd34c5855f6b043d334aa4be1ea6fac80801b0f829e5aa2c9cad2c1f7b9958cb435a8aa1ee08b5e541bf55e607a0dc3137a399d362fb1a98b86fe1d16907b25dd5f4a943217b0015709233c01dc63f62814e60269cf2ca27b32c10bc988e3c7de52d0d04e3889266bb780adad315376a10c4e40aa814a82dfc93735db829353af33c138ea25a6857c9f0ef59831145c15155d4d448b35f02ba92e24940187f4f37695155ef943dd1f55474d9e63993b6a5bc13073e05260187fc9db14df2500e476de97e673b9e498d552f752cb573191888d5560a1c054f93c5950e6fecbb1808f34fa9ab00be3d4cfa6f4363c4df3dea72beaa00bdd8ad02235a79cbe238c69dc05e6cfc69c6578cd8bc95cd45d69ff76b472ee6babe9d119835d67bce6515d22b39e3d6950d06c8054df7c986e9da4764c6c44fe1e0c4f5ca16b63567e61b6f0d4e57fa4360884bd5c60b1a9a42d28055'), bytes.fromhex('28b51442291ae22c0a961941885825a1558edd41092b14ab67add6a4e02350f97001bc149f0b152a8da070aeb708e4e132032ccc5fcec28dcd8e9f75697e98e9058a8c1b36993fcf417f16752cef6fa47bd1eb87a26cf08756549b5020ab2411a35663ab8ee1e485ce40d88d1eb37734cae1cd00076814e4cf7156f74821be5cc86448366a36092959e2a03214f937741ef1d828be59e64eb803cb486d5003d1c9c224dd553f0a1b203d4ae48bc2139a52c8ac69b67382ca14da373ad699b82e674ae1a2e103e98e6ad9573c114a06e0243634f1fbb508beddcb0398c3fbd16534bb87b15a90a59619ec609dd66d837f1923d46db97c79a88e63043662a44a2d8fa157ba95792e7e6e895f3da026d3649fedbc17f9c9914f3589772927c19054157642a001c2486813fa54c611cb85e84c1ac8575b81c5506fc6628a3929fb1f2a5666ccceef0cb66fd97cd39993aabd3c3381fe00ef2de247e467f5e9d3969e3e07002ffcb406422f05f5773852c623dfbce156559be518d601251491e4e96472268f6f207019084ff401ea930b67fd5b08f48a60a4888fd864f50966405f39e6a3c9108c7774d5d98e7ba552017a31f4ae25ce439d5b3aabdd809da8df53363cab763c519f089af7bafe4765d2d6cc665dec3403844981f67f1da394a92f3e48c6d8a63013c21240f7f0e56d64f4443b9d68591c8f074e7ce0fad3254dc4d4a3d25ff8931ee59d61987f9423dd2a674d2778c8c60059e2f3c7d7ef929726e6597bb7ccd778065f32830fea4238762c4029043d5be11eba16064af093301d0e227e304fed6a93db15a2ea4ac76a4596a3a541fde3185350ad1260c379627ea99fecb537c5adc3d92ba140b4478b7c8a1b77e0cc58cd2f7dcc46501a1dd5b58a1cb7fccd752239e613e3a89fd8ceec3c926c79a4a8580e9328d62c11ea69be57baeb15')]
    result_with_extra_commit = secp256k1_bulletproof_rangeproof_verify_multi(ctx, scratch, gens, proof_with_extra_commit, None, commit, 64, [secp256k1_generator_const_h, secp256k1_generator_const_h], extra_commit)
    assert result_with_extra_commit is True

    # Test verifying multiple Bulletproofs with all
    proof_with_all = [bytes.fromhex('95f292afea38c42d053e503b46a9600d1d44f2cd566a9e030a62960f260b89a8aaaa386827f063738167d916015341663b532c59d5aa1a6713608302280658e30eb492e9bab887066e0aceaa501f716ba9df4081d9ba497460b398b9bc6167e95bb38908f46cfb166a26ce8ef64bc82b04b8906b43c8ee545f7f488c641997abb1dd9d24a3fe1dc9b88ca2fe8c98d692176fae8c11d731ab9c7e5b3eaf9086d2de378f5dc3e07fca8b0aa09fee3ed3a0f862a1ccbebeeaf73b88e58f4571fd30b17c557f8a177c8cb9280f9abfc1097ba05c942122f4cce2fc9b5251e53c8bbf8a061fef8de33b01ab889687e97d543b6b85e7025ae1c309236904b095c5066da7991fce135bd89752e313e042e93f123f676a2dd7cc74c09963dd6838bfcb17ea40230d733a23ec8c75e43192d8072815068ec2a4ed57916e1be64218ce3bf27fc417c5385f37623cf38135e5ed8d42a728be2ef8688f4e02e68f885954507e5c0a03b43bc0fc5c5582be00e1eae5a5570c38d053712ba6e5cafb15e81e6469f4506634d1ea9748678b66cfe3617ade01125dae972e06c79f6113048f2270023a4c2b46c918b594cce02f8e4f43daef8682c2bb8ca8a7640ced2ad7e8fcd2291eb5c316c7944ea8906decba92c0275accc1480a1508133558b9a9af9f8654b87b6e3590892887cbd77a350ce047e693e746edde2288d620070d2f73cd669ddabb7542b6a8194d1d509a04055a11cf08bb3cf83771f1967399fb6a9a43ab220025eae94935f78501da2a41262700c9f0b2c49c787e30cd71e6edea72e2f92063922235b17ffa7093ed6cc34910011e33596c5ecd69e15599a83914205ef02011af2d8ef6d6fc42abe399758306a2211dd58773799b7eea354e747442a999f7c772d6c92e75b0f2779c720f70a29adab0d432b04d4f10113d8e4aeb6ff86a679a84c38a'), bytes.fromhex('fbdb0857608a9baa0e09b5e4c80213d58d5f48ab2d025f3a95052c3a5fd3cdac3ac5e3d3ce960a20253aa12bb69be1ae71c8c6fa04a02197554c06e3863806a9045ed82a2828817a9cc0c97715a31b6e3eae7ce4aee4ef00ac6393f27b786288b45663ab8ee1e485ce40d88d1eb37734cae1cd00076814e4cf7156f74821be5cc8994b01105cc49178d96aecfba512fecfe564822dd762259e64987c268247dabe3bc3ed3d37eb23eee752f4028652c4619751a60c086bf1a963501a5009d738583e80042888298f3c763ca74fe5853c2ce4976cce4969e42c759b08d39e9a9c6eaf3127b8837c6d01f5a0e0c7a4b6540ae8da9221a621b3e2650e7dfe5b616b795bd0916c8fba70dd48e38f9387a1c20985ee4e8ea1c612a5e09baa7adf1158a1f4c5a47522ee7511fdc72b4844887667ca1d5987b2bceeacea040711b9ea34a8c158f57ac500ef6e2094a43013dd061d69832b657f5eab2d6bbf6b6bcb9c5a0aed035753e0adb7cd420c12693619b14e0ee05c3da6187f5690831f0517223bdb562d4c729af72098103faed0ee7344116aecad01594c8832e06fc015f8ff6a64ac3d36066354cfa767635c68c225cf567c658abfd2d48acad4b0328db84230e2c998abf7cda7ee5a7643928d982a65083d879cf4899587662a9b986085c6ff56b2f035f30da68a5e33d588d1af38784fe146d5f434e29ef8b1f6e19128ce25779034257183089c2706ecb3430f090a733a26a3c8c44f71dd709425ff8b70596e592ce0711583dadf9ec56ff73818cb70ca596dbedc7f915cdc29e0554fbdcf5ff044b6f8c2f20f7420edc881562c97bfa89d371e4b649e204bfc9d139acf5bc62e91111e375946e8076057f55e8a73d3e404020ac4547978c8df06da956e892d8b0ffff70e97bfe20f2b24e76b78b688b535a1cef68a1039027c7d220a828c1f6150')]
    result_with_all = secp256k1_bulletproof_rangeproof_verify_multi(ctx, scratch, gens, proof_with_all, min_value, commit, 64, [secp256k1_generator_const_h, secp256k1_generator_const_h], extra_commit)
    assert result_with_all is True

    # Test verifying multiple invalid Bulletproofs
    invalid_proof = [bytes.fromhex('e679da5ef802338b14cac935ea99def5dc0d399db1435ac429863c9eb5b46b10682aaa885cbeb0e24846563a0093f35c75825da857145055259da7e3578492f2073af8080a30bc542f4293c15ecc522afd249b3b6ee2506f21b019653ad919a6b5b38908f46cfb166a26ce8ef64bc82b04b8906b43c8ee545f7f488c641997abb15ead216511e600f5c48eb55e1c7ab865e79282f0978b50d720e37bbba46786f91c28f8b5abf8127c0743b9adcb6bab89f6007af97802c7a97bfd997753e29cf1716245df5def5e5a50ff9aecebc9d8061e4d1137a9ff344be842451d29bd438c35c03827e4c6bfe144b333c557139b71fe6b94117cf8cc2c77848cb05953d4bf2fd0563a07bf140e968c0fcfbc0ec111f87b1b9317db3a09ab18beba67138b71c84fd7943cfa5164f088544077e27c8cd759dc5792d457795cd29abc8335f293c2f1d5090963e9d353be19b2e689099f84fdbbfae413c15ca5239e5b7886a7b11601c2ced7f23e2f4042fd1ec9b6c3445a61c35d04a74f64166e36abb5f016b47d5ca7ad8c9864e677109d0217437dc20a7be40af4d165b5e0c4aa031bc8374218f99591b4dcfd2e08702b367c1fa63aed73a9a2c39eed17494c582ced3f699183a3bacbb1147b7a61ec35d847f1644737650f9bfa82b4061b63ef6a85eee6f471b6bedc9aeacbe2049664c97774d75c64e807e5c4cef1d20c34b0bf1baddd32ee8dd4d48a4cec1df83409156744c2debf3dc0879bc1e3b4b84bb2bc7b05ac4039b685facd66a6b518c60d85d8a29beef645ab8bda8dae048336c5bfb6382b8edbc6b539e3a935cb892ae3cdaf314222d105f4f007b040eb9b7add48369e17700f0993379064b616a97df576e027c6d2f5eccb3b12543e3f1287595a390710c07dc5982aceb0c71ec2042505c3de900a7a47a06eaffd0134db9b879ac9dddf6676e0'), bytes.fromhex('0f424a2628c6688ccdb9b0afc79e228c3bf58362e73f127ec8f1910575cbd24dd73053817d05eb63fcc9c1975f13022cc50ddb431c50565774dca2d37795a69d098a8c1b36993fcf417f16752cef6fa47bd1eb87a26cf08756549b5020ab2411a35663ab8ee1e485ce40d88d1eb37734cae1cd00076814e4cf7156f74821be5cc8664bc738dd1bed2d95054d880a5703d06507265b1aabcc484c1994af6ed4b3ecaee13a29d8db6fdac546aa6bdd117872ab3527b3215de273d22b2d53d1b75ed65f5230a82cade55f1ae797d3e317bb9cdf4c01d5f5d5e45ea667373cbb144742e83842304dfb7c968462a15d8d9e8332940d3346cbdde1348944a92a2bd7e89b0270791b63d958eb4aebb1af14b57662b6303ba88c37db2cb88a9644a42b7ece4ef173fc9f0b14b07fd94ba43229f3d472b8049d13c927319873ffa3e84710ca533c768051a5bf6f92660045416791c78378761009ee69e190a6aee8b0673b28a103f8fa39bc56810991dabc3c6f1d22165cd41be0e5c6d467056a574a885612d9352f62f9afd1e8a5385e2bd0e01e68f77be13041fcc020beeb81ba4fb4e677d50f03a1667002f9941d86ba2c349e8b6b8b12737080e0f0cb2ce14d42295b0912ba85f7623d691a8f0e06199686b961f3716439c985aabdcc0defddd23a1b084daa0824916937034d3ebad663265213a02c55a3f4402b063f9c566a2ac2af08d8bd018a33c4a4d36577e5cc472e0c12eed9743ee343985bcdb97de829b8b16294b5afd754f9ff3d2527c75a725adf02a6b64c5091f8dce7ffc32dff0cc5114e80421e21deb35cae6a47f0f5618895cacd538110551ccfd1557646aa55e283f017cb719e3bf5c45fb547cb9bae81a886e55b14ba81d9769d433e152b5518c949d0cf5dec9eadccaffc1082cf8b5fd378459b2ad24c1d5d01ac5ac7dce0d4d7471719')]
    invalid_result = secp256k1_bulletproof_rangeproof_verify_multi(ctx, scratch, gens, invalid_proof, None, commit, 64, [secp256k1_generator_const_h, secp256k1_generator_const_h], None)
    assert invalid_result is False

    # Test verifying multiple Bulletproofs with invalid types
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify_multi(None, scratch, gens, proof_without_optional, None, commit, 64, [secp256k1_generator_const_h, secp256k1_generator_const_h], None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify_multi('string', scratch, gens, proof_without_optional, None, commit, 64, [secp256k1_generator_const_h, secp256k1_generator_const_h], None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify_multi(ctx, None, gens, proof_without_optional, None, commit, 64, [secp256k1_generator_const_h, secp256k1_generator_const_h], None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify_multi(ctx, 'string', gens, proof_without_optional, None, commit, 64, [secp256k1_generator_const_h, secp256k1_generator_const_h], None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify_multi(ctx, scratch, None, proof_without_optional, None, commit, 64, [secp256k1_generator_const_h, secp256k1_generator_const_h], None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify_multi(ctx, scratch, 'string', proof_without_optional, None, commit, 64, [secp256k1_generator_const_h, secp256k1_generator_const_h], None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify_multi(ctx, scratch, gens, None, None, commit, 64, [secp256k1_generator_const_h, secp256k1_generator_const_h], None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify_multi(ctx, scratch, gens, 'string', None, commit, 64, [secp256k1_generator_const_h, secp256k1_generator_const_h], None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify_multi(ctx, scratch, gens, [1, 2, 3], None, commit, 64, [secp256k1_generator_const_h, secp256k1_generator_const_h], None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify_multi(ctx, scratch, gens, proof_without_optional, 'string', commit, 64, [secp256k1_generator_const_h, secp256k1_generator_const_h], None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify_multi(ctx, scratch, gens, proof_without_optional, [1, 2, 3], commit, 64, [secp256k1_generator_const_h, secp256k1_generator_const_h], None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify_multi(ctx, scratch, gens, proof_without_optional, [['1', '2', '3'], ['1', '2', '3']], commit, 64, [secp256k1_generator_const_h, secp256k1_generator_const_h], None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify_multi(ctx, scratch, gens, proof_without_optional, None, None, 64, [secp256k1_generator_const_h, secp256k1_generator_const_h], None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify_multi(ctx, scratch, gens, proof_without_optional, None, 'string', 64, [secp256k1_generator_const_h, secp256k1_generator_const_h], None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify_multi(ctx, scratch, gens, proof_without_optional, None, [1, 2, 3], 64, [secp256k1_generator_const_h, secp256k1_generator_const_h], None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify_multi(ctx, scratch, gens, proof_without_optional, None, [[1, 2, 3], [1, 2, 3]], 64, [secp256k1_generator_const_h, secp256k1_generator_const_h], None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify_multi(ctx, scratch, gens, proof_without_optional, None, commit, None, [secp256k1_generator_const_h, secp256k1_generator_const_h], None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify_multi(ctx, scratch, gens, proof_without_optional, None, commit, 'string', [secp256k1_generator_const_h, secp256k1_generator_const_h], None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify_multi(ctx, scratch, gens, proof_without_optional, None, commit, 64, None, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify_multi(ctx, scratch, gens, proof_without_optional, None, commit, 64, 'string', None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify_multi(ctx, scratch, gens, proof_without_optional, None, commit, 64, [1, 2, 3], None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify_multi(ctx, scratch, gens, proof_without_optional, None, commit, 64, [secp256k1_generator_const_h, secp256k1_generator_const_h], 'string')
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_verify_multi(ctx, scratch, gens, proof_without_optional, None, commit, 64, [secp256k1_generator_const_h, secp256k1_generator_const_h], [1, 2, 3])

    # Test verifying multiple Bulletproofs with invalid values
    with pytest.raises(OverflowError):
        secp256k1_bulletproof_rangeproof_verify_multi(ctx, scratch, gens, proof_without_optional, [[-1], [-1]], commit, 64, [secp256k1_generator_const_h, secp256k1_generator_const_h], None)
    with pytest.raises(OverflowError):
        secp256k1_bulletproof_rangeproof_verify_multi(ctx, scratch, gens, proof_without_optional, [[0x10000000000000000], [0x10000000000000000]], commit, 64, [secp256k1_generator_const_h, secp256k1_generator_const_h], None)
    with pytest.raises(OverflowError):
        secp256k1_bulletproof_rangeproof_verify_multi(ctx, scratch, gens, proof_without_optional, None, commit, -1, [secp256k1_generator_const_h, secp256k1_generator_const_h], None)
    with pytest.raises(OverflowError):
        secp256k1_bulletproof_rangeproof_verify_multi(ctx, scratch, gens, proof_without_optional, None, commit, 0x10000000000000000, [secp256k1_generator_const_h, secp256k1_generator_const_h], None)

def test_secp256k1_bulletproof_rangeproof_rewind():
    # Test rewinding Bulletproof without optional
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    scratch = secp256k1_scratch_space_create(ctx, 30720)
    assert scratch is not None
    gens = secp256k1_bulletproof_generators_create(ctx, secp256k1_generator_const_g, 256)
    assert gens is not None
    value = 123456789
    blind = bytes.fromhex('59e721189cf77b5fcd6c7247ef8b997f66379e85218c2115f25d8cdbb50faa1a')
    proof_without_optional = bytes.fromhex('06c8d2140622ecdccad4a2810d4ec58939852e41606b456cf0fb34933e330dbe41890912a82a2d2bce57526df7988be80090a93f17ed093392d3c660aabae6880f5a35bd7843cd92b90b235eee1c886e6b294e4bfb84d1e932f464e693a0e74fdcb38908f46cfb166a26ce8ef64bc82b04b8906b43c8ee545f7f488c641997abb1b05d571bd913884b44d1954e42bfed4c743d93efb9e5c11e7f8983bf5e74f80070230676af6ef835023c9b42074d0404c69471d14b1b70e881e57d0c7edc5bad81904085700a11966c2017920dc4b0e443c0eec2c70ca5c9f2440457e36ed4bc77d9a0a995cc4d2503f8dded0db4031a8dcba32f5532598084b445aa081bd77c6a92cb77bb4b9fa72da67cce6ef2c95cc8a6cead1b1ae211d81964085f957f3d06f6a90a6a87f71ccc2cfabf2e5af741c24abf5cec063883909c3394d6967b419bf8f80132cf636c3c9b5afec6351dd18b85f556cbe560fd7ca4c359202948dc3902fa6abf8a55a65ce7cf28b91b2f107daf1fe37b9e9195fdf56fd7ba4c146fe9f4cf538b4666e47f594f81567ce4fdf2842b71be8618af11e6881e328c52a7fa3d874a138ee62ac2bfc23a6e82e6982901751277843f0f03bb40e99eb02b0a87d3768409603cd2fa24255d2765a27774cce3bffd2a0f76e903bfae9ff0de19ecd0e6d92b590f1ff7c648a2c0685834af56d23b45465fc893728326c524c2c50abbbb1b506159a7a7098061ccf3972d5df786538589f5921a1922c44ac329734bfa3821e39ecc93f7f1a9cb8a0f9fb5165df024e001ebb9107b04f5889799fe0ecf6fe2190c70b524a6f843a280992148031349aef170a684bf2c8ca424e68d9a99a96af130de9ce97285490358d75e188e6a0f53af4651626bbab059825f8812b669a44604eaa8d7dc8b3d646b2eb7601c7e1e4fb62b0b83490d78ed4d30255c2d')
    commit = secp256k1_pedersen_commit(ctx, blind, value, secp256k1_generator_const_h, secp256k1_generator_const_g)
    assert commit is not None
    nonce = bytes.fromhex('7e13a050ece0a11106b984b66dbe5b597af212c539404e87d18aa4ba1d4a2fa6')
    value_without_optional, blind_without_optional, message_without_optional = secp256k1_bulletproof_rangeproof_rewind(ctx, proof_without_optional, 0, commit, secp256k1_generator_const_h, nonce, None)
    no_message = bytes.fromhex('0000000000000000000000000000000000000000')
    assert value_without_optional == value and blind_without_optional == blind and message_without_optional == no_message

    # Test rewinding Bulletproof with min value
    min_value = 123
    proof_with_min_value = bytes.fromhex('fd0c2425873f3e2c6a1179c0ee14854089fa018c632ad21623e848b141cf4bf97ee1e7e72c7bc8562c9f530988d7c0c8eb631f08ea9b8cd5a24de2dde33d4eff07ad313720393e57b84c8724dd2d281ed60b0ad1c2e4754b1426e3fcfdea99338db38908f46cfb166a26ce8ef64bc82b04b8906b43c8ee545f7f488c641997abb1ffebfe8cde7d9beedc473afa9af14824f4dbc42464894580cae487fe65cda1511ad1bbd49f580f6951d1adde3f4a9708168ac179eea55f71b72eb6061e7c508482106c1eb365343e0df725203088472cb12f34357ee3760315704c5f949876a765cfc9915a577cd6270e8989c4c74d258d2e7bcaacd4fa9976686ffe72a0b27053a34d1b3e13071144bc32290422ec9430419a20e7465a5ea6b9b1a37b06232e6866869d1d762dbceead851aced160a1709c7db579094a83d3c5a045738bb246b626ac5b99bd0933cdd3d88c9d09562fd971ceed6cb8bd599901422e16ecee02bc013ac6fba47db5497591c55c34e74f40e1bbd0590e1124baea042b85c4fbcd62a5f0d595c21ac5f308a04496091f85bbe03789a98e1f6ad1001b5385f075db00df75e3df5c5b93ff52f70132c1bc0350b453dcae3cf1b205cb1ba5fc6d29be107e29e20cfba13b7eb816be6a13697944500fee6eb8fe27b1e179174304020f817fd99086c14948b2ac93cddbea61337ae4a164bf4a60b133258b28f71d69e881901efd034a36655fc614315f21ccc97f129f0842303b51d46126c56468f8210eec9ecde6dd58991bb21e171048b27f5eaefeb306d39dce7fc89db43036dedf9049023e5366489c6a7af4ee646ec6ed65e2e79df7182a98fd17d27e6ad438387853b595481a12e1db328453b54fe548ee2336e3ebeec5b6a9b7a450879e949f6fa035db4ff51457bf8bb49c15c764601666e3536ac62f9aae504118dd414f6161e6')
    value_with_min_value, blind_with_min_value, message_with_min_value = secp256k1_bulletproof_rangeproof_rewind(ctx, proof_with_min_value, min_value, commit, secp256k1_generator_const_h, nonce, None)
    assert value_with_min_value == value and blind_with_min_value == blind and message_with_min_value == no_message

    # Test rewinding Bulletproof with extra commit
    extra_commit = bytes.fromhex('060708090a')
    proof_with_extra_commit = bytes.fromhex('0251e002750d5d48327b04ea82b8249ad3e25068dc1a5cda47f46baf3fe0f5052f81130bf2f1cf44cdab9a1b21ba17b3bf7a77dca77c450fd728ea47fb8ec42a0f5a35bd7843cd92b90b235eee1c886e6b294e4bfb84d1e932f464e693a0e74fdcb38908f46cfb166a26ce8ef64bc82b04b8906b43c8ee545f7f488c641997abb14243b252262a2daee092fc6bd1b3a039dffdaaf6826affcbaf57194a41b60fb04ec4c81f1d3e215cef3be8961f8947651b2c254ce5736f1a6d8448f896b729db09ef59acd164be40de422644263b7ab9a668cbb819c154b7c34b85c7339ee91071335f56959b086a856e885a69140d6e675522d31918e086744e098c60b5cdad729d6e5f9959be4d99c14cb46083cd27caad7644c1803bf809d4ca256a11083045d876fa84b8d9ae7a0570d44b1dd82b16d0b8c8f77207d050b13c83a591df3634b53d6584302897cf0b9f82a3a1cc00cd34c5855f6b043d334aa4be1ea6fac80801b0f829e5aa2c9cad2c1f7b9958cb435a8aa1ee08b5e541bf55e607a0dc3137a399d362fb1a98b86fe1d16907b25dd5f4a943217b0015709233c01dc63f62814e60269cf2ca27b32c10bc988e3c7de52d0d04e3889266bb780adad315376a10c4e40aa814a82dfc93735db829353af33c138ea25a6857c9f0ef59831145c15155d4d448b35f02ba92e24940187f4f37695155ef943dd1f55474d9e63993b6a5bc13073e05260187fc9db14df2500e476de97e673b9e498d552f752cb573191888d5560a1c054f93c5950e6fecbb1808f34fa9ab00be3d4cfa6f4363c4df3dea72beaa00bdd8ad02235a79cbe238c69dc05e6cfc69c6578cd8bc95cd45d69ff76b472ee6babe9d119835d67bce6515d22b39e3d6950d06c8054df7c986e9da4764c6c44fe1e0c4f5ca16b63567e61b6f0d4e57fa4360884bd5c60b1a9a42d28055')
    value_with_extra_commit, blind_with_extra_commit, message_with_extra_commit = secp256k1_bulletproof_rangeproof_rewind(ctx, proof_with_extra_commit, 0, commit, secp256k1_generator_const_h, nonce, extra_commit)
    assert value_with_extra_commit == value and blind_with_extra_commit == blind and message_with_extra_commit == no_message

    # Test rewinding Bulletproof with all
    message = bytes.fromhex('000102030405060708090a0b0c0d0e0f10111213')
    proof_with_all_blind = bytes.fromhex('e3efd144992b07cf0c25ea61e630d98e85df62bd5673028f4b18f979d6036624')
    proof_with_all = bytes.fromhex('95f292afea38c42d053e503b46a9600d1d44f2cd566a9e030a62960f260b89a8aaaa386827f063738167d916015341663b532c59d5aa1a6713608302280658e30eb492e9bab887066e0aceaa501f716ba9df4081d9ba497460b398b9bc6167e95bb38908f46cfb166a26ce8ef64bc82b04b8906b43c8ee545f7f488c641997abb1dd9d24a3fe1dc9b88ca2fe8c98d692176fae8c11d731ab9c7e5b3eaf9086d2de378f5dc3e07fca8b0aa09fee3ed3a0f862a1ccbebeeaf73b88e58f4571fd30b17c557f8a177c8cb9280f9abfc1097ba05c942122f4cce2fc9b5251e53c8bbf8a061fef8de33b01ab889687e97d543b6b85e7025ae1c309236904b095c5066da7991fce135bd89752e313e042e93f123f676a2dd7cc74c09963dd6838bfcb17ea40230d733a23ec8c75e43192d8072815068ec2a4ed57916e1be64218ce3bf27fc417c5385f37623cf38135e5ed8d42a728be2ef8688f4e02e68f885954507e5c0a03b43bc0fc5c5582be00e1eae5a5570c38d053712ba6e5cafb15e81e6469f4506634d1ea9748678b66cfe3617ade01125dae972e06c79f6113048f2270023a4c2b46c918b594cce02f8e4f43daef8682c2bb8ca8a7640ced2ad7e8fcd2291eb5c316c7944ea8906decba92c0275accc1480a1508133558b9a9af9f8654b87b6e3590892887cbd77a350ce047e693e746edde2288d620070d2f73cd669ddabb7542b6a8194d1d509a04055a11cf08bb3cf83771f1967399fb6a9a43ab220025eae94935f78501da2a41262700c9f0b2c49c787e30cd71e6edea72e2f92063922235b17ffa7093ed6cc34910011e33596c5ecd69e15599a83914205ef02011af2d8ef6d6fc42abe399758306a2211dd58773799b7eea354e747442a999f7c772d6c92e75b0f2779c720f70a29adab0d432b04d4f10113d8e4aeb6ff86a679a84c38a')
    value_with_all, blind_with_all, message_with_all = secp256k1_bulletproof_rangeproof_rewind(ctx, proof_with_all, min_value, commit, secp256k1_generator_const_h, nonce, extra_commit)
    assert value_with_all == value and blind_with_all == proof_with_all_blind and message_with_all == message

    # Test rewinding invalid Bulletproof
    invalid_proof = bytes.fromhex('00')
    invalid_value = secp256k1_bulletproof_rangeproof_rewind(ctx, invalid_proof, 0, commit, secp256k1_generator_const_h, nonce, None)
    assert invalid_value is None

    # Test rewinding Bulletproof with invalid types
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_rewind(None, proof_without_optional, 0, commit, secp256k1_generator_const_h, nonce, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_rewind('string', proof_without_optional, 0, commit, secp256k1_generator_const_h, nonce, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_rewind(ctx, None, 0, commit, secp256k1_generator_const_h, nonce, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_rewind(ctx, 'string', 0, commit, secp256k1_generator_const_h, nonce, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_rewind(ctx, proof_without_optional, None, commit, secp256k1_generator_const_h, nonce, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_rewind(ctx, proof_without_optional, 'string', commit, secp256k1_generator_const_h, nonce, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_rewind(ctx, proof_without_optional, 0, None, secp256k1_generator_const_h, nonce, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_rewind(ctx, proof_without_optional, 0, 'string', secp256k1_generator_const_h, nonce, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_rewind(ctx, proof_without_optional, 0, commit, None, nonce, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_rewind(ctx, proof_without_optional, 0, commit, 'string', nonce, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_rewind(ctx, proof_without_optional, 0, commit, secp256k1_generator_const_h, None, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_rewind(ctx, proof_without_optional, 0, commit, secp256k1_generator_const_h, 'string', None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_rewind(ctx, proof_without_optional, 0, commit, secp256k1_generator_const_h, nonce, 'string')

    # Test rewinding Bulletproof with invalid values
    with pytest.raises(OverflowError):
        secp256k1_bulletproof_rangeproof_rewind(ctx, proof_without_optional, -1, commit, secp256k1_generator_const_h, nonce, None)
    with pytest.raises(OverflowError):
        secp256k1_bulletproof_rangeproof_rewind(ctx, proof_without_optional, 0x10000000000000000, commit, secp256k1_generator_const_h, nonce, None)

def test_secp256k1_bulletproof_rangeproof_prove():
    # Test creating Bulletproof without optional
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    scratch = secp256k1_scratch_space_create(ctx, 30720)
    assert scratch is not None
    gens = secp256k1_bulletproof_generators_create(ctx, secp256k1_generator_const_g, 256)
    assert gens is not None
    value = [123456789]
    valid_blind = [bytes.fromhex('59e721189cf77b5fcd6c7247ef8b997f66379e85218c2115f25d8cdbb50faa1a')]
    nonce = bytes.fromhex('7e13a050ece0a11106b984b66dbe5b597af212c539404e87d18aa4ba1d4a2fa6')
    proof_without_optional = secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, None, None, None, value, None, valid_blind, None, secp256k1_generator_const_h, 64, nonce, None, None, None)
    assert proof_without_optional == bytes.fromhex('06c8d2140622ecdccad4a2810d4ec58939852e41606b456cf0fb34933e330dbe41890912a82a2d2bce57526df7988be80090a93f17ed093392d3c660aabae6880f5a35bd7843cd92b90b235eee1c886e6b294e4bfb84d1e932f464e693a0e74fdcb38908f46cfb166a26ce8ef64bc82b04b8906b43c8ee545f7f488c641997abb1b05d571bd913884b44d1954e42bfed4c743d93efb9e5c11e7f8983bf5e74f80070230676af6ef835023c9b42074d0404c69471d14b1b70e881e57d0c7edc5bad81904085700a11966c2017920dc4b0e443c0eec2c70ca5c9f2440457e36ed4bc77d9a0a995cc4d2503f8dded0db4031a8dcba32f5532598084b445aa081bd77c6a92cb77bb4b9fa72da67cce6ef2c95cc8a6cead1b1ae211d81964085f957f3d06f6a90a6a87f71ccc2cfabf2e5af741c24abf5cec063883909c3394d6967b419bf8f80132cf636c3c9b5afec6351dd18b85f556cbe560fd7ca4c359202948dc3902fa6abf8a55a65ce7cf28b91b2f107daf1fe37b9e9195fdf56fd7ba4c146fe9f4cf538b4666e47f594f81567ce4fdf2842b71be8618af11e6881e328c52a7fa3d874a138ee62ac2bfc23a6e82e6982901751277843f0f03bb40e99eb02b0a87d3768409603cd2fa24255d2765a27774cce3bffd2a0f76e903bfae9ff0de19ecd0e6d92b590f1ff7c648a2c0685834af56d23b45465fc893728326c524c2c50abbbb1b506159a7a7098061ccf3972d5df786538589f5921a1922c44ac329734bfa3821e39ecc93f7f1a9cb8a0f9fb5165df024e001ebb9107b04f5889799fe0ecf6fe2190c70b524a6f843a280992148031349aef170a684bf2c8ca424e68d9a99a96af130de9ce97285490358d75e188e6a0f53af4651626bbab059825f8812b669a44604eaa8d7dc8b3d646b2eb7601c7e1e4fb62b0b83490d78ed4d30255c2d')

    # Test creating Bulletproof with min value
    min_value = [123]
    proof_with_min_value = secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, None, None, None, value, min_value, valid_blind, None, secp256k1_generator_const_h, 64, nonce, None, None, None)
    assert proof_with_min_value == bytes.fromhex('fd0c2425873f3e2c6a1179c0ee14854089fa018c632ad21623e848b141cf4bf97ee1e7e72c7bc8562c9f530988d7c0c8eb631f08ea9b8cd5a24de2dde33d4eff07ad313720393e57b84c8724dd2d281ed60b0ad1c2e4754b1426e3fcfdea99338db38908f46cfb166a26ce8ef64bc82b04b8906b43c8ee545f7f488c641997abb1ffebfe8cde7d9beedc473afa9af14824f4dbc42464894580cae487fe65cda1511ad1bbd49f580f6951d1adde3f4a9708168ac179eea55f71b72eb6061e7c508482106c1eb365343e0df725203088472cb12f34357ee3760315704c5f949876a765cfc9915a577cd6270e8989c4c74d258d2e7bcaacd4fa9976686ffe72a0b27053a34d1b3e13071144bc32290422ec9430419a20e7465a5ea6b9b1a37b06232e6866869d1d762dbceead851aced160a1709c7db579094a83d3c5a045738bb246b626ac5b99bd0933cdd3d88c9d09562fd971ceed6cb8bd599901422e16ecee02bc013ac6fba47db5497591c55c34e74f40e1bbd0590e1124baea042b85c4fbcd62a5f0d595c21ac5f308a04496091f85bbe03789a98e1f6ad1001b5385f075db00df75e3df5c5b93ff52f70132c1bc0350b453dcae3cf1b205cb1ba5fc6d29be107e29e20cfba13b7eb816be6a13697944500fee6eb8fe27b1e179174304020f817fd99086c14948b2ac93cddbea61337ae4a164bf4a60b133258b28f71d69e881901efd034a36655fc614315f21ccc97f129f0842303b51d46126c56468f8210eec9ecde6dd58991bb21e171048b27f5eaefeb306d39dce7fc89db43036dedf9049023e5366489c6a7af4ee646ec6ed65e2e79df7182a98fd17d27e6ad438387853b595481a12e1db328453b54fe548ee2336e3ebeec5b6a9b7a450879e949f6fa035db4ff51457bf8bb49c15c764601666e3536ac62f9aae504118dd414f6161e6')

    # Test creating Bulletproof with private nonce
    private_nonce = bytes.fromhex('6e3c862278e1b92b6567c41a77ca1814efe0b3bec411ea1ac61b4a2cca6a1942')
    proof_with_private_nonce = secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, None, None, None, value, None, valid_blind, None, secp256k1_generator_const_h, 64, nonce, private_nonce, None, None)
    assert proof_with_private_nonce == bytes.fromhex('6f85e62c82042be6cf361cc21f25f6f8cd1b83aad47a2e198e44b7a1f89c0a36b77d6767c9bb48f349924407967e47cab5674c701e3cb7574e52d5b3f085d5550b5a35bd7843cd92b90b235eee1c886e6b294e4bfb84d1e932f464e693a0e74fdcb38908f46cfb166a26ce8ef64bc82b04b8906b43c8ee545f7f488c641997abb1b2027ac78947cad164af1b7c11f3813dd143da15b668b4b2978df8a3ff3263feeae54cdb13b013afd80697aa2136ab3b2ee46ffd9d8a7955a0fec799eafc9299a6e9447af1e843712b4142f9fb99fce887af48b6c73b8b73ca2e65f6cbcba86450e5ae729e217c4f1efb437dfc10c5434455d5fe4f78bd12964504c355021f272ecf106fb0d2e4511b3d9ea03c6b0215b8dfddbf62e5594243457af38e68c15f0a711e29ab20f0804d23c987c34e92898fa2700826514f9e06515756615b2adde1fdb0b2966212f8983a335f9f8aaf6c87d385799a51f33015b9a74d34b95fe9e9001e813db554bbf655116249cd67a4c74c38f39fed662cf135536070932b777063116b44bbb76b7d50971937b6d7a847f39ac8adf7e01a23a0468332bac2b40645bf54581ae0fdf673daffcd08a1b931f4d492fddeccd3c3ce5b7f9a78a5bc2a9c10acfb2bf1c0aa52f5c463da72c66aea001ebd8efb06238101d4786a92c54b30ed8a2eaf101006bd5d913eaf008b6360733cbffd12c211c210a7703aa78eea036cafcde6707dac0d02b2862578c3e22e8100d7bad44f75f655f7b59c1ca0fca40ed300ac53fe1eef992ee216d6abc2e46482b9056bb1388991df9e478a840c2012ce30f0bfed0048b9b587ebcd2fbcd8372d13e82963ebef3dcb7b92c9fd92af3fe4cb7c3cbefd47428d05147758e82b7fb101765cc2fce7cee269f0707d06740a5f9198a6276c3560264ddc2080d70a714ed48dba8fc852852ad5564d825b0b')

    # Test creating Bulletproof with extra commit
    extra_commit = bytes.fromhex('060708090a')
    proof_with_extra_commit = secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, None, None, None, value, None, valid_blind, None, secp256k1_generator_const_h, 64, nonce, None, extra_commit, None)
    assert proof_with_extra_commit == bytes.fromhex('0251e002750d5d48327b04ea82b8249ad3e25068dc1a5cda47f46baf3fe0f5052f81130bf2f1cf44cdab9a1b21ba17b3bf7a77dca77c450fd728ea47fb8ec42a0f5a35bd7843cd92b90b235eee1c886e6b294e4bfb84d1e932f464e693a0e74fdcb38908f46cfb166a26ce8ef64bc82b04b8906b43c8ee545f7f488c641997abb14243b252262a2daee092fc6bd1b3a039dffdaaf6826affcbaf57194a41b60fb04ec4c81f1d3e215cef3be8961f8947651b2c254ce5736f1a6d8448f896b729db09ef59acd164be40de422644263b7ab9a668cbb819c154b7c34b85c7339ee91071335f56959b086a856e885a69140d6e675522d31918e086744e098c60b5cdad729d6e5f9959be4d99c14cb46083cd27caad7644c1803bf809d4ca256a11083045d876fa84b8d9ae7a0570d44b1dd82b16d0b8c8f77207d050b13c83a591df3634b53d6584302897cf0b9f82a3a1cc00cd34c5855f6b043d334aa4be1ea6fac80801b0f829e5aa2c9cad2c1f7b9958cb435a8aa1ee08b5e541bf55e607a0dc3137a399d362fb1a98b86fe1d16907b25dd5f4a943217b0015709233c01dc63f62814e60269cf2ca27b32c10bc988e3c7de52d0d04e3889266bb780adad315376a10c4e40aa814a82dfc93735db829353af33c138ea25a6857c9f0ef59831145c15155d4d448b35f02ba92e24940187f4f37695155ef943dd1f55474d9e63993b6a5bc13073e05260187fc9db14df2500e476de97e673b9e498d552f752cb573191888d5560a1c054f93c5950e6fecbb1808f34fa9ab00be3d4cfa6f4363c4df3dea72beaa00bdd8ad02235a79cbe238c69dc05e6cfc69c6578cd8bc95cd45d69ff76b472ee6babe9d119835d67bce6515d22b39e3d6950d06c8054df7c986e9da4764c6c44fe1e0c4f5ca16b63567e61b6f0d4e57fa4360884bd5c60b1a9a42d28055')

    # Test creating Bulletproof with message
    message = bytes.fromhex('000102030405060708090a0b0c0d0e0f10111213')
    proof_with_message = secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, None, None, None, value, None, valid_blind, None, secp256k1_generator_const_h, 64, nonce, None, None, message)
    assert proof_with_message == bytes.fromhex('d679da5ef802338b14cac935ea99def5dc0d399db1435ac429863c9eb5b46b10682aaa885cbeb0e24846563a0093f35c75825da857145055259da7e3578492f2073af8080a30bc542f4293c15ecc522afd249b3b6ee2506f21b019653ad919a6b5b38908f46cfb166a26ce8ef64bc82b04b8906b43c8ee545f7f488c641997abb15ead216511e600f5c48eb55e1c7ab865e79282f0978b50d720e37bbba46786f91c28f8b5abf8127c0743b9adcb6bab89f6007af97802c7a97bfd997753e29cf1716245df5def5e5a50ff9aecebc9d8061e4d1137a9ff344be842451d29bd438c35c03827e4c6bfe144b333c557139b71fe6b94117cf8cc2c77848cb05953d4bf2fd0563a07bf140e968c0fcfbc0ec111f87b1b9317db3a09ab18beba67138b71c84fd7943cfa5164f088544077e27c8cd759dc5792d457795cd29abc8335f293c2f1d5090963e9d353be19b2e689099f84fdbbfae413c15ca5239e5b7886a7b11601c2ced7f23e2f4042fd1ec9b6c3445a61c35d04a74f64166e36abb5f016b47d5ca7ad8c9864e677109d0217437dc20a7be40af4d165b5e0c4aa031bc8374218f99591b4dcfd2e08702b367c1fa63aed73a9a2c39eed17494c582ced3f699183a3bacbb1147b7a61ec35d847f1644737650f9bfa82b4061b63ef6a85eee6f471b6bedc9aeacbe2049664c97774d75c64e807e5c4cef1d20c34b0bf1baddd32ee8dd4d48a4cec1df83409156744c2debf3dc0879bc1e3b4b84bb2bc7b05ac4039b685facd66a6b518c60d85d8a29beef645ab8bda8dae048336c5bfb6382b8edbc6b539e3a935cb892ae3cdaf314222d105f4f007b040eb9b7add48369e17700f0993379064b616a97df576e027c6d2f5eccb3b12543e3f1287595a390710c07dc5982aceb0c71ec2042505c3de900a7a47a06eaffd0134db9b879ac9dddf6676e0')

    # Test creating Bulletproof with all
    proof_with_all = secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, None, None, None, value, min_value, valid_blind, None, secp256k1_generator_const_h, 64, nonce, private_nonce, extra_commit, message)
    assert proof_with_all == bytes.fromhex('95f292afea38c42d053e503b46a9600d1d44f2cd566a9e030a62960f260b89a8aaaa386827f063738167d916015341663b532c59d5aa1a6713608302280658e30eb492e9bab887066e0aceaa501f716ba9df4081d9ba497460b398b9bc6167e95bb38908f46cfb166a26ce8ef64bc82b04b8906b43c8ee545f7f488c641997abb1dd9d24a3fe1dc9b88ca2fe8c98d692176fae8c11d731ab9c7e5b3eaf9086d2de378f5dc3e07fca8b0aa09fee3ed3a0f862a1ccbebeeaf73b88e58f4571fd30b17c557f8a177c8cb9280f9abfc1097ba05c942122f4cce2fc9b5251e53c8bbf8a061fef8de33b01ab889687e97d543b6b85e7025ae1c309236904b095c5066da7991fce135bd89752e313e042e93f123f676a2dd7cc74c09963dd6838bfcb17ea40230d733a23ec8c75e43192d8072815068ec2a4ed57916e1be64218ce3bf27fc417c5385f37623cf38135e5ed8d42a728be2ef8688f4e02e68f885954507e5c0a03b43bc0fc5c5582be00e1eae5a5570c38d053712ba6e5cafb15e81e6469f4506634d1ea9748678b66cfe3617ade01125dae972e06c79f6113048f2270023a4c2b46c918b594cce02f8e4f43daef8682c2bb8ca8a7640ced2ad7e8fcd2291eb5c316c7944ea8906decba92c0275accc1480a1508133558b9a9af9f8654b87b6e3590892887cbd77a350ce047e693e746edde2288d620070d2f73cd669ddabb7542b6a8194d1d509a04055a11cf08bb3cf83771f1967399fb6a9a43ab220025eae94935f78501da2a41262700c9f0b2c49c787e30cd71e6edea72e2f92063922235b17ffa7093ed6cc34910011e33596c5ecd69e15599a83914205ef02011af2d8ef6d6fc42abe399758306a2211dd58773799b7eea354e747442a999f7c772d6c92e75b0f2779c720f70a29adab0d432b04d4f10113d8e4aeb6ff86a679a84c38a')

    # Test creating invalid Bulletproof
    invalid_blind = [bytes.fromhex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')]
    invalid_proof = secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, None, None, None, value, None, invalid_blind, None, secp256k1_generator_const_h, 64, nonce, None, None, None)
    assert invalid_proof is None

    # Test creating Bulletproof with invalid types
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_prove(None, scratch, gens, None, None, None, value, None, valid_blind, None, secp256k1_generator_const_h, 64, nonce, None, None, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_prove('string', scratch, gens, None, None, None, value, None, valid_blind, None, secp256k1_generator_const_h, 64, nonce, None, None, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_prove(ctx, None, gens, None, None, None, value, None, valid_blind, None, secp256k1_generator_const_h, 64, nonce, None, None, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_prove(ctx, 'string', gens, None, None, None, value, None, valid_blind, None, secp256k1_generator_const_h, 64, nonce, None, None, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_prove(ctx, scratch, None, None, None, None, value, None, valid_blind, None, secp256k1_generator_const_h, 64, nonce, None, None, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_prove(ctx, scratch, 'string', None, None, None, value, None, valid_blind, None, secp256k1_generator_const_h, 64, nonce, None, None, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, 'string', None, None, value, None, valid_blind, None, secp256k1_generator_const_h, 64, nonce, None, None, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, None, 'string', None, value, None, valid_blind, None, secp256k1_generator_const_h, 64, nonce, None, None, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, None, None, 'string', value, None, valid_blind, None, secp256k1_generator_const_h, 64, nonce, None, None, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, None, None, None, None, None, valid_blind, None, secp256k1_generator_const_h, 64, nonce, None, None, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, None, None, None, 'string', None, valid_blind, None, secp256k1_generator_const_h, 64, nonce, None, None, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, None, None, None, ['1', '2', '3'], None, valid_blind, None, secp256k1_generator_const_h, 64, nonce, None, None, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, None, None, None, value, 'string', valid_blind, None, secp256k1_generator_const_h, 64, nonce, None, None, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, None, None, None, value, ['1', '2', '3'], valid_blind, None, secp256k1_generator_const_h, 64, nonce, None, None, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, None, None, None, value, None, None, None, secp256k1_generator_const_h, 64, nonce, None, None, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, None, None, None, value, None, 'string', None, secp256k1_generator_const_h, 64, nonce, None, None, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, None, None, None, value, None, [1, 2, 3], None, secp256k1_generator_const_h, 64, nonce, None, None, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, None, None, None, value, None, valid_blind, 'string', secp256k1_generator_const_h, 64, nonce, None, None, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, None, None, None, value, None, valid_blind, [1, 2, 3], secp256k1_generator_const_h, 64, nonce, None, None, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, None, None, None, value, None, valid_blind, None, None, 64, nonce, None, None, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, None, None, None, value, None, valid_blind, None, 'string', 64, nonce, None, None, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, None, None, None, value, None, valid_blind, None, secp256k1_generator_const_h, None, nonce, None, None, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, None, None, None, value, None, valid_blind, None, secp256k1_generator_const_h, 'string', nonce, None, None, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, None, None, None, value, None, valid_blind, None, secp256k1_generator_const_h, 64, None, None, None, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, None, None, None, value, None, valid_blind, None, secp256k1_generator_const_h, 64, 'string', None, None, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, None, None, None, value, None, valid_blind, None, secp256k1_generator_const_h, 64, nonce, 'string', None, None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, None, None, None, value, None, valid_blind, None, secp256k1_generator_const_h, 64, nonce, None, 'string', None)
    with pytest.raises(TypeError):
        secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, None, None, None, value, None, valid_blind, None, secp256k1_generator_const_h, 64, nonce, None, None, 'string')

    # Test creating Bulletproof with invalid values
    with pytest.raises(OverflowError):
        secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, None, None, None, [-1], None, valid_blind, None, secp256k1_generator_const_h, 64, nonce, None, None, None)
    with pytest.raises(OverflowError):
        secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, None, None, None, [0x10000000000000000], None, valid_blind, None, secp256k1_generator_const_h, 64, nonce, None, None, None)
    with pytest.raises(OverflowError):
        secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, None, None, None, value, [-1], valid_blind, None, secp256k1_generator_const_h, 64, nonce, None, None, None)
    with pytest.raises(OverflowError):
        secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, None, None, None, value, [0x10000000000000000], valid_blind, None, secp256k1_generator_const_h, 64, nonce, None, None, None)
    with pytest.raises(OverflowError):
        secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, None, None, None, value, None, valid_blind, None, secp256k1_generator_const_h, -1, nonce, None, None, None)
    with pytest.raises(OverflowError):
        secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, None, None, None, value, None, valid_blind, None, secp256k1_generator_const_h, 0x10000000000000000, nonce, None, None, None)

def test_secp256k1_pedersen_commitment_parse():
    # Test parsing Pedersen commit
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    valid_input = bytes.fromhex('08883a3f816419d4ce5bf44e320c24c5b09b0621c70fb780d7a35c86570bd35475')
    valid_commit = secp256k1_pedersen_commitment_parse(ctx, valid_input)
    assert valid_commit is not None

    # Test parsing invalid Pedersen commit
    invalid_input = bytes.fromhex('18883a3f816419d4ce5bf44e320c24c5b09b0621c70fb780d7a35c86570bd35475')
    invalid_commit = secp256k1_pedersen_commitment_parse(ctx, invalid_input)
    assert invalid_commit is None

    # Test parsing Pedersen commit with invalid types
    with pytest.raises(TypeError):
        secp256k1_pedersen_commitment_parse(None, valid_input)
    with pytest.raises(TypeError):
        secp256k1_pedersen_commitment_parse('string', valid_input)
    with pytest.raises(TypeError):
        secp256k1_pedersen_commitment_parse(ctx, None)
    with pytest.raises(TypeError):
        secp256k1_pedersen_commitment_parse(ctx, 'string')

def test_secp256k1_pedersen_commitment_serialize():
    # Test serializing Pedersen commit
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    input = bytes.fromhex('08883a3f816419d4ce5bf44e320c24c5b09b0621c70fb780d7a35c86570bd35475')
    commit = secp256k1_pedersen_commitment_parse(ctx, input)
    assert commit is not None
    output = secp256k1_pedersen_commitment_serialize(ctx, commit)
    assert output == input

    # Test serializing Pedersen commit with invalid types
    with pytest.raises(TypeError):
        secp256k1_pedersen_commitment_serialize(None, commit)
    with pytest.raises(TypeError):
        secp256k1_pedersen_commitment_serialize('string', commit)
    with pytest.raises(TypeError):
        secp256k1_pedersen_commitment_serialize(ctx, None)
    with pytest.raises(TypeError):
        secp256k1_pedersen_commitment_serialize(ctx, 'string')

def test_secp256k1_pedersen_commit():
    # Test creating Pedersen commit
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    valid_blind = bytes.fromhex('8c3882fbd7966085e760e000b1ea9eb1ad3df1eec02e720adaa5104c6bd9fd88')
    value = 123456789
    valid_commit = secp256k1_pedersen_commit(ctx, valid_blind, value, secp256k1_generator_const_h, secp256k1_generator_const_g)
    assert valid_commit is not None
    output = secp256k1_pedersen_commitment_serialize(ctx, valid_commit)
    assert output == bytes.fromhex('08883a3f816419d4ce5bf44e320c24c5b09b0621c70fb780d7a35c86570bd35475')

    # Test creating invalid Pedersen commit
    invalid_blind = bytes.fromhex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
    invalid_commit = secp256k1_pedersen_commit(ctx, invalid_blind, value, secp256k1_generator_const_h, secp256k1_generator_const_g)
    assert invalid_commit is None

    # Test serializing Pedersen commit with invalid types
    with pytest.raises(TypeError):
        secp256k1_pedersen_commit(None, valid_blind, value, secp256k1_generator_const_h, secp256k1_generator_const_g)
    with pytest.raises(TypeError):
        secp256k1_pedersen_commit('string', valid_blind, value, secp256k1_generator_const_h, secp256k1_generator_const_g)
    with pytest.raises(TypeError):
        secp256k1_pedersen_commit(ctx, None, value, secp256k1_generator_const_h, secp256k1_generator_const_g)
    with pytest.raises(TypeError):
        secp256k1_pedersen_commit(ctx, 'string', value, secp256k1_generator_const_h, secp256k1_generator_const_g)
    with pytest.raises(TypeError):
        secp256k1_pedersen_commit(ctx, valid_blind, None, secp256k1_generator_const_h, secp256k1_generator_const_g)
    with pytest.raises(TypeError):
        secp256k1_pedersen_commit(ctx, valid_blind, 'string', secp256k1_generator_const_h, secp256k1_generator_const_g)
    with pytest.raises(TypeError):
        secp256k1_pedersen_commit(ctx, valid_blind, value, None, secp256k1_generator_const_g)
    with pytest.raises(TypeError):
        secp256k1_pedersen_commit(ctx, valid_blind, value, 'string', secp256k1_generator_const_g)
    with pytest.raises(TypeError):
        secp256k1_pedersen_commit(ctx, valid_blind, value, secp256k1_generator_const_h, None)
    with pytest.raises(TypeError):
        secp256k1_pedersen_commit(ctx, valid_blind, value, secp256k1_generator_const_h, 'string')

    # Test serializing Pedersen commit with invalid values
    with pytest.raises(OverflowError):
        secp256k1_pedersen_commit(ctx, valid_blind, -1, secp256k1_generator_const_h, secp256k1_generator_const_g)
    with pytest.raises(OverflowError):
        secp256k1_pedersen_commit(ctx, valid_blind, 0x10000000000000000, secp256k1_generator_const_h, secp256k1_generator_const_g)

def test_secp256k1_pedersen_blind_commit():
    # Test creating Pedersen commit with blinding factors
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    valid_blind = bytes.fromhex('8c3882fbd7966085e760e000b1ea9eb1ad3df1eec02e720adaa5104c6bd9fd88')
    value = bytes.fromhex('18883a3f816419d4ce5bf44e320c24c5b09b0621c70fb780d7a35c86570bd354')
    valid_commit = secp256k1_pedersen_blind_commit(ctx, valid_blind, value, secp256k1_generator_const_h, secp256k1_generator_const_g)
    assert valid_commit is not None
    output = secp256k1_pedersen_commitment_serialize(ctx, valid_commit)
    assert output == bytes.fromhex('086321a9fc1d1fb9dc81256cf1c3119404bb5a57f178ce062b76f820afab278052')

    # Test creating invalid Pedersen commit with blinding factors
    invalid_blind = bytes.fromhex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
    invalid_commit = secp256k1_pedersen_blind_commit(ctx, invalid_blind, value, secp256k1_generator_const_h, secp256k1_generator_const_g)
    assert invalid_commit is None

    # Test creating invalid Pedersen commit with blinding factors with invalid types
    with pytest.raises(TypeError):
        secp256k1_pedersen_blind_commit(None, valid_blind, value, secp256k1_generator_const_h, secp256k1_generator_const_g)
    with pytest.raises(TypeError):
        secp256k1_pedersen_blind_commit('string', valid_blind, value, secp256k1_generator_const_h, secp256k1_generator_const_g)
    with pytest.raises(TypeError):
        secp256k1_pedersen_blind_commit(ctx, None, value, secp256k1_generator_const_h, secp256k1_generator_const_g)
    with pytest.raises(TypeError):
        secp256k1_pedersen_blind_commit(ctx, 'string', value, secp256k1_generator_const_h, secp256k1_generator_const_g)
    with pytest.raises(TypeError):
        secp256k1_pedersen_blind_commit(ctx, valid_blind, None, secp256k1_generator_const_h, secp256k1_generator_const_g)
    with pytest.raises(TypeError):
        secp256k1_pedersen_blind_commit(ctx, valid_blind, 'string', secp256k1_generator_const_h, secp256k1_generator_const_g)
    with pytest.raises(TypeError):
        secp256k1_pedersen_blind_commit(ctx, valid_blind, value, None, secp256k1_generator_const_g)
    with pytest.raises(TypeError):
        secp256k1_pedersen_blind_commit(ctx, valid_blind, value, 'string', secp256k1_generator_const_g)
    with pytest.raises(TypeError):
        secp256k1_pedersen_blind_commit(ctx, valid_blind, value, secp256k1_generator_const_h, None)
    with pytest.raises(TypeError):
        secp256k1_pedersen_blind_commit(ctx, valid_blind, value, secp256k1_generator_const_h, 'string')

def test_secp256k1_pedersen_blind_sum():
    # Test creating blind sum
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    valid_blinds = [bytes.fromhex('8c3882fbd7966085e760e000b1ea9eb1ad3df1eec02e720adaa5104c6bd9fd88'), bytes.fromhex('f843522f6bba1da1414e29be6a37e6c56a082e9daa2447c643285641dd7d29ec'), bytes.fromhex('bc105e8a86a81ab8628b8f71b61c4730b99e781ec816e5d7f9fef49362988bac'), bytes.fromhex('ea211855556afb5918e0108bee6a08191391cdb2ac5bd0f7c6a57fc96ce823f2'), bytes.fromhex('5d38fd6223fb320806dac8e6e53b3c987633eab671adde83977378322122f1fc')]
    valid_blind_out = secp256k1_pedersen_blind_sum(ctx, valid_blinds, 3)
    assert valid_blind_out == bytes.fromhex('f9321dfe50926b7e6b7fbfbdfe9987f6471ee042145ff02db9b363261de49d32')

    # Test creating invalid blind sum
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    invalid_blinds = [bytes.fromhex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'), bytes.fromhex('f843522f6bba1da1414e29be6a37e6c56a082e9daa2447c643285641dd7d29ec'), bytes.fromhex('bc105e8a86a81ab8628b8f71b61c4730b99e781ec816e5d7f9fef49362988bac'), bytes.fromhex('ea211855556afb5918e0108bee6a08191391cdb2ac5bd0f7c6a57fc96ce823f2'), bytes.fromhex('5d38fd6223fb320806dac8e6e53b3c987633eab671adde83977378322122f1fc')]
    invalid_blind_out = secp256k1_pedersen_blind_sum(ctx, invalid_blinds, 3)
    assert invalid_blind_out is None

    # Test creating blind sum with invalid types
    with pytest.raises(TypeError):
        secp256k1_pedersen_blind_sum(None, valid_blinds, 3)
    with pytest.raises(TypeError):
        secp256k1_pedersen_blind_sum('string', valid_blinds, 3)
    with pytest.raises(TypeError):
        secp256k1_pedersen_blind_sum(ctx, None, 3)
    with pytest.raises(TypeError):
        secp256k1_pedersen_blind_sum(ctx, 'string', 3)
    with pytest.raises(TypeError):
        secp256k1_pedersen_blind_sum(ctx, [1, 2, 3], 3)
    with pytest.raises(TypeError):
        secp256k1_pedersen_blind_sum(ctx, valid_blinds, None)
    with pytest.raises(TypeError):
        secp256k1_pedersen_blind_sum(ctx, valid_blinds, 'string')

    # Test creating blind sum with invalid values
    with pytest.raises(OverflowError):
        secp256k1_pedersen_blind_sum(ctx, valid_blinds, -1)
    with pytest.raises(OverflowError):
        secp256k1_pedersen_blind_sum(ctx, valid_blinds, 0x10000000000000000)

def test_secp256k1_pedersen_commit_sum():
    # Test creating Pedersen commit sum
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    commits = [secp256k1_pedersen_commitment_parse(ctx, bytes.fromhex('08883a3f816419d4ce5bf44e320c24c5b09b0621c70fb780d7a35c86570bd35475')), secp256k1_pedersen_commitment_parse(ctx, bytes.fromhex('09a43fdf9cf1efe77d6e328a9022ddf9fceb2004e2dccf0696397542ed9c6a6143')), secp256k1_pedersen_commitment_parse(ctx, bytes.fromhex('094b21d96556ac5e91c52fbeec4621ecf108910702f8b8aea3197b838b755b0121'))]
    assert all(commit is not None for commit in commits)
    ncommits = [secp256k1_pedersen_commitment_parse(ctx, bytes.fromhex('08bc56846cf0992abc1bbb6f267dfba69390a89f6df4c56f38bec18b84df145725')), secp256k1_pedersen_commitment_parse(ctx, bytes.fromhex('08e59f38d0e656ef1dc658554b668056f6d90d555de60af46b5fae1c5983823770'))]
    assert all(ncommit is not None for ncommit in ncommits)
    commit_out = secp256k1_pedersen_commit_sum(ctx, commits, ncommits)
    assert commit_out is not None
    output = secp256k1_pedersen_commitment_serialize(ctx, commit_out)
    assert output == bytes.fromhex('09463d0dbc015d6724fec38d0b29eff8fddd1f6a65460a4ca3a394904d59db6125')

    # Test creating Pedersen commit sum with invalid types
    with pytest.raises(TypeError):
        secp256k1_pedersen_commit_sum(None, commits, ncommits)
    with pytest.raises(TypeError):
        secp256k1_pedersen_commit_sum('string', commits, ncommits)
    with pytest.raises(TypeError):
        secp256k1_pedersen_commit_sum(ctx, None, ncommits)
    with pytest.raises(TypeError):
        secp256k1_pedersen_commit_sum(ctx, 'string', ncommits)
    with pytest.raises(TypeError):
        secp256k1_pedersen_commit_sum(ctx, [1, 2, 3], ncommits)
    with pytest.raises(TypeError):
        secp256k1_pedersen_commit_sum(ctx, commits, None)
    with pytest.raises(TypeError):
        secp256k1_pedersen_commit_sum(ctx, commits, 'string')
    with pytest.raises(TypeError):
        secp256k1_pedersen_commit_sum(ctx, commits, [1, 2, 3])

def test_secp256k1_pedersen_verify_tally():
    # Test tallying Pedersen commits
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    pos = [secp256k1_pedersen_commitment_parse(ctx, bytes.fromhex('08883a3f816419d4ce5bf44e320c24c5b09b0621c70fb780d7a35c86570bd35475')), secp256k1_pedersen_commitment_parse(ctx, bytes.fromhex('09a43fdf9cf1efe77d6e328a9022ddf9fceb2004e2dccf0696397542ed9c6a6143')), secp256k1_pedersen_commitment_parse(ctx, bytes.fromhex('094b21d96556ac5e91c52fbeec4621ecf108910702f8b8aea3197b838b755b0121'))]
    assert all(commit is not None for commit in pos)
    valid_neg = [secp256k1_pedersen_commitment_parse(ctx, bytes.fromhex('08883a3f816419d4ce5bf44e320c24c5b09b0621c70fb780d7a35c86570bd35475')), secp256k1_pedersen_commitment_parse(ctx, bytes.fromhex('09a43fdf9cf1efe77d6e328a9022ddf9fceb2004e2dccf0696397542ed9c6a6143')), secp256k1_pedersen_commitment_parse(ctx, bytes.fromhex('094b21d96556ac5e91c52fbeec4621ecf108910702f8b8aea3197b838b755b0121'))]
    assert all(ncommit is not None for ncommit in valid_neg)
    valid_result = secp256k1_pedersen_verify_tally(ctx, pos, valid_neg)
    assert valid_result is True

    # Test tallying invalid Pedersen commits
    invalid_neg = [secp256k1_pedersen_commitment_parse(ctx, bytes.fromhex('08bc56846cf0992abc1bbb6f267dfba69390a89f6df4c56f38bec18b84df145725')), secp256k1_pedersen_commitment_parse(ctx, bytes.fromhex('08e59f38d0e656ef1dc658554b668056f6d90d555de60af46b5fae1c5983823770'))]
    assert all(ncommit is not None for ncommit in invalid_neg)
    invalid_result = secp256k1_pedersen_verify_tally(ctx, pos, invalid_neg)
    assert invalid_result is False

    # Test tallying Pedersen commits with invalid types
    with pytest.raises(TypeError):
        secp256k1_pedersen_verify_tally(None, pos, valid_neg)
    with pytest.raises(TypeError):
        secp256k1_pedersen_verify_tally('string', pos, valid_neg)
    with pytest.raises(TypeError):
        secp256k1_pedersen_verify_tally(ctx, None, valid_neg)
    with pytest.raises(TypeError):
        secp256k1_pedersen_verify_tally(ctx, 'string', valid_neg)
    with pytest.raises(TypeError):
        secp256k1_pedersen_verify_tally(ctx, [1, 2, 3], valid_neg)
    with pytest.raises(TypeError):
        secp256k1_pedersen_verify_tally(ctx, pos, None)
    with pytest.raises(TypeError):
        secp256k1_pedersen_verify_tally(ctx, pos, 'string')
    with pytest.raises(TypeError):
        secp256k1_pedersen_verify_tally(ctx, pos, [1, 2, 3])

def test_secp256k1_pedersen_blind_generator_blind_sum():
    # Test getting blind generator blind sum
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    value = [123456789, 59283]
    valid_generator_blind = [bytes.fromhex('8c3882fbd7966085e760e000b1ea9eb1ad3df1eec02e720adaa5104c6bd9fd88'), bytes.fromhex('504630d1a004eb039bd9338353068250bbc4b4ddea6b80ac1c315eac1f16dba1')]
    blinding_factor = [bytes.fromhex('f843522f6bba1da1414e29be6a37e6c56a082e9daa2447c643285641dd7d29ec'), bytes.fromhex('6cd08165a8a5c9728f1d608d3eb4a5c90f28170ace7eb369c51ec3885fe42df5')]
    valid_final_blinding_factor = secp256k1_pedersen_blind_generator_blind_sum(ctx, value, valid_generator_blind, blinding_factor, 1)
    assert valid_final_blinding_factor == bytes.fromhex('bdd94bd02c64f3c1f989acafa13ba6d0a83416e54f8e6f1d554aee69dc3df27e')

    # Test getting invalid blind generator blind sum
    invalid_generator_blind = [bytes.fromhex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')]
    invalid_final_blinding_factor = secp256k1_pedersen_blind_generator_blind_sum(ctx, value, invalid_generator_blind, blinding_factor, 1)
    assert invalid_final_blinding_factor is None

    # Test getting blind generator blind sum with invalid types
    with pytest.raises(TypeError):
        secp256k1_pedersen_blind_generator_blind_sum(None, value, valid_generator_blind, blinding_factor, 1)
    with pytest.raises(TypeError):
        secp256k1_pedersen_blind_generator_blind_sum('string', value, valid_generator_blind, blinding_factor, 1)
    with pytest.raises(TypeError):
        secp256k1_pedersen_blind_generator_blind_sum(ctx, None, valid_generator_blind, blinding_factor, 1)
    with pytest.raises(TypeError):
        secp256k1_pedersen_blind_generator_blind_sum(ctx, 'string', valid_generator_blind, blinding_factor, 1)
    with pytest.raises(TypeError):
        secp256k1_pedersen_blind_generator_blind_sum(ctx, value, None, blinding_factor, 1)
    with pytest.raises(TypeError):
        secp256k1_pedersen_blind_generator_blind_sum(ctx, value, 'string', blinding_factor, 1)
    with pytest.raises(TypeError):
        secp256k1_pedersen_blind_generator_blind_sum(ctx, value, [1, 2, 3], blinding_factor, 1)
    with pytest.raises(TypeError):
        secp256k1_pedersen_blind_generator_blind_sum(ctx, value, valid_generator_blind, None, 1)
    with pytest.raises(TypeError):
        secp256k1_pedersen_blind_generator_blind_sum(ctx, value, valid_generator_blind, 'string', 1)
    with pytest.raises(TypeError):
        secp256k1_pedersen_blind_generator_blind_sum(ctx, value, valid_generator_blind, [1, 2, 3], 1)
    with pytest.raises(TypeError):
        secp256k1_pedersen_blind_generator_blind_sum(ctx, value, valid_generator_blind, blinding_factor, None)
    with pytest.raises(TypeError):
        secp256k1_pedersen_blind_generator_blind_sum(ctx, value, valid_generator_blind, blinding_factor, 'string')

    # Test getting blind generator blind sum with invalid values
    with pytest.raises(OverflowError):
        secp256k1_pedersen_blind_generator_blind_sum(ctx, [-1], valid_generator_blind, blinding_factor, 1)
    with pytest.raises(OverflowError):
        secp256k1_pedersen_blind_generator_blind_sum(ctx, [0x10000000000000000], valid_generator_blind, blinding_factor, 1)
    with pytest.raises(OverflowError):
        secp256k1_pedersen_blind_generator_blind_sum(ctx, value, valid_generator_blind, blinding_factor, -1)
    with pytest.raises(OverflowError):
        secp256k1_pedersen_blind_generator_blind_sum(ctx, value, valid_generator_blind, blinding_factor, 0x10000000000000000)

def test_secp256k1_blind_switch():
    # Test getting blind switch
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    blind = bytes.fromhex('8c3882fbd7966085e760e000b1ea9eb1ad3df1eec02e720adaa5104c6bd9fd88')
    value = 123456789
    switch_pubkey = secp256k1_ec_pubkey_parse(ctx, bytes.fromhex('02b860f56795fc03f3c21685383d1b5a2f2954f49b7e398b8d2a0193933621155f'))
    assert switch_pubkey is not None
    blind_switch = secp256k1_blind_switch(ctx, blind, value, secp256k1_generator_const_h, secp256k1_generator_const_g, switch_pubkey)
    assert blind_switch == bytes.fromhex('b58549c27426759f5005858b107fad4f576de3040390988548dbd6b0a9937a0a')

    # Test getting blind switch with invalid types
    with pytest.raises(TypeError):
        secp256k1_blind_switch(None, blind, value, secp256k1_generator_const_h, secp256k1_generator_const_g, switch_pubkey)
    with pytest.raises(TypeError):
        secp256k1_blind_switch('string', blind, value, secp256k1_generator_const_h, secp256k1_generator_const_g, switch_pubkey)
    with pytest.raises(TypeError):
        secp256k1_blind_switch(ctx, None, value, secp256k1_generator_const_h, secp256k1_generator_const_g, switch_pubkey)
    with pytest.raises(TypeError):
        secp256k1_blind_switch(ctx, 'string', value, secp256k1_generator_const_h, secp256k1_generator_const_g, switch_pubkey)
    with pytest.raises(TypeError):
        secp256k1_blind_switch(ctx, blind, None, secp256k1_generator_const_h, secp256k1_generator_const_g, switch_pubkey)
    with pytest.raises(TypeError):
        secp256k1_blind_switch(ctx, blind, 'string', secp256k1_generator_const_h, secp256k1_generator_const_g, switch_pubkey)
    with pytest.raises(TypeError):
        secp256k1_blind_switch(ctx, blind, value, None, secp256k1_generator_const_g, switch_pubkey)
    with pytest.raises(TypeError):
        secp256k1_blind_switch(ctx, blind, value, 'string', secp256k1_generator_const_g, switch_pubkey)
    with pytest.raises(TypeError):
        secp256k1_blind_switch(ctx, blind, value, secp256k1_generator_const_h, None, switch_pubkey)
    with pytest.raises(TypeError):
        secp256k1_blind_switch(ctx, blind, value, secp256k1_generator_const_h, 'string', switch_pubkey)
    with pytest.raises(TypeError):
        secp256k1_blind_switch(ctx, blind, value, secp256k1_generator_const_h, secp256k1_generator_const_g, None)
    with pytest.raises(TypeError):
        secp256k1_blind_switch(ctx, blind, value, secp256k1_generator_const_h, secp256k1_generator_const_g, 'string')

    # Test getting blind switch with invalid values
    with pytest.raises(OverflowError):
        secp256k1_blind_switch(ctx, blind, -1, secp256k1_generator_const_h, secp256k1_generator_const_g, switch_pubkey)
    with pytest.raises(OverflowError):
        secp256k1_blind_switch(ctx, blind, 0x10000000000000000, secp256k1_generator_const_h, secp256k1_generator_const_g, switch_pubkey)

def test_secp256k1_pedersen_commitment_to_pubkey():
    # Test getting public key from Pedersen commit
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    commit = secp256k1_pedersen_commitment_parse(ctx, bytes.fromhex('08883a3f816419d4ce5bf44e320c24c5b09b0621c70fb780d7a35c86570bd35475'))
    assert commit is not None
    pubkey = secp256k1_pedersen_commitment_to_pubkey(ctx, commit)
    assert pubkey is not None
    output = secp256k1_ec_pubkey_serialize(ctx, pubkey, SECP256K1_EC_COMPRESSED)
    assert output == bytes.fromhex('02883a3f816419d4ce5bf44e320c24c5b09b0621c70fb780d7a35c86570bd35475')

    # Test getting public key from Pedersen commit with invalid types
    with pytest.raises(TypeError):
        secp256k1_pedersen_commitment_to_pubkey(None, commit)
    with pytest.raises(TypeError):
        secp256k1_pedersen_commitment_to_pubkey('string', commit)
    with pytest.raises(TypeError):
        secp256k1_pedersen_commitment_to_pubkey(ctx, None)
    with pytest.raises(TypeError):
        secp256k1_pedersen_commitment_to_pubkey(ctx, 'string')

def test_secp256k1_pubkey_to_pedersen_commitment():
    # Test getting Pedersen commit from public key
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    pubkey = secp256k1_ec_pubkey_parse(ctx, bytes.fromhex('02883a3f816419d4ce5bf44e320c24c5b09b0621c70fb780d7a35c86570bd35475'))
    assert pubkey is not None
    commit = secp256k1_pubkey_to_pedersen_commitment(ctx, pubkey)
    assert commit is not None
    output = secp256k1_pedersen_commitment_serialize(ctx, commit)
    assert output == bytes.fromhex('08883a3f816419d4ce5bf44e320c24c5b09b0621c70fb780d7a35c86570bd35475')

    # Test getting Pedersen commit from public key with invalid types
    with pytest.raises(TypeError):
        secp256k1_pubkey_to_pedersen_commitment(None, pubkey)
    with pytest.raises(TypeError):
        secp256k1_pubkey_to_pedersen_commitment('string', pubkey)
    with pytest.raises(TypeError):
        secp256k1_pubkey_to_pedersen_commitment(ctx, None)
    with pytest.raises(TypeError):
        secp256k1_pubkey_to_pedersen_commitment(ctx, 'string')

def test_secp256k1_ecdh():
    # Test getting EC Diffie-Hellman secret
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    pubkey = secp256k1_ec_pubkey_parse(ctx, bytes.fromhex('03e7e3dd547cc3171ffdc403824fcc5d5d03712a29f459ca10668c2864c088e951'))
    assert pubkey is not None
    valid_privkey = bytes.fromhex('8c3882fbd7966085e760e000b1ea9eb1ad3df1eec02e720adaa5104c6bd9fd88')
    valid_result = secp256k1_ecdh(ctx, pubkey, valid_privkey)
    assert valid_result == bytes.fromhex('49c3c28196fa288fb8368400632564fc3e133a1bdcd499d8d6b5f0073b948eb9')

    # Test getting invalid EC Diffie-Hellman secret
    invalid_privkey = bytes.fromhex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
    invalid_result = secp256k1_ecdh(ctx, pubkey, invalid_privkey)
    assert invalid_result is None

    # Test getting EC Diffie-Hellman secret with invalid types
    with pytest.raises(TypeError):
        secp256k1_ecdh(None, pubkey, valid_privkey)
    with pytest.raises(TypeError):
        secp256k1_ecdh('string', pubkey, valid_privkey)
    with pytest.raises(TypeError):
        secp256k1_ecdh(ctx, None, valid_privkey)
    with pytest.raises(TypeError):
        secp256k1_ecdh(ctx, 'string', valid_privkey)
    with pytest.raises(TypeError):
        secp256k1_ecdh(ctx, pubkey, None)
    with pytest.raises(TypeError):
        secp256k1_ecdh(ctx, pubkey, 'string')

def test_secp256k1_generator_parse():
    # Test parsing generator
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    valid_input = bytes.fromhex('0bc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5')
    valid_commit = secp256k1_generator_parse(ctx, valid_input)
    assert valid_commit is not None

    # Test parsing invalid generator
    invalid_input = bytes.fromhex('1bc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5')
    invalid_commit = secp256k1_generator_parse(ctx, invalid_input)
    assert invalid_commit is None

    # Test parsing generator with invalid types
    with pytest.raises(TypeError):
        secp256k1_generator_parse(None, valid_input)
    with pytest.raises(TypeError):
        secp256k1_generator_parse('string', valid_input)
    with pytest.raises(TypeError):
        secp256k1_generator_parse(ctx, None)
    with pytest.raises(TypeError):
        secp256k1_generator_parse(ctx, 'string')

def test_secp256k1_generator_serialize():
    # Test serializing generator
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    input = bytes.fromhex('0bc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5')
    commit = secp256k1_generator_parse(ctx, input)
    assert commit is not None
    output = secp256k1_generator_serialize(ctx, commit)
    assert output == bytes.fromhex('0bc6047f9441ed7d6d3045406e95c07cd85c778e4b8cef3ca7abac09b95c709ee5')

    # Test parsing generator with invalid types
    with pytest.raises(TypeError):
        secp256k1_generator_parse(None, input)
    with pytest.raises(TypeError):
        secp256k1_generator_parse('string', input)
    with pytest.raises(TypeError):
        secp256k1_generator_parse(ctx, None)
    with pytest.raises(TypeError):
        secp256k1_generator_parse(ctx, 'string')

def test_secp256k1_generator_generate():
    # Test generating generator
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    seed32 = bytes.fromhex('8c3882fbd7966085e760e000b1ea9eb1ad3df1eec02e720adaa5104c6bd9fd88')
    gen = secp256k1_generator_generate(ctx, seed32)
    assert gen is not None
    output = secp256k1_generator_serialize(ctx, gen)
    assert output == bytes.fromhex('0bceac7d9e76c0cd1a640a38ee20bfdf00987a0383ca2bfee15973d31ec344fdf4')

    # Test parsing generator with invalid types
    with pytest.raises(TypeError):
        secp256k1_generator_generate(None, seed32)
    with pytest.raises(TypeError):
        secp256k1_generator_generate('string', seed32)
    with pytest.raises(TypeError):
        secp256k1_generator_generate(ctx, None)
    with pytest.raises(TypeError):
        secp256k1_generator_generate(ctx, 'string')

def test_secp256k1_generator_generate_blinded():
    # Test generating blinded generator
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    key32 = bytes.fromhex('8c3882fbd7966085e760e000b1ea9eb1ad3df1eec02e720adaa5104c6bd9fd88')
    blind32 = bytes.fromhex('f843522f6bba1da1414e29be6a37e6c56a082e9daa2447c643285641dd7d29ec')
    gen = secp256k1_generator_generate_blinded(ctx, key32, blind32)
    assert gen is not None
    output = secp256k1_generator_serialize(ctx, gen)
    assert output == bytes.fromhex('0b5c554e6e131a71d273b48ad1393b5c71cb4e2c19dc95109ac5ca143658449d2a')

    # Test generating blinded generator with invalid types
    with pytest.raises(TypeError):
        secp256k1_generator_generate_blinded(None, key32, blind32)
    with pytest.raises(TypeError):
        secp256k1_generator_generate_blinded('string', key32, blind32)
    with pytest.raises(TypeError):
        secp256k1_generator_generate_blinded(ctx, None, blind32)
    with pytest.raises(TypeError):
        secp256k1_generator_generate_blinded(ctx, 'string', blind32)
    with pytest.raises(TypeError):
        secp256k1_generator_generate_blinded(ctx, key32, None)
    with pytest.raises(TypeError):
        secp256k1_generator_generate_blinded(ctx, key32, 'string')

def test_secp256k1_context_preallocated_size():
    # Test getting preallocated none context size
    none_context_size = secp256k1_context_preallocated_size(SECP256K1_CONTEXT_NONE)
    assert none_context_size == (224 if ffi.sizeof('void *') == 8 else 192)

    # Test getting preallocated verify context size
    verify_context_size = secp256k1_context_preallocated_size(SECP256K1_CONTEXT_VERIFY)
    assert verify_context_size == (1048800 if ffi.sizeof('void *') == 8 else 1048768)

    # Test getting preallocated sign context size
    sign_context_size = secp256k1_context_preallocated_size(SECP256K1_CONTEXT_SIGN)
    assert sign_context_size == (65760 if ffi.sizeof('void *') == 8 else 65728)

    # Test getting preallocated verify and sign context size
    verify_and_sign_context_size = secp256k1_context_preallocated_size(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert verify_and_sign_context_size == (1114336 if ffi.sizeof('void *') == 8 else 1114304)

    # Test getting preallocated context size with invalid types
    with pytest.raises(TypeError):
        secp256k1_context_preallocated_size(None)
    with pytest.raises(TypeError):
        secp256k1_context_preallocated_size('string')

    # Test getting preallocated context size invalid values
    with pytest.raises(OverflowError):
        secp256k1_context_preallocated_size(-1)
    with pytest.raises(OverflowError):
        secp256k1_context_preallocated_size(0x100000000)

def test_secp256k1_context_preallocated_create():
    # Test creating preallocated none context
    none_prealloc = ffi.new('unsigned char []', secp256k1_context_preallocated_size(SECP256K1_CONTEXT_NONE))
    none_ctx = secp256k1_context_preallocated_create(none_prealloc, SECP256K1_CONTEXT_NONE)
    assert none_ctx is not None

    # Test creating preallocated verify context
    verify_prealloc = ffi.new('unsigned char []', secp256k1_context_preallocated_size(SECP256K1_CONTEXT_VERIFY))
    verify_ctx = secp256k1_context_preallocated_create(verify_prealloc, SECP256K1_CONTEXT_VERIFY)
    assert verify_ctx is not None

    # Test creating preallocated sign context
    sign_prealloc = ffi.new('unsigned char []', secp256k1_context_preallocated_size(SECP256K1_CONTEXT_SIGN))
    sign_ctx = secp256k1_context_preallocated_create(sign_prealloc, SECP256K1_CONTEXT_SIGN)
    assert sign_ctx is not None

    # Test creating preallocated verify and sign context
    verify_and_sign_prealloc = ffi.new('unsigned char []', secp256k1_context_preallocated_size(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN))
    verify_and_sign_ctx = secp256k1_context_preallocated_create(verify_and_sign_prealloc, SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert verify_and_sign_ctx is not None

    # Test creating preallocated context with invalid types
    with pytest.raises(TypeError):
        secp256k1_context_preallocated_create(None, SECP256K1_CONTEXT_NONE)
    with pytest.raises(TypeError):
        secp256k1_context_preallocated_create('string', SECP256K1_CONTEXT_NONE)
    with pytest.raises(TypeError):
        secp256k1_context_preallocated_create(none_prealloc, None)
    with pytest.raises(TypeError):
        secp256k1_context_preallocated_create(none_prealloc, 'string')

    # Test creating preallocated context invalid values
    with pytest.raises(OverflowError):
        secp256k1_context_preallocated_create(none_prealloc, -1)
    with pytest.raises(OverflowError):
        secp256k1_context_preallocated_create(none_prealloc, 0x100000000)

def test_secp256k1_context_preallocated_clone_size():
    # Test getting preallocated none context clone size
    none_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE)
    assert none_ctx is not None
    none_context_clone_size = secp256k1_context_preallocated_clone_size(none_ctx)
    assert none_context_clone_size == secp256k1_context_preallocated_size(SECP256K1_CONTEXT_NONE)

    # Test getting preallocated verify context clone size
    verify_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY)
    assert verify_ctx is not None
    verify_context_clone_size = secp256k1_context_preallocated_clone_size(verify_ctx)
    assert verify_context_clone_size == secp256k1_context_preallocated_size(SECP256K1_CONTEXT_VERIFY)

    # Test getting preallocated sign context clone size
    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN)
    assert sign_ctx is not None
    sign_context_clone_size = secp256k1_context_preallocated_clone_size(sign_ctx)
    assert sign_context_clone_size == secp256k1_context_preallocated_size(SECP256K1_CONTEXT_SIGN)

    # Test getting preallocated verify and sign context clone size
    verify_and_sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert verify_and_sign_ctx is not None
    verify_and_sign_context_clone_size = secp256k1_context_preallocated_clone_size(verify_and_sign_ctx)
    assert verify_and_sign_context_clone_size == secp256k1_context_preallocated_size(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)

    # Test getting preallocated context clone size with invalid types
    with pytest.raises(TypeError):
        secp256k1_context_preallocated_size(None)
    with pytest.raises(TypeError):
        secp256k1_context_preallocated_size('string')

def test_secp256k1_context_preallocated_clone():
    # Test cloning preallocated context
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    prealloc = ffi.new('unsigned char []', secp256k1_context_preallocated_clone_size(ctx))
    clone = secp256k1_context_preallocated_clone(ctx, prealloc)
    assert clone is not None

    # Test cloning preallocated context with invalid types
    with pytest.raises(TypeError):
        secp256k1_context_preallocated_clone(None, prealloc)
    with pytest.raises(TypeError):
        secp256k1_context_preallocated_clone('string', prealloc)
    with pytest.raises(TypeError):
        secp256k1_context_preallocated_clone(ctx, None)
    with pytest.raises(TypeError):
        secp256k1_context_preallocated_clone(ctx, 'string')

def test_secp256k1_context_preallocated_destroy():
    # Test destroying no preallocated context
    secp256k1_context_preallocated_destroy(None)
    assert True

    # Test destroying preallocated context
    prealloc = ffi.new('unsigned char []', secp256k1_context_preallocated_size(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN))
    ctx = secp256k1_context_preallocated_create(prealloc, SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    secp256k1_context_preallocated_destroy(ctx)
    assert True

    # Test destroying preallocated context with invalid types
    with pytest.raises(TypeError):
        secp256k1_context_preallocated_destroy('string')

def test_secp256k1_rangeproof_verify():
    # Test verifying rangeproof without extra commit
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    commit_without_extra_commit = secp256k1_pedersen_commitment_parse(ctx, bytes.fromhex('08f51e0dc5867851a90000ef4de29460898304b40e9010051c7fd733921fe77459'))
    assert commit_without_extra_commit is not None
    proof_without_extra_commit = bytes.fromhex('62070000000000000056022a5c420e1d51e1b7f36904b5bb9b416614f3644226e3a76a06bba85a496f1976fbe5757788aba9664480ea29957fdf724aaf02bedd5d15d8aeff74c98c1a670eb2572299c321466f15580edbe66ec40dfe6f046b0d183d784098564ee44a7490a7ac9c16e03e81af0fe34f349952f7a7f6d383a0174b2da7d4fdf78445c411713d4a2234099ca7e5c8ba04bffd25117da44345c7629e7b80f609bb1b2ef3cd23e0ed814342bec49f588a0d6679097011683d87381c3c85525b62f73e7e87a29924d07d18635648a43afe65faa4d067aa98654de422754552e841c7ed38ebf50290c945a3b04d03d7ab43e421fc83d6121d76b13c67631f529dc3235c4ea68d014aba9af4165b67c8e1d2426ddfcd086a73416ac284c631be57cb0edebf71d58af724b2a78996624fd9f7c3de4cab1372b4b3350482a8751dde46a80db823440044fa536c2dced3a680a120cad163bbbe395f9d2769b3331fdbda670537be65e97ea9c3ff378ab42dfef21685c70fd9be14d180149f58569841f626f7a27166b47a9c1273d3df772b49e5ca5057446e3f5856bc21704fc6aa12ff7ca73ded46c140e658092adab376ab44b54eb312e0268a52ac491de706533a0135212e8648c575c1a27d2253f63f41c5b3087da367c0bbb68df0d30172d36382011ae71d22fa9533f6f2dea25386555ab42e7575c6d5939c57a91fb93ee81cbfac1c546ff5ab41eeb30ed076c41a45cdf1d6ccb0837073bc8874a05be7981036bfec231cc2b5ba4b9d7f8c8ae2da18ddab278a15ebb0d43a8b7700c7bbccfabaa46a175cf8515d8d16cda70e719798785a41b3f01f872d65cd2949d2872c91a95fcca9d8bb5318e7d6ec65a645f6cecf48f61e3dd2cfcb3acdbb922924167f8aa85c0c457133')
    min_value_without_extra_commit, max_value_without_extra_commit = secp256k1_rangeproof_verify(ctx, commit_without_extra_commit, proof_without_extra_commit, None, secp256k1_generator_const_h)
    assert min_value_without_extra_commit == 86 and max_value_without_extra_commit == 25586

    # Test verifying rangeproof with extra commit
    commit_with_extra_commit = secp256k1_pedersen_commitment_parse(ctx, bytes.fromhex('08fbea8e2c9b939f822677452e5f48e7a08edeeb1ab949a2384b9d7a32b745bde4'))
    assert commit_with_extra_commit is not None
    proof_with_extra_commit = bytes.fromhex('401a9009d78bce88c76a0b7bd52d4b307edae626ebb82eaab20a7ac0abd915fcd8bfc863f849270e5d2deaf3a8c4b7a8b4b52171232391b4b933eb6564de2a6ce423cc1eb6c445ccea4eb92d78f972e0ba7b43bd9cb4f384406e112b79bfe78af65f1dafb2849cae4a093db4a700bf3c3fd57cb0333670bac6855c349907bf33b79cb7ba7aeb3bed6be546f4704fde2b0656e9e0827901e837f04ffeee3d3326d637e641be20f673f0a537c3995b130f2e657af47d3c047b22f018f5470d7a2a0b1a9df35fa93d9b59bba7bf2d6219347631e70f8725bba1f9a106eefda3fffc4742150e3a77478770c902df97d0989769c1da0177d7ec817fbb079eedf7349c5b3dd6a0761726c084922350b18c40afe9da699373431c5c0d7c09e4fb985c9468a49e8cfa9b11e24c952d5541ed71691c6d461814095f0fe5556c9b9479bfc62f55e19043a99bc058409203ac076a68cc10d64c00bdfc77b0582a262a4653bb6bfdf98e5e0a841e164065b241daace1ab00a9a7422e8bd7cf8efccfc432e33fcd24f070b80f332ea5c412e0163a7edda790a17385824d39e7f724b6a3a40ed28c465adde3683c789556d7fedd7a7646dce2b0586a230134113001f356ab7f630fee1d0ed902fb198dd12a3a4023648a6f8770c9014a9fdb82d2d6b7b64b12739f60403ceca1fef693520ac8fb8b16c9cbbf4c309918319f62cdf3e30407dbfae2af5da7dc3173b78c11f657a97ed7a7c09cd6d4e4501eb8ea3f7a6d69f7a9e3e8ee6c3aacd148b4efc31035ee9ec3b1a22dfca21d7e5ae3c297ccc93fe7f53c1a8aab3eb2d3d5acb9a05434cff106902e84fcf10256ea8e0a14353b1da73664e724d83fe42aaa8153b565b8abfa916bd52ddb4ffa4f3388f456107aecae2acb0772a322192c793cc6d59607de5370531cdc7fdb63413ad8752da58cc086c99efea0a204a86ae59ca68837daa827fd30410fa86c740f459a8d4183736489d61bf0c686e98035996278c793f27004c49f6a913c202e5e191957207f8e3dbacedf790499d242f059b9e840d7307c657544ef34f8d539653f5d0d87ecbceb38da7ceed2d89a2526ffff4192e9cd7db62e31748707813ebc6726c2a918664ceaad2aa2822d4978ea194dc6db912f3cc07b73dc1e2bffcc7945f41eb6b8809ac945a7197de0a3888ffa18fedb9f99a6fda27bcd853776bc14945f9dc1399432372b376d2522f919803eaa36ec61e5fdf9e34da6c34c7ca56b1a62cc15842185a81ae01d845bac7e2e799c636ac17bd63121f66665aa716464b6ce025c1006d52b75754725a898b0daeae1635f1e18290d8aa1937fd1209acda8454c51418fe25642d7eabd75a84727109bcec617e1922353aee7e0b3fa3364efc2df64dfff6709e1946caf625d798ed0d2a490a5c489dfcaba2992a9813cc0c9c5259fb1ed9f7e84c0f7e720e6e823bf15e5658113dcbf4fbb45e42de14704754cffc4d578107ee9971802267838705c25b289998734bad657953560d1dd7a20362a0c2fb627693c6c78afc1f14bf5dc9d5f775302340344f3011719b0f0616f9439f3b1a77b9fa032be6657e64a65d180632444d67a670ecb685e221818628dae67e08c9a15ad2bb779f2f8b22b44806007e502c5fcefe2d7232fcf1073586fb3ba98007cd1ca32f03383e22636015330143001ee30ee0cd2410482372a331b17906ab06e4363dba2df1688e7ec6848966e34f597f6f0b6955be181539701a0197e694dc314a9fdfe672d340cd72053ab648876ebe00114faa75d0306b49e4a9836def3de8aa6f3ed32c5c13a9a374c02c8886e4cfebf5f792ba257c99a720553da11d9a8ad0e195d22d821524ba7c82e194c25fc127fffa57705ab1a178e509edf989ffed589cd3131c15c3656248167c49bc940e90a5caa60514e4f7c2a48ad641a1f9a679d2a53c830e827db455c90193641695bd31d70d6fbaf2f3897fc2ef5d94167f016ab7620cbce843c0baa19d3c64558007d15e3fac2c4a2e2870c8588ec5aa0b3486d29d1295516efacc0144249e5b202ca93f54b5c43cc91c611501318519f9d88dfdbd3a72f43e2c7b32d6d9724b3e7d31a9b2d43026e749ac2c109ff1049024b860e3c2ec094e97155e70c0b39563e9f3fa036e3ea404dc25813fa056dd79717e6056206d7b2db6786e21d4668f54a8c017bac7bc1e8f3b579aa45f38fac394d6d636596c33c39e4cf638b4811b6d40a8564ddb2a307d5e26939a39235dd7de610cc89d3979891fa539054003f3c872d960083b46693edb67bc0577c16721b3304311485b934666ab5583d30a851a824052cd4a1d6e2ac518b02b7d550726a16078e20b6b5c66fc7d3fbfcf7303b5b85962b8efeeabaebc35c362c4c4b1fe0fbe39852874a69bd701c26ec46412b867734f9f65ede42a55dcd4396a286e4c6ce5a25121f003a41eedda151a84f188600d8d0e6e5dcbd1c53bfbf808fea696ed23958b113508aeeb3aa6dae558973c2ce8c568ba34d1cd436629b19019188052f835e8032152eee279c3937215289b9f406350608448a2193bfd5128b7002e3806c263d35ec01773eefb9ba1aed729edd452d5f06c92d323fe5eea096c74363d0f8fd22f8f3244b56da818cf22326b60875b176ea3fac63eeb2a306895101d23191a95ca44a57ac4e57a8008f001c6382e6425d1375796fce09b0557be576b96fb94ea86ca5a678d73cb07c33867b235bc8fe4e801f9aef28c2d63db0e648a4bc6d54c9cff5d904832a325a3118afce62d7a2c4db6e3ad93d87987763456f8890a2aa23e5537db73855000410217334f130a49eb59c55d4e5991b8f86bc8b39d4f1223684389291d83ee6ebc58e5caaf31b4fcf13ddbff10ba0b35e69372572ac212b0faa5f42bf8e65ca58b3e2697f7e5a99c509f83e6cf07a9c4e452b15bf6b5e8c63fe4e50a66f983406d97380fe996c9305c8d878179046ddd667795a0aa83926b12352fc28269b4b04847d31d479f08c04cb316cd00976663a40bad563a7c083078cf1ee09162c59f57e4e3ec233f16f4393aa6f25bc4a93926d4cda64ec6c21930e29dd')
    extra_commit = bytes.fromhex('060708090a')
    min_value_with_extra_commit, max_value_with_extra_commit = secp256k1_rangeproof_verify(ctx, commit_with_extra_commit, proof_with_extra_commit, extra_commit, secp256k1_generator_const_h)
    assert min_value_with_extra_commit == 0 and max_value_with_extra_commit == 134217727

    # Test verifying invalid rangeproof
    invalid_proof = bytes.fromhex('72070000000000000056022a5c420e1d51e1b7f36904b5bb9b416614f3644226e3a76a06bba85a496f1976fbe5757788aba9664480ea29957fdf724aaf02bedd5d15d8aeff74c98c1a670eb2572299c321466f15580edbe66ec40dfe6f046b0d183d784098564ee44a7490a7ac9c16e03e81af0fe34f349952f7a7f6d383a0174b2da7d4fdf78445c411713d4a2234099ca7e5c8ba04bffd25117da44345c7629e7b80f609bb1b2ef3cd23e0ed814342bec49f588a0d6679097011683d87381c3c85525b62f73e7e87a29924d07d18635648a43afe65faa4d067aa98654de422754552e841c7ed38ebf50290c945a3b04d03d7ab43e421fc83d6121d76b13c67631f529dc3235c4ea68d014aba9af4165b67c8e1d2426ddfcd086a73416ac284c631be57cb0edebf71d58af724b2a78996624fd9f7c3de4cab1372b4b3350482a8751dde46a80db823440044fa536c2dced3a680a120cad163bbbe395f9d2769b3331fdbda670537be65e97ea9c3ff378ab42dfef21685c70fd9be14d180149f58569841f626f7a27166b47a9c1273d3df772b49e5ca5057446e3f5856bc21704fc6aa12ff7ca73ded46c140e658092adab376ab44b54eb312e0268a52ac491de706533a0135212e8648c575c1a27d2253f63f41c5b3087da367c0bbb68df0d30172d36382011ae71d22fa9533f6f2dea25386555ab42e7575c6d5939c57a91fb93ee81cbfac1c546ff5ab41eeb30ed076c41a45cdf1d6ccb0837073bc8874a05be7981036bfec231cc2b5ba4b9d7f8c8ae2da18ddab278a15ebb0d43a8b7700c7bbccfabaa46a175cf8515d8d16cda70e719798785a41b3f01f872d65cd2949d2872c91a95fcca9d8bb5318e7d6ec65a645f6cecf48f61e3dd2cfcb3acdbb922924167f8aa85c0c457133')
    invalid_min_value = secp256k1_rangeproof_verify(ctx, commit_without_extra_commit, invalid_proof, None, secp256k1_generator_const_h)
    assert invalid_min_value is None

    # Test verifying rangeproof with invalid types
    with pytest.raises(TypeError):
        secp256k1_rangeproof_verify(None, commit_without_extra_commit, proof_without_extra_commit, None, secp256k1_generator_const_h)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_verify('string', commit_without_extra_commit, proof_without_extra_commit, None, secp256k1_generator_const_h)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_verify(ctx, None, proof_without_extra_commit, None, secp256k1_generator_const_h)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_verify(ctx, 'string', proof_without_extra_commit, None, secp256k1_generator_const_h)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_verify(ctx, commit_without_extra_commit, None, None, secp256k1_generator_const_h)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_verify(ctx, commit_without_extra_commit, 'string', None, secp256k1_generator_const_h)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_verify(ctx, commit_without_extra_commit, proof_without_extra_commit, 'string', secp256k1_generator_const_h)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_verify(ctx, commit_without_extra_commit, proof_without_extra_commit, None, None)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_verify(ctx, commit_without_extra_commit, proof_without_extra_commit, None, 'string')

def test_secp256k1_rangeproof_rewind():
    # Test rewinding rangeproof without extra commit
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    value = 123456789
    blind = bytes.fromhex('1fa9603de2484636f6ba326486c7d98c26c12b23d1ec024fa45c1ed689e60a97')
    commit = secp256k1_pedersen_commit(ctx, blind, value, secp256k1_generator_const_h, secp256k1_generator_const_g)
    assert commit is not None
    nonce = bytes.fromhex('909a8befc5beaeb9b43afc7476b6e1c87e522fb85abc162ff10e26c98306540f')
    message = bytes.fromhex('000102030405')
    proof_without_extra_commit = secp256k1_rangeproof_sign(ctx, 0, commit, blind, nonce, 0, 0, value, message, None, secp256k1_generator_const_h)
    blind_out_without_extra_commit, value_out_without_extra_commit, message_out_without_extra_commit, min_value_without_extra_commit, max_value_without_extra_commit = secp256k1_rangeproof_rewind(ctx, nonce, commit, proof_without_extra_commit, None, secp256k1_generator_const_h)
    assert blind_out_without_extra_commit == blind and value_out_without_extra_commit == value and message_out_without_extra_commit[0 : len(message)] == message and min_value_without_extra_commit == 0 and max_value_without_extra_commit == 134217727

    # Test rewinding rangeproof with extra commit
    extra_commit = bytes.fromhex('060708090a')
    proof_with_extra_commit = secp256k1_rangeproof_sign(ctx, 0, commit, blind, nonce, 0, 0, value, message, extra_commit, secp256k1_generator_const_h)
    blind_out_with_extra_commit, value_out_with_extra_commit, message_out_with_extra_commit, min_value_with_extra_commit, max_value_with_extra_commit = secp256k1_rangeproof_rewind(ctx, nonce, commit, proof_with_extra_commit, extra_commit, secp256k1_generator_const_h)
    assert blind_out_with_extra_commit == blind and value_out_with_extra_commit == value and message_out_with_extra_commit[0 : len(message)] == message and min_value_with_extra_commit == 0 and max_value_with_extra_commit == 134217727

    # Test rewinding invalid rangeproof
    invalid_proof = bytes.fromhex('501a9009d78bce88c76a0b7bd52d4b307edae626ebb82eaab20a7ac0abd915fcd8bfc863f849270e5d2deaf3a8c4b7a8b4b52171232391b4b933eb6564de2a6ce423cc1eb6c445ccea4eb92d78f972e0ba7b43bd9cb4f384406e112b79bfe78af65f1dafb2849cae4a093db4a700bf3c3fd57cb0333670bac6855c349907bf33b79cb7ba7aeb3bed6be546f4704fde2b0656e9e0827901e837f04ffeee3d3326d637e641be20f673f0a537c3995b130f2e657af47d3c047b22f018f5470d7a2a0b1a9df35fa93d9b59bba7bf2d6219347631e70f8725bba1f9a106eefda3fffc4742150e3a77478770c902df97d0989769c1da0177d7ec817fbb079eedf7349c5b3dd6a0761726c084922350b18c40afe9da699373431c5c0d7c09e4fb985c9468a49e8cfa9b11e24c952d5541ed71691c6d461814095f0fe5556c9b9479bfc62f55e19043a99bc058409203ac076a68cc10d64c00bdfc77b0582a262a4653bb6bfdf98e5e0a841e164065b241daace1ab00a9a7422e8bd7cf8efccfc432e33fcd24f070b80f332ea5c412e0163a7edda790a17385824d39e7f724b6a3a40ed28c465adde3683c789556d7fedd7a7646dce2b0586a230134113001f356ab7f630fee1d0ed902fb198dd12a3a4023648a6f8770c9014a9fdb82d2d6b7b64b12739f60403ceca1fef693520ac8fb8b16c9cbbf4c309918319f62cdf3e30407dbfae2af5da7dc3173b78c11f657a97ed7a7c09cd6d4e4501eb8ea3f7a6d69f7a9e3e8ee6c3aacd148b4efc31035ee9ec3b1a22dfca21d7e5ae3c297ccc93fe7f53c1a8aab3eb2d3d5acb9a05434cff106902e84fcf10256ea8e0a14353b1da73664e724d83fe42aaa8153b565b8abfa916bd52ddb4ffa4f3388f456107aecae2acb0772a322192c793cc6d59607de5370531cdc7fdb63413ad8752da58cc086c99efea0a204a86ae59ca68837daa827fd30410fa86c740f459a8d4183736489d61bf0c686e98035996278c793f27004c49f6a913c202e5e191957207f8e3dbacedf790499d242f059b9e840d7307c657544ef34f8d539653f5d0d87ecbceb38da7ceed2d89a2526ffff4192e9cd7db62e31748707813ebc6726c2a918664ceaad2aa2822d4978ea194dc6db912f3cc07b73dc1e2bffcc7945f41eb6b8809ac945a7197de0a3888ffa18fedb9f99a6fda27bcd853776bc14945f9dc1399432372b376d2522f919803eaa36ec61e5fdf9e34da6c34c7ca56b1a62cc15842185a81ae01d845bac7e2e799c636ac17bd63121f66665aa716464b6ce025c1006d52b75754725a898b0daeae1635f1e18290d8aa1937fd1209acda8454c51418fe25642d7eabd75a84727109bcec617e1922353aee7e0b3fa3364efc2df64dfff6709e1946caf625d798ed0d2a490a5c489dfcaba2992a9813cc0c9c5259fb1ed9f7e84c0f7e720e6e823bf15e5658113dcbf4fbb45e42de14704754cffc4d578107ee9971802267838705c25b289998734bad657953560d1dd7a20362a0c2fb627693c6c78afc1f14bf5dc9d5f775302340344f3011719b0f0616f9439f3b1a77b9fa032be6657e64a65d180632444d67a670ecb685e221818628dae67e08c9a15ad2bb779f2f8b22b44806007e502c5fcefe2d7232fcf1073586fb3ba98007cd1ca32f03383e22636015330143001ee30ee0cd2410482372a331b17906ab06e4363dba2df1688e7ec6848966e34f597f6f0b6955be181539701a0197e694dc314a9fdfe672d340cd72053ab648876ebe00114faa75d0306b49e4a9836def3de8aa6f3ed32c5c13a9a374c02c8886e4cfebf5f792ba257c99a720553da11d9a8ad0e195d22d821524ba7c82e194c25fc127fffa57705ab1a178e509edf989ffed589cd3131c15c3656248167c49bc940e90a5caa60514e4f7c2a48ad641a1f9a679d2a53c830e827db455c90193641695bd31d70d6fbaf2f3897fc2ef5d94167f016ab7620cbce843c0baa19d3c64558007d15e3fac2c4a2e2870c8588ec5aa0b3486d29d1295516efacc0144249e5b202ca93f54b5c43cc91c611501318519f9d88dfdbd3a72f43e2c7b32d6d9724b3e7d31a9b2d43026e749ac2c109ff1049024b860e3c2ec094e97155e70c0b39563e9f3fa036e3ea404dc25813fa056dd79717e6056206d7b2db6786e21d4668f54a8c017bac7bc1e8f3b579aa45f38fac394d6d636596c33c39e4cf638b4811b6d40a8564ddb2a307d5e26939a39235dd7de610cc89d3979891fa539054003f3c872d960083b46693edb67bc0577c16721b3304311485b934666ab5583d30a851a824052cd4a1d6e2ac518b02b7d550726a16078e20b6b5c66fc7d3fbfcf7303b5b85962b8efeeabaebc35c362c4c4b1fe0fbe39852874a69bd701c26ec46412b867734f9f65ede42a55dcd4396a286e4c6ce5a25121f003a41eedda151a84f188600d8d0e6e5dcbd1c53bfbf808fea696ed23958b113508aeeb3aa6dae558973c2ce8c568ba34d1cd436629b19019188052f835e8032152eee279c3937215289b9f406350608448a2193bfd5128b7002e3806c263d35ec01773eefb9ba1aed729edd452d5f06c92d323fe5eea096c74363d0f8fd22f8f3244b56da818cf22326b60875b176ea3fac63eeb2a306895101d23191a95ca44a57ac4e57a8008f001c6382e6425d1375796fce09b0557be576b96fb94ea86ca5a678d73cb07c33867b235bc8fe4e801f9aef28c2d63db0e648a4bc6d54c9cff5d904832a325a3118afce62d7a2c4db6e3ad93d87987763456f8890a2aa23e5537db73855000410217334f130a49eb59c55d4e5991b8f86bc8b39d4f1223684389291d83ee6ebc58e5caaf31b4fcf13ddbff10ba0b35e69372572ac212b0faa5f42bf8e65ca58b3e2697f7e5a99c509f83e6cf07a9c4e452b15bf6b5e8c63fe4e50a66f983406d97380fe996c9305c8d878179046ddd667795a0aa83926b12352fc28269b4b04847d31d479f08c04cb316cd00976663a40bad563a7c083078cf1ee09162c59f57e4e3ec233f16f4393aa6f25bc4a93926d4cda64ec6c21930e29dd')
    invalid_blind_out = secp256k1_rangeproof_rewind(ctx, nonce, commit, invalid_proof, None, secp256k1_generator_const_h)
    assert invalid_blind_out is None

    # Test rewinding rangeproof with invalid types
    with pytest.raises(TypeError):
        secp256k1_rangeproof_rewind(None, nonce, commit, proof_without_extra_commit, None, secp256k1_generator_const_h)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_rewind('string', nonce, commit, proof_without_extra_commit, None, secp256k1_generator_const_h)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_rewind(ctx, None, commit, proof_without_extra_commit, None, secp256k1_generator_const_h)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_rewind(ctx, 'string', commit, proof_without_extra_commit, None, secp256k1_generator_const_h)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_rewind(ctx, nonce, None, proof_without_extra_commit, None, secp256k1_generator_const_h)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_rewind(ctx, nonce, 'string', proof_without_extra_commit, None, secp256k1_generator_const_h)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_rewind(ctx, nonce, commit, None, None, secp256k1_generator_const_h)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_rewind(ctx, nonce, commit, 'string', None, secp256k1_generator_const_h)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_rewind(ctx, nonce, commit, proof_without_extra_commit, 'string', secp256k1_generator_const_h)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_rewind(ctx, nonce, commit, proof_without_extra_commit, None, None)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_rewind(ctx, nonce, commit, proof_without_extra_commit, None, 'string')

def test_secp256k1_rangeproof_sign():
    # Test creating rangeproof without optional
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    value = 123456789
    valid_blind = bytes.fromhex('1fa9603de2484636f6ba326486c7d98c26c12b23d1ec024fa45c1ed689e60a97')
    commit = secp256k1_pedersen_commit(ctx, valid_blind, value, secp256k1_generator_const_h, secp256k1_generator_const_g)
    assert commit is not None
    nonce = bytes.fromhex('909a8befc5beaeb9b43afc7476b6e1c87e522fb85abc162ff10e26c98306540f')
    proof_without_optional = secp256k1_rangeproof_sign(ctx, 0, commit, valid_blind, nonce, 0, 0, value, None, None, secp256k1_generator_const_h)
    assert proof_without_optional == bytes.fromhex('401a9009d78bce88c76a0b7bd52d4b307edae626ebb82eaab20a7ac0abd915fcd8bfc863f849270e5d2deaf3a8c4b7a8b4b52171232391b4b933eb6564de2a6ce423cc1eb6c445ccea4eb92d78f972e0ba7b43bd9cb4f384406e112b79bfe78af65f1dafb2849cae4a093db4a700bf3c3fd57cb0333670bac6855c349907bf33b79cb7ba7aeb3bed6be546f4704fde2b0656e9e0827901e837f04ffeee3d3326d637e641be20f673f0a537c3995b130f2e657af47d3c047b22f018f5470d7a2a0b1a9df35fa93d9b59bba7bf2d6219347631e70f8725bba1f9a106eefda3fffc4742150e3a77478770c902df97d0989769c1da0177d7ec817fbb079eedf7349c5b3dd6a0761726c084922350b18c40afe9da699373431c5c0d7c09e4fb985c9468a49e8cfa9b11e24c952d5541ed71691c6d461814095f0fe5556c9b9479bfc62f55e19043a99bc058409203ac076a68cc10d64c00bdfc77b0582a262a4653bb6bfdf98e5e0a841e164065b241daace1ab00a9a7422e8bd7cf8efccfc432e33fcd24f070b80f332ea5c412e0163a7edda790a17385824d39e7f724b6a3a40ed28c465add4ee5181fd9ff94050238d00b03f79d864bac4db331dcdce09d0e0d462a98295cd903f91a89d42a3a4023648a6f8770c9014a9fdb82d2d6b7b64b12739f60403c37d019389f4aa5c93c706a58a4be5ed2220e7f007e55f8fa7fb589016ac14fe8dc3173b78c11f657a97ed7a7c09cd6d4e4501eb8ea3f7a6d69f7a9e3e8ee6c3aacd148b4efc31035ee9ec3b1a22dfca21d7e5ae3c297ccc93fe7f53c1a8aab3eb2d3d5acb9a05434cff106902e84fcf10256ea8e0a14353b1da73664e724d83f7fcc5dbccc0bd30d8d590cc42c5d9fc504aff996efe9b6dfb558bb87c105393b192c793cc6d59607de5370531cdc7fdb63413ad8752da58cc086c99efea0a204a86ae59ca68837daa827fd30410fa86c740f459a8d4183736489d61bf0c686e98035996278c793f27004c49f6a913c202e5e191957207f8e3dbacedf790499d2f38d4afdfad976d058d0a5f8665b0f847a841e72eb84dc8a734fbcb9048b68a82526ffff4192e9cd7db62e31748707813ebc6726c2a918664ceaad2aa2822d4978ea194dc6db912f3cc07b73dc1e2bffcc7945f41eb6b8809ac945a7197de0a337c0f70628edb72a7ba7fb8802b0239208a6e41923b00afb0c93836862c5404919803eaa36ec61e5fdf9e34da6c34c7ca56b1a62cc15842185a81ae01d845bac7e2e799c636ac17bd63121f66665aa716464b6ce025c1006d52b75754725a898b0daeae1635f1e18290d8aa1937fd1209acda8454c51418fe25642d7eabd75a84727109bcec617e1922353aee7e0b3fa3364efc2df64dfff6709e1946caf625d4764d8833016c3ad3c9918fcb2b71fbca3418d353937bed7beb326f74f188336e823bf15e5658113dcbf4fbb45e42de14704754cffc4d578107ee9971802267838705c25b289998734bad657953560d1dd7a20362a0c2fb627693c6c78afc1f14bf5dc9d5f775302340344f3011719b0f0616f9439f3b1a77b9fa032be6657e64a65d180632444d67a670ecb685e221818628dae67e08c9a15ad2bb779f2f8b22b44806007e502c5fcefe2d7232fcf1073586fb3ba98007cd1ca32f03383e22624d1f2204069fb827092b8559e2ff50b813c681fe8389c8f800f20766a70e51b87cc079ae0123b1e063f427b15f4c5cebd5d4797a647e87574b419eff8faaf10d72053ab648876ebe00114faa75d0306b49e4a9836def3de8aa6f3ed32c5c13a9a374c02c8886e4cfebf5f792ba257c99a720553da11d9a8ad0e195d22d821524ba7c82e194c25fc127fffa57705ab1a178e509edf989ffed589cd3131c15c3656248167c49bc940e90a5caa60514e4f7c2a48ad641a1f9a679d2a53c830e827db455c90193641695bd31d70d6fbaf2f3897fc2ef5d94167f016ab7620cbce843c0baa19d3c64558007d15e3fac2c4a2e2870c8588ec5aa0b3486d29d1295516610247a0861a7d1d0d29fef4f600d6b2f2bc6fea2a1a25d430344bedf25d08fce2c7b32d6d9724b3e7d31a9b2d43026e749ac2c109ff1049024b860e3c2ec094e97155e70c0b39563e9f3fa036e3ea404dc25813fa056dd79717e6056206d7b2db6786e21d4668f54a8c017bac7bc1e8f3b579aa45f38fac394d6d636596c33c0d233675b2bde1011b86212b132272dff06101e8ed160937d62078239c2004b691fa539054003f3c872d960083b46693edb67bc0577c16721b3304311485b934666ab5583d30a851a824052cd4a1d6e2ac518b02b7d550726a16078e20b6b5c6b651b941b89af53a0c8827fa4fabe849130fd7e143ab8dd6a7eb33d71c956b0abd701c26ec46412b867734f9f65ede42a55dcd4396a286e4c6ce5a25121f003a41eedda151a84f188600d8d0e6e5dcbd1c53bfbf808fea696ed23958b113508a2ed560c9c1d33f8dda28b3eb17fa110559c3a49276be4bc47e8a694196ac85faee279c3937215289b9f406350608448a2193bfd5128b7002e3806c263d35ec01773eefb9ba1aed729edd452d5f06c92d323fe5eea096c74363d0f8fd22f8f3244b56da818cf22326b60875b176ea3fac63eeb2a306895101d23191a95ca44a57fcb24ccd72fe74bb61aadb5c83d80045040be492b6fdddf0094eb562c59e93e878d73cb07c33867b235bc8fe4e801f9aef28c2d63db0e648a4bc6d54c9cff5d904832a325a3118afce62d7a2c4db6e3ad93d87987763456f8890a2aa23e5537db73855000410217334f130a49eb59c55d4e5991b8f86bc8b39d4f1223684389291d83ee6ebc58e5caaf31b4fcf13ddbff10ba0b35e69372572ac212b0faa5f42bf8e65ca58b3e2697f7e5a99c509f83e6cf07a9c4e452b15bf6b5e8c63fe4e5025759daa092853940cd9856fac683ca0e45d5b22beb40d47546e4cd261383e7528269b4b04847d31d479f08c04cb316cd00976663a40bad563a7c083078cf1eee915557b41046bfc37c4e3eae70da1f424675cde40295cb42cad7330be95743b')

    # Test creating rangeproof with message
    message = bytes.fromhex('000102030405')
    proof_with_message = secp256k1_rangeproof_sign(ctx, 0, commit, valid_blind, nonce, 0, 0, value, message, None, secp256k1_generator_const_h)
    assert proof_with_message == bytes.fromhex('401a9009d78bce88c76a0b7bd52d4b307edae626ebb82eaab20a7ac0abd915fcd8bfc863f849270e5d2deaf3a8c4b7a8b4b52171232391b4b933eb6564de2a6ce423cc1eb6c445ccea4eb92d78f972e0ba7b43bd9cb4f384406e112b79bfe78af65f1dafb2849cae4a093db4a700bf3c3fd57cb0333670bac6855c349907bf33b79cb7ba7aeb3bed6be546f4704fde2b0656e9e0827901e837f04ffeee3d3326d637e641be20f673f0a537c3995b130f2e657af47d3c047b22f018f5470d7a2a0b1a9df35fa93d9b59bba7bf2d6219347631e70f8725bba1f9a106eefda3fffc4742150e3a77478770c902df97d0989769c1da0177d7ec817fbb079eedf7349c5b3dd6a0761726c084922350b18c40afe9da699373431c5c0d7c09e4fb985c9468a49e8cfa9b11e24c952d5541ed71691c6d461814095f0fe5556c9b9479bfc62f55e19043a99bc058409203ac076a68cc10d64c00bdfc77b0582a262a4653bb6bfdf98e5e0a841e164065b241daace1ab00a9a7422e8bd7cf8efccfc432e33fcd24f070b80f332ea5c412e0163a7edda790a17385824d39e7f724b6a3a40ed28c465add4ee5181fd9ff94050238d00b03f79d864bac4db331dcdce09d0e0d462a98295cd902fb198dd12a3a4023648a6f8770c9014a9fdb82d2d6b7b64b12739f60403c5e4298af009cb55a7eb5720d64aa8b5b7d94cc092c83b5b80c09ea9a02f20bf5dc3173b78c11f657a97ed7a7c09cd6d4e4501eb8ea3f7a6d69f7a9e3e8ee6c3aacd148b4efc31035ee9ec3b1a22dfca21d7e5ae3c297ccc93fe7f53c1a8aab3eb2d3d5acb9a05434cff106902e84fcf10256ea8e0a14353b1da73664e724d83f7fcc5dbccc0bd30d8d590cc42c5d9fc504aff996efe9b6dfb558bb87c105393b192c793cc6d59607de5370531cdc7fdb63413ad8752da58cc086c99efea0a204a86ae59ca68837daa827fd30410fa86c740f459a8d4183736489d61bf0c686e98035996278c793f27004c49f6a913c202e5e191957207f8e3dbacedf790499d2f38d4afdfad976d058d0a5f8665b0f847a841e72eb84dc8a734fbcb9048b68a82526ffff4192e9cd7db62e31748707813ebc6726c2a918664ceaad2aa2822d4978ea194dc6db912f3cc07b73dc1e2bffcc7945f41eb6b8809ac945a7197de0a337c0f70628edb72a7ba7fb8802b0239208a6e41923b00afb0c93836862c5404919803eaa36ec61e5fdf9e34da6c34c7ca56b1a62cc15842185a81ae01d845bac7e2e799c636ac17bd63121f66665aa716464b6ce025c1006d52b75754725a898b0daeae1635f1e18290d8aa1937fd1209acda8454c51418fe25642d7eabd75a84727109bcec617e1922353aee7e0b3fa3364efc2df64dfff6709e1946caf625d4764d8833016c3ad3c9918fcb2b71fbca3418d353937bed7beb326f74f188336e823bf15e5658113dcbf4fbb45e42de14704754cffc4d578107ee9971802267838705c25b289998734bad657953560d1dd7a20362a0c2fb627693c6c78afc1f14bf5dc9d5f775302340344f3011719b0f0616f9439f3b1a77b9fa032be6657e64a65d180632444d67a670ecb685e221818628dae67e08c9a15ad2bb779f2f8b22b44806007e502c5fcefe2d7232fcf1073586fb3ba98007cd1ca32f03383e22624d1f2204069fb827092b8559e2ff50b813c681fe8389c8f800f20766a70e51b87cc079ae0123b1e063f427b15f4c5cebd5d4797a647e87574b419eff8faaf10d72053ab648876ebe00114faa75d0306b49e4a9836def3de8aa6f3ed32c5c13a9a374c02c8886e4cfebf5f792ba257c99a720553da11d9a8ad0e195d22d821524ba7c82e194c25fc127fffa57705ab1a178e509edf989ffed589cd3131c15c3656248167c49bc940e90a5caa60514e4f7c2a48ad641a1f9a679d2a53c830e827db455c90193641695bd31d70d6fbaf2f3897fc2ef5d94167f016ab7620cbce843c0baa19d3c64558007d15e3fac2c4a2e2870c8588ec5aa0b3486d29d1295516610247a0861a7d1d0d29fef4f600d6b2f2bc6fea2a1a25d430344bedf25d08fce2c7b32d6d9724b3e7d31a9b2d43026e749ac2c109ff1049024b860e3c2ec094e97155e70c0b39563e9f3fa036e3ea404dc25813fa056dd79717e6056206d7b2db6786e21d4668f54a8c017bac7bc1e8f3b579aa45f38fac394d6d636596c33c0d233675b2bde1011b86212b132272dff06101e8ed160937d62078239c2004b691fa539054003f3c872d960083b46693edb67bc0577c16721b3304311485b934666ab5583d30a851a824052cd4a1d6e2ac518b02b7d550726a16078e20b6b5c6b651b941b89af53a0c8827fa4fabe849130fd7e143ab8dd6a7eb33d71c956b0abd701c26ec46412b867734f9f65ede42a55dcd4396a286e4c6ce5a25121f003a41eedda151a84f188600d8d0e6e5dcbd1c53bfbf808fea696ed23958b113508a2ed560c9c1d33f8dda28b3eb17fa110559c3a49276be4bc47e8a694196ac85faee279c3937215289b9f406350608448a2193bfd5128b7002e3806c263d35ec01773eefb9ba1aed729edd452d5f06c92d323fe5eea096c74363d0f8fd22f8f3244b56da818cf22326b60875b176ea3fac63eeb2a306895101d23191a95ca44a57fcb24ccd72fe74bb61aadb5c83d80045040be492b6fdddf0094eb562c59e93e878d73cb07c33867b235bc8fe4e801f9aef28c2d63db0e648a4bc6d54c9cff5d904832a325a3118afce62d7a2c4db6e3ad93d87987763456f8890a2aa23e5537db73855000410217334f130a49eb59c55d4e5991b8f86bc8b39d4f1223684389291d83ee6ebc58e5caaf31b4fcf13ddbff10ba0b35e69372572ac212b0faa5f42bf8e65ca58b3e2697f7e5a99c509f83e6cf07a9c4e452b15bf6b5e8c63fe4e5025759daa092853940cd9856fac683ca0e45d5b22beb40d47546e4cd261383e7528269b4b04847d31d479f08c04cb316cd00976663a40bad563a7c083078cf1eee915557b41046bfc37c4e3eae70da1f424675cde40295cb42cad7330be95743b')

    # Test creating rangeproof with extra commit
    extra_commit = bytes.fromhex('060708090a')
    proof_with_extra_commit = secp256k1_rangeproof_sign(ctx, 0, commit, valid_blind, nonce, 0, 0, value, None, extra_commit, secp256k1_generator_const_h)
    assert proof_with_extra_commit == bytes.fromhex('401a9009d78bce88c76a0b7bd52d4b307edae626ebb82eaab20a7ac0abd915fcd8bfc863f849270e5d2deaf3a8c4b7a8b4b52171232391b4b933eb6564de2a6ce423cc1eb6c445ccea4eb92d78f972e0ba7b43bd9cb4f384406e112b79bfe78af65f1dafb2849cae4a093db4a700bf3c3fd57cb0333670bac6855c349907bf33b79cb7ba7aeb3bed6be546f4704fde2b0656e9e0827901e837f04ffeee3d3326d637e641be20f673f0a537c3995b130f2e657af47d3c047b22f018f5470d7a2a0b1a9df35fa93d9b59bba7bf2d6219347631e70f8725bba1f9a106eefda3fffc4742150e3a77478770c902df97d0989769c1da0177d7ec817fbb079eedf7349c5b3dd6a0761726c084922350b18c40afe9da699373431c5c0d7c09e4fb985c9468a49e8cfa9b11e24c952d5541ed71691c6d461814095f0fe5556c9b9479bfc62f55e19043a99bc058409203ac076a68cc10d64c00bdfc77b0582a262a4653bb6bfdf98e5e0a841e164065b241daace1ab00a9a7422e8bd7cf8efccfc432e33fcd24f070b80f332ea5c412e0163a7edda790a17385824d39e7f724b6a3a40ed28c465adde3683c789556d7fedd7a7646dce2b0586a230134113001f356ab7f630fee1d0ed903f91a89d42a3a4023648a6f8770c9014a9fdb82d2d6b7b64b12739f60403cb306621c24a2b1cf4f94ac90abf5910e068e55e355d2ebccf97bd533a89cc8d0dc3173b78c11f657a97ed7a7c09cd6d4e4501eb8ea3f7a6d69f7a9e3e8ee6c3aacd148b4efc31035ee9ec3b1a22dfca21d7e5ae3c297ccc93fe7f53c1a8aab3eb2d3d5acb9a05434cff106902e84fcf10256ea8e0a14353b1da73664e724d83fe42aaa8153b565b8abfa916bd52ddb4ffa4f3388f456107aecae2acb0772a322192c793cc6d59607de5370531cdc7fdb63413ad8752da58cc086c99efea0a204a86ae59ca68837daa827fd30410fa86c740f459a8d4183736489d61bf0c686e98035996278c793f27004c49f6a913c202e5e191957207f8e3dbacedf790499d242f059b9e840d7307c657544ef34f8d539653f5d0d87ecbceb38da7ceed2d89a2526ffff4192e9cd7db62e31748707813ebc6726c2a918664ceaad2aa2822d4978ea194dc6db912f3cc07b73dc1e2bffcc7945f41eb6b8809ac945a7197de0a3888ffa18fedb9f99a6fda27bcd853776bc14945f9dc1399432372b376d2522f919803eaa36ec61e5fdf9e34da6c34c7ca56b1a62cc15842185a81ae01d845bac7e2e799c636ac17bd63121f66665aa716464b6ce025c1006d52b75754725a898b0daeae1635f1e18290d8aa1937fd1209acda8454c51418fe25642d7eabd75a84727109bcec617e1922353aee7e0b3fa3364efc2df64dfff6709e1946caf625d798ed0d2a490a5c489dfcaba2992a9813cc0c9c5259fb1ed9f7e84c0f7e720e6e823bf15e5658113dcbf4fbb45e42de14704754cffc4d578107ee9971802267838705c25b289998734bad657953560d1dd7a20362a0c2fb627693c6c78afc1f14bf5dc9d5f775302340344f3011719b0f0616f9439f3b1a77b9fa032be6657e64a65d180632444d67a670ecb685e221818628dae67e08c9a15ad2bb779f2f8b22b44806007e502c5fcefe2d7232fcf1073586fb3ba98007cd1ca32f03383e22636015330143001ee30ee0cd2410482372a331b17906ab06e4363dba2df1688e7ec6848966e34f597f6f0b6955be181539701a0197e694dc314a9fdfe672d340cd72053ab648876ebe00114faa75d0306b49e4a9836def3de8aa6f3ed32c5c13a9a374c02c8886e4cfebf5f792ba257c99a720553da11d9a8ad0e195d22d821524ba7c82e194c25fc127fffa57705ab1a178e509edf989ffed589cd3131c15c3656248167c49bc940e90a5caa60514e4f7c2a48ad641a1f9a679d2a53c830e827db455c90193641695bd31d70d6fbaf2f3897fc2ef5d94167f016ab7620cbce843c0baa19d3c64558007d15e3fac2c4a2e2870c8588ec5aa0b3486d29d1295516efacc0144249e5b202ca93f54b5c43cc91c611501318519f9d88dfdbd3a72f43e2c7b32d6d9724b3e7d31a9b2d43026e749ac2c109ff1049024b860e3c2ec094e97155e70c0b39563e9f3fa036e3ea404dc25813fa056dd79717e6056206d7b2db6786e21d4668f54a8c017bac7bc1e8f3b579aa45f38fac394d6d636596c33c39e4cf638b4811b6d40a8564ddb2a307d5e26939a39235dd7de610cc89d3979891fa539054003f3c872d960083b46693edb67bc0577c16721b3304311485b934666ab5583d30a851a824052cd4a1d6e2ac518b02b7d550726a16078e20b6b5c66fc7d3fbfcf7303b5b85962b8efeeabaebc35c362c4c4b1fe0fbe39852874a69bd701c26ec46412b867734f9f65ede42a55dcd4396a286e4c6ce5a25121f003a41eedda151a84f188600d8d0e6e5dcbd1c53bfbf808fea696ed23958b113508aeeb3aa6dae558973c2ce8c568ba34d1cd436629b19019188052f835e8032152eee279c3937215289b9f406350608448a2193bfd5128b7002e3806c263d35ec01773eefb9ba1aed729edd452d5f06c92d323fe5eea096c74363d0f8fd22f8f3244b56da818cf22326b60875b176ea3fac63eeb2a306895101d23191a95ca44a57ac4e57a8008f001c6382e6425d1375796fce09b0557be576b96fb94ea86ca5a678d73cb07c33867b235bc8fe4e801f9aef28c2d63db0e648a4bc6d54c9cff5d904832a325a3118afce62d7a2c4db6e3ad93d87987763456f8890a2aa23e5537db73855000410217334f130a49eb59c55d4e5991b8f86bc8b39d4f1223684389291d83ee6ebc58e5caaf31b4fcf13ddbff10ba0b35e69372572ac212b0faa5f42bf8e65ca58b3e2697f7e5a99c509f83e6cf07a9c4e452b15bf6b5e8c63fe4e50a66f983406d97380fe996c9305c8d878179046ddd667795a0aa83926b12352fc28269b4b04847d31d479f08c04cb316cd00976663a40bad563a7c083078cf1ee09162c59f57e4e3ec233f16f4393aa6f25bc4a93926d4cda64ec6c21930e29dd')

    # Test creating rangeproof with all
    proof_with_all = secp256k1_rangeproof_sign(ctx, 0, commit, valid_blind, nonce, 0, 0, value, message, extra_commit, secp256k1_generator_const_h)
    assert proof_with_all == bytes.fromhex('401a9009d78bce88c76a0b7bd52d4b307edae626ebb82eaab20a7ac0abd915fcd8bfc863f849270e5d2deaf3a8c4b7a8b4b52171232391b4b933eb6564de2a6ce423cc1eb6c445ccea4eb92d78f972e0ba7b43bd9cb4f384406e112b79bfe78af65f1dafb2849cae4a093db4a700bf3c3fd57cb0333670bac6855c349907bf33b79cb7ba7aeb3bed6be546f4704fde2b0656e9e0827901e837f04ffeee3d3326d637e641be20f673f0a537c3995b130f2e657af47d3c047b22f018f5470d7a2a0b1a9df35fa93d9b59bba7bf2d6219347631e70f8725bba1f9a106eefda3fffc4742150e3a77478770c902df97d0989769c1da0177d7ec817fbb079eedf7349c5b3dd6a0761726c084922350b18c40afe9da699373431c5c0d7c09e4fb985c9468a49e8cfa9b11e24c952d5541ed71691c6d461814095f0fe5556c9b9479bfc62f55e19043a99bc058409203ac076a68cc10d64c00bdfc77b0582a262a4653bb6bfdf98e5e0a841e164065b241daace1ab00a9a7422e8bd7cf8efccfc432e33fcd24f070b80f332ea5c412e0163a7edda790a17385824d39e7f724b6a3a40ed28c465adde3683c789556d7fedd7a7646dce2b0586a230134113001f356ab7f630fee1d0ed902fb198dd12a3a4023648a6f8770c9014a9fdb82d2d6b7b64b12739f60403ceca1fef693520ac8fb8b16c9cbbf4c309918319f62cdf3e30407dbfae2af5da7dc3173b78c11f657a97ed7a7c09cd6d4e4501eb8ea3f7a6d69f7a9e3e8ee6c3aacd148b4efc31035ee9ec3b1a22dfca21d7e5ae3c297ccc93fe7f53c1a8aab3eb2d3d5acb9a05434cff106902e84fcf10256ea8e0a14353b1da73664e724d83fe42aaa8153b565b8abfa916bd52ddb4ffa4f3388f456107aecae2acb0772a322192c793cc6d59607de5370531cdc7fdb63413ad8752da58cc086c99efea0a204a86ae59ca68837daa827fd30410fa86c740f459a8d4183736489d61bf0c686e98035996278c793f27004c49f6a913c202e5e191957207f8e3dbacedf790499d242f059b9e840d7307c657544ef34f8d539653f5d0d87ecbceb38da7ceed2d89a2526ffff4192e9cd7db62e31748707813ebc6726c2a918664ceaad2aa2822d4978ea194dc6db912f3cc07b73dc1e2bffcc7945f41eb6b8809ac945a7197de0a3888ffa18fedb9f99a6fda27bcd853776bc14945f9dc1399432372b376d2522f919803eaa36ec61e5fdf9e34da6c34c7ca56b1a62cc15842185a81ae01d845bac7e2e799c636ac17bd63121f66665aa716464b6ce025c1006d52b75754725a898b0daeae1635f1e18290d8aa1937fd1209acda8454c51418fe25642d7eabd75a84727109bcec617e1922353aee7e0b3fa3364efc2df64dfff6709e1946caf625d798ed0d2a490a5c489dfcaba2992a9813cc0c9c5259fb1ed9f7e84c0f7e720e6e823bf15e5658113dcbf4fbb45e42de14704754cffc4d578107ee9971802267838705c25b289998734bad657953560d1dd7a20362a0c2fb627693c6c78afc1f14bf5dc9d5f775302340344f3011719b0f0616f9439f3b1a77b9fa032be6657e64a65d180632444d67a670ecb685e221818628dae67e08c9a15ad2bb779f2f8b22b44806007e502c5fcefe2d7232fcf1073586fb3ba98007cd1ca32f03383e22636015330143001ee30ee0cd2410482372a331b17906ab06e4363dba2df1688e7ec6848966e34f597f6f0b6955be181539701a0197e694dc314a9fdfe672d340cd72053ab648876ebe00114faa75d0306b49e4a9836def3de8aa6f3ed32c5c13a9a374c02c8886e4cfebf5f792ba257c99a720553da11d9a8ad0e195d22d821524ba7c82e194c25fc127fffa57705ab1a178e509edf989ffed589cd3131c15c3656248167c49bc940e90a5caa60514e4f7c2a48ad641a1f9a679d2a53c830e827db455c90193641695bd31d70d6fbaf2f3897fc2ef5d94167f016ab7620cbce843c0baa19d3c64558007d15e3fac2c4a2e2870c8588ec5aa0b3486d29d1295516efacc0144249e5b202ca93f54b5c43cc91c611501318519f9d88dfdbd3a72f43e2c7b32d6d9724b3e7d31a9b2d43026e749ac2c109ff1049024b860e3c2ec094e97155e70c0b39563e9f3fa036e3ea404dc25813fa056dd79717e6056206d7b2db6786e21d4668f54a8c017bac7bc1e8f3b579aa45f38fac394d6d636596c33c39e4cf638b4811b6d40a8564ddb2a307d5e26939a39235dd7de610cc89d3979891fa539054003f3c872d960083b46693edb67bc0577c16721b3304311485b934666ab5583d30a851a824052cd4a1d6e2ac518b02b7d550726a16078e20b6b5c66fc7d3fbfcf7303b5b85962b8efeeabaebc35c362c4c4b1fe0fbe39852874a69bd701c26ec46412b867734f9f65ede42a55dcd4396a286e4c6ce5a25121f003a41eedda151a84f188600d8d0e6e5dcbd1c53bfbf808fea696ed23958b113508aeeb3aa6dae558973c2ce8c568ba34d1cd436629b19019188052f835e8032152eee279c3937215289b9f406350608448a2193bfd5128b7002e3806c263d35ec01773eefb9ba1aed729edd452d5f06c92d323fe5eea096c74363d0f8fd22f8f3244b56da818cf22326b60875b176ea3fac63eeb2a306895101d23191a95ca44a57ac4e57a8008f001c6382e6425d1375796fce09b0557be576b96fb94ea86ca5a678d73cb07c33867b235bc8fe4e801f9aef28c2d63db0e648a4bc6d54c9cff5d904832a325a3118afce62d7a2c4db6e3ad93d87987763456f8890a2aa23e5537db73855000410217334f130a49eb59c55d4e5991b8f86bc8b39d4f1223684389291d83ee6ebc58e5caaf31b4fcf13ddbff10ba0b35e69372572ac212b0faa5f42bf8e65ca58b3e2697f7e5a99c509f83e6cf07a9c4e452b15bf6b5e8c63fe4e50a66f983406d97380fe996c9305c8d878179046ddd667795a0aa83926b12352fc28269b4b04847d31d479f08c04cb316cd00976663a40bad563a7c083078cf1ee09162c59f57e4e3ec233f16f4393aa6f25bc4a93926d4cda64ec6c21930e29dd')

    # Test creating invalid rangeproof
    invalid_blind = bytes.fromhex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
    invalid_proof = secp256k1_rangeproof_sign(ctx, 0, commit, invalid_blind, nonce, 0, 0, value, message, extra_commit, secp256k1_generator_const_h)
    assert invalid_proof is None

    # Test creating rangeproof with invalid types
    with pytest.raises(TypeError):
        secp256k1_rangeproof_sign(None, 0, commit, valid_blind, nonce, 0, 0, value, message, extra_commit, secp256k1_generator_const_h)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_sign('string', 0, commit, valid_blind, nonce, 0, 0, value, message, extra_commit, secp256k1_generator_const_h)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_sign(ctx, None, commit, valid_blind, nonce, 0, 0, value, message, extra_commit, secp256k1_generator_const_h)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_sign(ctx, 'string', commit, valid_blind, nonce, 0, 0, value, message, extra_commit, secp256k1_generator_const_h)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_sign(ctx, 0, None, valid_blind, nonce, 0, 0, value, message, extra_commit, secp256k1_generator_const_h)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_sign(ctx, 0, 'string', valid_blind, nonce, 0, 0, value, message, extra_commit, secp256k1_generator_const_h)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_sign(ctx, 0, commit, None, nonce, 0, 0, value, message, extra_commit, secp256k1_generator_const_h)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_sign(ctx, 0, commit, 'string', nonce, 0, 0, value, message, extra_commit, secp256k1_generator_const_h)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_sign(ctx, 0, commit, valid_blind, None, 0, 0, value, message, extra_commit, secp256k1_generator_const_h)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_sign(ctx, 0, commit, valid_blind, 'string', 0, 0, value, message, extra_commit, secp256k1_generator_const_h)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_sign(ctx, 0, commit, valid_blind, nonce, None, 0, value, message, extra_commit, secp256k1_generator_const_h)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_sign(ctx, 0, commit, valid_blind, nonce, 'string', 0, value, message, extra_commit, secp256k1_generator_const_h)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_sign(ctx, 0, commit, valid_blind, nonce, 0, None, value, message, extra_commit, secp256k1_generator_const_h)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_sign(ctx, 0, commit, valid_blind, nonce, 0, 'string', value, message, extra_commit, secp256k1_generator_const_h)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_sign(ctx, 0, commit, valid_blind, nonce, 0, 0, None, message, extra_commit, secp256k1_generator_const_h)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_sign(ctx, 0, commit, valid_blind, nonce, 0, 0, 'string', message, extra_commit, secp256k1_generator_const_h)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_sign(ctx, 0, commit, valid_blind, nonce, 0, 0, value, 'string', extra_commit, secp256k1_generator_const_h)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_sign(ctx, 0, commit, valid_blind, nonce, 0, 0, value, message, 'string', secp256k1_generator_const_h)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_sign(ctx, 0, commit, valid_blind, nonce, 0, 0, value, message, extra_commit, None)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_sign(ctx, 0, commit, valid_blind, nonce, 0, 0, value, message, extra_commit, 'string')

    # Test creating rangeproof with invalid values
    with pytest.raises(OverflowError):
        secp256k1_rangeproof_sign(ctx, -1, commit, valid_blind, nonce, 0, 0, value, message, extra_commit, secp256k1_generator_const_h)
    with pytest.raises(OverflowError):
        secp256k1_rangeproof_sign(ctx, 0x10000000000000000, commit, valid_blind, nonce, 0, 0, value, message, extra_commit, secp256k1_generator_const_h)
    with pytest.raises(OverflowError):
        secp256k1_rangeproof_sign(ctx, 0, commit, valid_blind, nonce, 0x80000000, 0, value, message, extra_commit, secp256k1_generator_const_h)
    with pytest.raises(OverflowError):
        secp256k1_rangeproof_sign(ctx, 0, commit, valid_blind, nonce, 0, 0x80000000, value, message, extra_commit, secp256k1_generator_const_h)
    with pytest.raises(OverflowError):
        secp256k1_rangeproof_sign(ctx, 0, commit, valid_blind, nonce, 0, 0, -1, message, extra_commit, secp256k1_generator_const_h)
    with pytest.raises(OverflowError):
        secp256k1_rangeproof_sign(ctx, 0, commit, valid_blind, nonce, 0, 0, 0x10000000000000000, message, extra_commit, secp256k1_generator_const_h)

def test_secp256k1_rangeproof_info():
    # Test getting rangeproof info
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    valid_proof = bytes.fromhex('62070000000000000056022a5c420e1d51e1b7f36904b5bb9b416614f3644226e3a76a06bba85a496f1976fbe5757788aba9664480ea29957fdf724aaf02bedd5d15d8aeff74c98c1a670eb2572299c321466f15580edbe66ec40dfe6f046b0d183d784098564ee44a7490a7ac9c16e03e81af0fe34f349952f7a7f6d383a0174b2da7d4fdf78445c411713d4a2234099ca7e5c8ba04bffd25117da44345c7629e7b80f609bb1b2ef3cd23e0ed814342bec49f588a0d6679097011683d87381c3c85525b62f73e7e87a29924d07d18635648a43afe65faa4d067aa98654de422754552e841c7ed38ebf50290c945a3b04d03d7ab43e421fc83d6121d76b13c67631f529dc3235c4ea68d014aba9af4165b67c8e1d2426ddfcd086a73416ac284c631be57cb0edebf71d58af724b2a78996624fd9f7c3de4cab1372b4b3350482a8751dde46a80db823440044fa536c2dced3a680a120cad163bbbe395f9d2769b3331fdbda670537be65e97ea9c3ff378ab42dfef21685c70fd9be14d180149f58569841f626f7a27166b47a9c1273d3df772b49e5ca5057446e3f5856bc21704fc6aa12ff7ca73ded46c140e658092adab376ab44b54eb312e0268a52ac491de706533a0135212e8648c575c1a27d2253f63f41c5b3087da367c0bbb68df0d30172d36382011ae71d22fa9533f6f2dea25386555ab42e7575c6d5939c57a91fb93ee81cbfac1c546ff5ab41eeb30ed076c41a45cdf1d6ccb0837073bc8874a05be7981036bfec231cc2b5ba4b9d7f8c8ae2da18ddab278a15ebb0d43a8b7700c7bbccfabaa46a175cf8515d8d16cda70e719798785a41b3f01f872d65cd2949d2872c91a95fcca9d8bb5318e7d6ec65a645f6cecf48f61e3dd2cfcb3acdbb922924167f8aa85c0c457133')
    valid_exp, valid_mantissa, valid_min_value, valid_max_value = secp256k1_rangeproof_info(ctx, valid_proof)
    assert valid_exp == 2 and valid_mantissa == 8 and valid_min_value == 86 and valid_max_value == 25586

    # Test getting invalid rangeproof info
    invalid_proof = bytes.fromhex('72070000000000000056022a5c420e1d51e1b7f36904b5bb9b416614f3644226e3a76a06bba85a496f1976fbe5757788aba9664480ea29957fdf724aaf02bedd5d15d8aeff74c98c1a670eb2572299c321466f15580edbe66ec40dfe6f046b0d183d784098564ee44a7490a7ac9c16e03e81af0fe34f349952f7a7f6d383a0174b2da7d4fdf78445c411713d4a2234099ca7e5c8ba04bffd25117da44345c7629e7b80f609bb1b2ef3cd23e0ed814342bec49f588a0d6679097011683d87381c3c85525b62f73e7e87a29924d07d18635648a43afe65faa4d067aa98654de422754552e841c7ed38ebf50290c945a3b04d03d7ab43e421fc83d6121d76b13c67631f529dc3235c4ea68d014aba9af4165b67c8e1d2426ddfcd086a73416ac284c631be57cb0edebf71d58af724b2a78996624fd9f7c3de4cab1372b4b3350482a8751dde46a80db823440044fa536c2dced3a680a120cad163bbbe395f9d2769b3331fdbda670537be65e97ea9c3ff378ab42dfef21685c70fd9be14d180149f58569841f626f7a27166b47a9c1273d3df772b49e5ca5057446e3f5856bc21704fc6aa12ff7ca73ded46c140e658092adab376ab44b54eb312e0268a52ac491de706533a0135212e8648c575c1a27d2253f63f41c5b3087da367c0bbb68df0d30172d36382011ae71d22fa9533f6f2dea25386555ab42e7575c6d5939c57a91fb93ee81cbfac1c546ff5ab41eeb30ed076c41a45cdf1d6ccb0837073bc8874a05be7981036bfec231cc2b5ba4b9d7f8c8ae2da18ddab278a15ebb0d43a8b7700c7bbccfabaa46a175cf8515d8d16cda70e719798785a41b3f01f872d65cd2949d2872c91a95fcca9d8bb5318e7d6ec65a645f6cecf48f61e3dd2cfcb3acdbb922924167f8aa85c0c457133')
    invalid_exp = secp256k1_rangeproof_info(ctx, invalid_proof)
    assert invalid_exp is None

    # Test getting rangeproof info with invalid types
    with pytest.raises(TypeError):
        secp256k1_rangeproof_info(None, valid_proof)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_info('string', valid_proof)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_info(ctx, None)
    with pytest.raises(TypeError):
        secp256k1_rangeproof_info(ctx, 'string')

def test_secp256k1_ecdsa_recoverable_signature_parse_compact():
    # Test parsing recoverable signature
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    valid_input64 = bytes.fromhex('67cb285f9cd194e840d629397af5569662fde44649995963179a7dd17bd235324b1b7df34ce1f68e694ff6f11ac751dd7dd73e387ee4fc866e1be8ecc7dd9557')
    valid_sig = secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, valid_input64, 0)
    assert valid_sig is not None

    # Test parsing invalid recoverable signature
    invalid_input64 = bytes.fromhex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff')
    invalid_sig = secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, invalid_input64, 0)
    assert invalid_sig is None

    # Test parsing recoverable signature with invalid types
    with pytest.raises(TypeError):
        secp256k1_ecdsa_recoverable_signature_parse_compact(None, valid_input64, 0)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_recoverable_signature_parse_compact('string', valid_input64, 0)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, None, 0)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, 'string', 0)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, valid_input64, None)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, valid_input64, 'string')

    # Test parsing recoverable signature with invalid values
    with pytest.raises(OverflowError):
        secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, valid_input64, 0x80000000)

def test_secp256k1_ecdsa_recoverable_signature_convert():
    # Test converting recoverable signature
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    input64 = bytes.fromhex('67cb285f9cd194e840d629397af5569662fde44649995963179a7dd17bd235324b1b7df34ce1f68e694ff6f11ac751dd7dd73e387ee4fc866e1be8ecc7dd9557')
    sigin = secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, input64, 0)
    assert sigin is not None
    sig = secp256k1_ecdsa_recoverable_signature_convert(ctx, sigin)
    assert sig is not None
    output64 = secp256k1_ecdsa_signature_serialize_compact(ctx, sig)
    assert output64 == bytes.fromhex('67cb285f9cd194e840d629397af5569662fde44649995963179a7dd17bd235324b1b7df34ce1f68e694ff6f11ac751dd7dd73e387ee4fc866e1be8ecc7dd9557')

    # Test converting recoverable signature with invalid types
    with pytest.raises(TypeError):
        secp256k1_ecdsa_recoverable_signature_convert(None, sigin)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_recoverable_signature_convert('string', sigin)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_recoverable_signature_convert(ctx, None)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_recoverable_signature_convert(ctx, 'string')

def test_secp256k1_ecdsa_recoverable_signature_serialize_compact():
    # Test serializing recoverable signature
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    input64 = bytes.fromhex('67cb285f9cd194e840d629397af5569662fde44649995963179a7dd17bd235324b1b7df34ce1f68e694ff6f11ac751dd7dd73e387ee4fc866e1be8ecc7dd9557')
    sig = secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, input64, 0)
    assert sig is not None
    output64, recid = secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, sig)
    assert output64 == input64 and recid == 0

    # Test serializing recoverable signature with invalid types
    with pytest.raises(TypeError):
        secp256k1_ecdsa_recoverable_signature_serialize_compact(None, sig)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_recoverable_signature_serialize_compact('string', sig)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, None)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, 'string')

def test_secp256k1_ecdsa_sign_recoverable():
    # Test creating recoverable signature with no nonce function
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    msg32 = bytes.fromhex('546869732069732061207665727920736563726574206d6573736167652e2e2e')
    valid_seckey = bytes.fromhex('8c3882fbd7966085e760e000b1ea9eb1ad3df1eec02e720adaa5104c6bd9fd88')
    no_nonce_function_sig = secp256k1_ecdsa_sign_recoverable(ctx, msg32, valid_seckey, None, None)
    assert no_nonce_function_sig is not None
    no_nonce_function_output64, no_nonce_function_recid = secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, no_nonce_function_sig)
    assert no_nonce_function_output64 == bytes.fromhex('8d51d9d7adc8df0c040fbb3183c49f13c529f03c551f0cf0d9d03d58b290598f157a0394c5b539699012fdd2f8d02856d02b455ee5b344e662167ba79dfc102b') and no_nonce_function_recid == 0

    # Test creating recoverable signature with default nonce function
    default_nonce_function_sig = secp256k1_ecdsa_sign_recoverable(ctx, msg32, valid_seckey, secp256k1_nonce_function_default, None)
    assert default_nonce_function_sig is not None
    default_nonce_function_output64, default_nonce_function_recid = secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, default_nonce_function_sig)
    assert default_nonce_function_output64 == bytes.fromhex('8d51d9d7adc8df0c040fbb3183c49f13c529f03c551f0cf0d9d03d58b290598f157a0394c5b539699012fdd2f8d02856d02b455ee5b344e662167ba79dfc102b') and default_nonce_function_recid == 0

    # Test creating recoverable signature with RFC6979 nonce function without nonce data
    rfc6979_nonce_function_without_ndata_sig = secp256k1_ecdsa_sign_recoverable(ctx, msg32, valid_seckey, secp256k1_nonce_function_rfc6979, None)
    assert rfc6979_nonce_function_without_ndata_sig is not None
    rfc6979_nonce_function_without_ndata_output64, rfc6979_nonce_function_without_ndata_recid = secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, rfc6979_nonce_function_without_ndata_sig)
    assert rfc6979_nonce_function_without_ndata_output64 == bytes.fromhex('8d51d9d7adc8df0c040fbb3183c49f13c529f03c551f0cf0d9d03d58b290598f157a0394c5b539699012fdd2f8d02856d02b455ee5b344e662167ba79dfc102b') and rfc6979_nonce_function_without_ndata_recid == 0

    # Test creating recoverable signature with RFC6979 nonce function with nonce data
    ndata = bytes.fromhex('8368fb6bcd437e2685af0d5b71543d2c077bfac05b74307068b06ed96a08bb4f')
    rfc6979_nonce_function_with_ndata_sig = secp256k1_ecdsa_sign_recoverable(ctx, msg32, valid_seckey, secp256k1_nonce_function_rfc6979, ndata)
    assert rfc6979_nonce_function_with_ndata_sig is not None
    rfc6979_nonce_function_with_ndata_output64, rfc6979_nonce_function_with_ndata_recid = secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, rfc6979_nonce_function_with_ndata_sig)
    assert rfc6979_nonce_function_with_ndata_output64 == bytes.fromhex('0eca4e0521eaaf2f5e2204950b590fa99f1f3aa402f166a4e914496b5ad3cb9f13982d4665904f2908886dfd3c86359c3b625e653569a692049707bbf0be3f3b') and rfc6979_nonce_function_with_ndata_recid == 0

    # Test creating an invalid recoverable signature
    invalid_seckey = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
    invalid_sig = secp256k1_ecdsa_sign_recoverable(ctx, msg32, invalid_seckey, None, None)
    assert invalid_sig is None

    # Test creating recoverable signature with invalid types
    with pytest.raises(TypeError):
        secp256k1_ecdsa_sign_recoverable(None, msg32, valid_seckey, None, None)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_sign_recoverable('string', msg32, valid_seckey, None, None)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_sign_recoverable(ctx, None, valid_seckey, None, None)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_sign_recoverable(ctx, 'string', valid_seckey, None, None)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_sign_recoverable(ctx, msg32, None, None, None)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_sign_recoverable(ctx, msg32, 'string', None, None)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_sign_recoverable(ctx, msg32, valid_seckey, 'string', None)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_sign_recoverable(ctx, msg32, valid_seckey, None, 'string')

def test_secp256k1_ecdsa_recover():
    # Test recovering a public key from a recoverable signature
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    input64 = bytes.fromhex('67cb285f9cd194e840d629397af5569662fde44649995963179a7dd17bd235324b1b7df34ce1f68e694ff6f11ac751dd7dd73e387ee4fc866e1be8ecc7dd9557')
    valid_sig = secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, input64, 1)
    assert valid_sig is not None
    msg32 = bytes.fromhex('546869732069732061207665727920736563726574206d6573736167652e2e2e')
    valid_pubkey = secp256k1_ecdsa_recover(ctx, valid_sig, msg32)
    assert valid_pubkey is not None
    output = secp256k1_ec_pubkey_serialize(ctx, valid_pubkey, SECP256K1_EC_COMPRESSED)
    assert output == bytes.fromhex('0386874a6b24a754627116560e7ae15cd69eb33e73b4d8c81033b27c2fa9cf5d1c')

    # Test recovering a public key from an invalid recoverable signature
    invalid_sig = secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, input64, 0)
    assert invalid_sig is not None
    invalid_pubkey = secp256k1_ecdsa_recover(ctx, invalid_sig, msg32)
    assert invalid_pubkey is None

    # Test recovering a public key from a recoverable signature with invalid types
    with pytest.raises(TypeError):
        secp256k1_ecdsa_recover(None, valid_sig, msg32)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_recover('string', valid_sig, msg32)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_recover(ctx, None, msg32)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_recover(ctx, 'string', msg32)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_recover(ctx, valid_sig, None)
    with pytest.raises(TypeError):
        secp256k1_ecdsa_recover(ctx, valid_sig, 'string')

def test_secp256k1_schnorrsig_serialize():
    # Test serializing Schnorr signature
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    in64 = bytes.fromhex('787a848e71043d280c50470e8e1532b2dd5d20ee912a45dbdd2bd1dfbf187ef67031a98831859dc34dffeedda86831842ccd0079e1f92af177f7f22cc1dced05')
    sig = secp256k1_schnorrsig_parse(ctx, in64)
    assert sig is not None
    out64 = secp256k1_schnorrsig_serialize(ctx, sig)
    assert out64 == in64

    # Test serializing Schnorr signature with invalid types
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_serialize(None, sig)
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_serialize('string', sig)
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_serialize(ctx, None)
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_serialize(ctx, 'string')

def test_secp256k1_schnorrsig_parse():
    # Test parsing Schnorr signature
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    in64 = bytes.fromhex('787a848e71043d280c50470e8e1532b2dd5d20ee912a45dbdd2bd1dfbf187ef67031a98831859dc34dffeedda86831842ccd0079e1f92af177f7f22cc1dced05')
    sig = secp256k1_schnorrsig_parse(ctx, in64)
    assert sig is not None

    # Test parsing Schnorr signature with invalid types
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_parse(None, in64)
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_parse('string', in64)
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_parse(ctx, None)
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_parse(ctx, 'string')

def test_secp256k1_schnorrsig_sig():
    # Test creating Schnorr signature with no nonce function
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    msg32 = bytes.fromhex('243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89')
    valid_seckey = bytes.fromhex('b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfef')
    no_nonce_function_sig, no_nonce_function_nonce_is_negated = secp256k1_schnorrsig_sign(ctx, msg32, valid_seckey, None, None)
    assert no_nonce_function_sig is not None and no_nonce_function_nonce_is_negated is False
    no_nonce_function_out64 = secp256k1_schnorrsig_serialize(ctx, no_nonce_function_sig)
    assert no_nonce_function_out64 == bytes.fromhex('2a298dacae57395a15d0795ddbfd1dcb564da82b0f269bc70a74f8220429ba1d1e51a22ccec35599b8f266912281f8365ffc2d035a230434a1a64dc59f7013fd')

    # Test creating Schnorr signature with default nonce function
    default_nonce_function_sig, default_nonce_function_nonce_is_negated = secp256k1_schnorrsig_sign(ctx, msg32, valid_seckey, secp256k1_nonce_function_default, None)
    assert default_nonce_function_sig is not None and default_nonce_function_nonce_is_negated is False
    default_nonce_function_out64 = secp256k1_schnorrsig_serialize(ctx, default_nonce_function_sig)
    assert default_nonce_function_out64 == bytes.fromhex('b205a970e2fed06001bcd3864ce7a2c63291b531525d693dc2deeb92c91627de6e5892fd93f13f134f9cb96c5b9e375647f3a9a8fa57271702a8f5d416819004')

    # Test creating Schnorr signature with RFC6979 nonce function without nonce data
    rfc6979_nonce_function_without_ndata_sig, rfc6979_nonce_function_without_ndata_nonce_is_negated = secp256k1_schnorrsig_sign(ctx, msg32, valid_seckey, secp256k1_nonce_function_rfc6979, None)
    assert rfc6979_nonce_function_without_ndata_sig is not None and rfc6979_nonce_function_without_ndata_nonce_is_negated is False
    rfc6979_nonce_function_without_ndata_out64 = secp256k1_schnorrsig_serialize(ctx, rfc6979_nonce_function_without_ndata_sig)
    assert rfc6979_nonce_function_without_ndata_out64 == bytes.fromhex('b205a970e2fed06001bcd3864ce7a2c63291b531525d693dc2deeb92c91627de6e5892fd93f13f134f9cb96c5b9e375647f3a9a8fa57271702a8f5d416819004')

    # Test creating Schnorr signature with RFC6979 nonce function with nonce data
    ndata = bytes.fromhex('8368fb6bcd437e2685af0d5b71543d2c077bfac05b74307068b06ed96a08bb4f')
    rfc6979_nonce_function_with_ndata_sig, rfc6979_nonce_function_with_ndata_nonce_is_negated = secp256k1_schnorrsig_sign(ctx, msg32, valid_seckey, secp256k1_nonce_function_rfc6979, ndata)
    assert rfc6979_nonce_function_with_ndata_sig is not None and rfc6979_nonce_function_with_ndata_nonce_is_negated is False
    rfc6979_nonce_function_with_ndata_out64 = secp256k1_schnorrsig_serialize(ctx, rfc6979_nonce_function_with_ndata_sig)
    assert rfc6979_nonce_function_with_ndata_out64 == bytes.fromhex('70551b95f4a7f2950897b0a5c5fad0249a6c26737636865461b7326647157de36ae85e14e887d1f90009f594e069e16f2e7f2d465b9d931eca26723176568316')

    # Test creating an invalid Schnorr signature
    invalid_seckey = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
    invalid_sig = secp256k1_schnorrsig_sign(ctx, msg32, invalid_seckey, None, None)
    assert invalid_sig is None

    # Test creating Schnorr signature with invalid types
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_sign(None, msg32, valid_seckey, None, None)
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_sign('string', msg32, valid_seckey, None, None)
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_sign(ctx, None, valid_seckey, None, None)
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_sign(ctx, 'string', valid_seckey, None, None)
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_sign(ctx, msg32, None, None, None)
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_sign(ctx, msg32, 'string', None, None)
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_sign(ctx, msg32, valid_seckey, 'string', None)
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_sign(ctx, msg32, valid_seckey, None, 'string')

def test_secp256k1_schnorrsig_verify():
    # Test verifying Schnorr signature
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    sig = secp256k1_schnorrsig_parse(ctx, bytes.fromhex('2a298dacae57395a15d0795ddbfd1dcb564da82b0f269bc70a74f8220429ba1d1e51a22ccec35599b8f266912281f8365ffc2d035a230434a1a64dc59f7013fd'))
    valid_msg32 = bytes.fromhex('243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89')
    pubkey = secp256k1_ec_pubkey_parse(ctx, bytes.fromhex('02dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659'))
    assert pubkey is not None
    valid_result = secp256k1_schnorrsig_verify(ctx, sig, valid_msg32, pubkey)
    assert valid_result is True

    # Test verifying invalid Schnorr signature
    invalid_msg32 = bytes.fromhex('343f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89')
    invalid_result = secp256k1_schnorrsig_verify(ctx, sig, invalid_msg32, pubkey)
    assert invalid_result is False

    # Test verifying Schnorr signature with invalid types
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_verify(None, sig, valid_msg32, pubkey)
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_verify('string', sig, valid_msg32, pubkey)
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_verify(ctx, None, valid_msg32, pubkey)
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_verify(ctx, 'string', valid_msg32, pubkey)
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_verify(ctx, sig, None, pubkey)
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_verify(ctx, sig, 'string', pubkey)
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_verify(ctx, sig, valid_msg32, None)
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_verify(ctx, sig, valid_msg32, 'string')

def test_secp256k1_schnorrsig_verify_batch():
    # Test verifying Schnorr signature batch
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    scratch = secp256k1_scratch_space_create(ctx, 30720)
    assert scratch is not None
    sig = [secp256k1_schnorrsig_parse(ctx, bytes.fromhex('2a298dacae57395a15d0795ddbfd1dcb564da82b0f269bc70a74f8220429ba1d1e51a22ccec35599b8f266912281f8365ffc2d035a230434a1a64dc59f7013fd')), secp256k1_schnorrsig_parse(ctx, bytes.fromhex('00da9b08172a9b6f0466a2defd817f2d7ab437e0d253cb5395a963866b3574be00880371d01766935b92d2ab4cd5c8a2a5837ec57fed7660773a05f0de142380'))]
    assert all(signature is not None for signature in sig)
    valid_msg32 = [bytes.fromhex('243f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89'), bytes.fromhex('5e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a508b75c')]
    pk = [secp256k1_ec_pubkey_parse(ctx, bytes.fromhex('02dff1d77f2a671c5f36183726db2341be58feae1da2deced843240f7b502ba659')), secp256k1_ec_pubkey_parse(ctx, bytes.fromhex('03fac2114c2fbb091527eb7c64ecb11f8021cb45e8e7809d3c0938e4b8c0e5f84b'))]
    assert all(pubkey is not None for pubkey in pk)
    valid_result = secp256k1_schnorrsig_verify_batch(ctx, scratch, sig, valid_msg32, pk)
    assert valid_result is True

    # Test verifying invalid Schnorr signature batch
    invalid_msg32 = [bytes.fromhex('343f6a8885a308d313198a2e03707344a4093822299f31d0082efa98ec4e6c89'), bytes.fromhex('5e2d58d8b3bcdf1abadec7829054f90dda9805aab56c77333024b9d0a508b75c')]
    invalid_result = secp256k1_schnorrsig_verify_batch(ctx, scratch, sig, invalid_msg32, pk)
    assert invalid_result is False

    # Test verifying Schnorr signature batch with invalid types
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_verify_batch(None, scratch, sig, valid_msg32, pk)
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_verify_batch('string', scratch, sig, valid_msg32, pk)
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_verify_batch(ctx, None, sig, valid_msg32, pk)
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_verify_batch(ctx, 'string', sig, valid_msg32, pk)
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_verify_batch(ctx, scratch, None, valid_msg32, pk)
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_verify_batch(ctx, scratch, 'string', valid_msg32, pk)
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_verify_batch(ctx, scratch, [1, 2, 3], valid_msg32, pk)
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_verify_batch(ctx, scratch, sig, None, pk)
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_verify_batch(ctx, scratch, sig, 'string', pk)
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_verify_batch(ctx, scratch, sig, [1, 2, 3], pk)
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_verify_batch(ctx, scratch, sig, valid_msg32, None)
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_verify_batch(ctx, scratch, sig, valid_msg32, 'string')
    with pytest.raises(TypeError):
        secp256k1_schnorrsig_verify_batch(ctx, scratch, sig, valid_msg32, [1, 2, 3])

def test_secp256k1_surjectionproof_parse():
    # Test parsing surjection proof
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    valid_input = bytes.fromhex('020001ca810eb35435b2e6422bbd813ddf849c34d68b8285850b2168b2ff1f389add36446d73e9f69d204ad18ed8e44b590efe48da58d8015e82f5a6e550c150bc86aa')
    valid_proof = secp256k1_surjectionproof_parse(ctx, valid_input)
    assert valid_proof is not None

    # Test parsing invalid surjection proof
    invalid_input = bytes.fromhex('00')
    invalid_proof = secp256k1_surjectionproof_parse(ctx, invalid_input)
    assert invalid_proof is None

    # Test parsing surjection proof with invalid types
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_parse(None, valid_input)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_parse('string', valid_input)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_parse(ctx, None)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_parse(ctx, 'string')

def test_secp256k1_surjectionproof_serialize():
    # Test serializing surjection proof
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    input = bytes.fromhex('020001ca810eb35435b2e6422bbd813ddf849c34d68b8285850b2168b2ff1f389add36446d73e9f69d204ad18ed8e44b590efe48da58d8015e82f5a6e550c150bc86aa')
    proof = secp256k1_surjectionproof_parse(ctx, input)
    assert proof is not None
    output = secp256k1_surjectionproof_serialize(ctx, proof)
    assert output == input

    # Test serializing surjection proof with invalid types
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_serialize(None, proof)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_serialize('string', proof)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_serialize(ctx, None)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_serialize(ctx, 'string')

def test_secp256k1_surjectionproof_n_total_inputs():
    # Test getting surjection proof number of total inputs
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    input = bytes.fromhex('020001ca810eb35435b2e6422bbd813ddf849c34d68b8285850b2168b2ff1f389add36446d73e9f69d204ad18ed8e44b590efe48da58d8015e82f5a6e550c150bc86aa')
    proof = secp256k1_surjectionproof_parse(ctx, input)
    assert proof is not None
    result = secp256k1_surjectionproof_n_total_inputs(ctx, proof)
    assert result == 2

    # Test getting surjection proof number of total inputs with invalid types
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_n_total_inputs(None, proof)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_n_total_inputs('string', proof)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_n_total_inputs(ctx, None)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_n_total_inputs(ctx, 'string')

def test_secp256k1_surjectionproof_n_used_inputs():
    # Test getting surjection proof number of used inputs
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    input = bytes.fromhex('020001ca810eb35435b2e6422bbd813ddf849c34d68b8285850b2168b2ff1f389add36446d73e9f69d204ad18ed8e44b590efe48da58d8015e82f5a6e550c150bc86aa')
    proof = secp256k1_surjectionproof_parse(ctx, input)
    assert proof is not None
    result = secp256k1_surjectionproof_n_used_inputs(ctx, proof)
    assert result == 1

    # Test getting surjection proof number of used inputs with invalid types
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_n_used_inputs(None, proof)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_n_used_inputs('string', proof)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_n_used_inputs(ctx, None)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_n_used_inputs(ctx, 'string')

def test_secp256k1_surjectionproof_serialized_size():
    # Test getting surjection proof serialized size
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    input = bytes.fromhex('020001ca810eb35435b2e6422bbd813ddf849c34d68b8285850b2168b2ff1f389add36446d73e9f69d204ad18ed8e44b590efe48da58d8015e82f5a6e550c150bc86aa')
    proof = secp256k1_surjectionproof_parse(ctx, input)
    assert proof is not None
    result = secp256k1_surjectionproof_serialized_size(ctx, proof)
    assert result == 67

    # Test getting surjection proof serialized size with invalid types
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_serialized_size(None, proof)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_serialized_size('string', proof)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_serialized_size(ctx, None)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_serialized_size(ctx, 'string')

def test_secp256k1_surjectionproof_initialize():
    # Test initializing surjection proof
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    fixed_input_tags = ffi.new('secp256k1_fixed_asset_tag []', 2)
    ffi.memmove(ffi.addressof(fixed_input_tags, 0), bytes.fromhex('91040b4ac710c4ce715c89e400c1d583202b1bd1bba74b6a490675dc433d0225'), ffi.sizeof('secp256k1_fixed_asset_tag'))
    ffi.memmove(ffi.addressof(fixed_input_tags, 1), bytes.fromhex('136dd5da611b01cb0d5a0c74a2a3d4c98d4b56a517fab91becc6043fb8284d03'), ffi.sizeof('secp256k1_fixed_asset_tag'))
    random_seed32 = bytes.fromhex('a5340621cf1a07699fecc1f82833d8a746992e4e1f61b5123b547a80d4e9a4e2')
    valid_proof, input_index = secp256k1_surjectionproof_initialize(ctx, [ffi.addressof(fixed_input_tags, 0), ffi.addressof(fixed_input_tags, 1)], 1, ffi.addressof(fixed_input_tags, 0), 100, random_seed32)
    assert valid_proof is not None and input_index == 0
    output = secp256k1_surjectionproof_serialize(ctx, valid_proof)
    assert output == bytes.fromhex('02000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000')

    # Test initializing invalid surjection proof
    invalid_proof = secp256k1_surjectionproof_initialize(ctx, [ffi.addressof(fixed_input_tags, 0), ffi.addressof(fixed_input_tags, 1)], 0, ffi.addressof(fixed_input_tags, 0), 100, random_seed32)
    assert invalid_proof is None

    # Test initializing surjection proof with invalid types
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_initialize(None, [ffi.addressof(fixed_input_tags, 0), ffi.addressof(fixed_input_tags, 1)], 1, ffi.addressof(fixed_input_tags, 0), 100, random_seed32)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_initialize('string', [ffi.addressof(fixed_input_tags, 0), ffi.addressof(fixed_input_tags, 1)], 1, ffi.addressof(fixed_input_tags, 0), 100, random_seed32)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_initialize(ctx, None, 1, ffi.addressof(fixed_input_tags, 0), 100, random_seed32)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_initialize(ctx, 'string', 1, ffi.addressof(fixed_input_tags, 0), 100, random_seed32)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_initialize(ctx, [1, 2, 3], 1, ffi.addressof(fixed_input_tags, 0), 100, random_seed32)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_initialize(ctx, [ffi.addressof(fixed_input_tags, 0), ffi.addressof(fixed_input_tags, 1)], None, ffi.addressof(fixed_input_tags, 0), 100, random_seed32)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_initialize(ctx, [ffi.addressof(fixed_input_tags, 0), ffi.addressof(fixed_input_tags, 1)], 'string', ffi.addressof(fixed_input_tags, 0), 100, random_seed32)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_initialize(ctx, [ffi.addressof(fixed_input_tags, 0), ffi.addressof(fixed_input_tags, 1)], 1, None, 100, random_seed32)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_initialize(ctx, [ffi.addressof(fixed_input_tags, 0), ffi.addressof(fixed_input_tags, 1)], 1, 'string', 100, random_seed32)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_initialize(ctx, [ffi.addressof(fixed_input_tags, 0), ffi.addressof(fixed_input_tags, 1)], 1, ffi.addressof(fixed_input_tags, 0), None, random_seed32)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_initialize(ctx, [ffi.addressof(fixed_input_tags, 0), ffi.addressof(fixed_input_tags, 1)], 1, ffi.addressof(fixed_input_tags, 0), 'string', random_seed32)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_initialize(ctx, [ffi.addressof(fixed_input_tags, 0), ffi.addressof(fixed_input_tags, 1)], 1, ffi.addressof(fixed_input_tags, 0), 100, None)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_initialize(ctx, [ffi.addressof(fixed_input_tags, 0), ffi.addressof(fixed_input_tags, 1)], 1, ffi.addressof(fixed_input_tags, 0), 100, 'string')

    # Test creating context with invalid values
    with pytest.raises(OverflowError):
        secp256k1_surjectionproof_initialize(ctx, [ffi.addressof(fixed_input_tags, 0), ffi.addressof(fixed_input_tags, 1)], -1, ffi.addressof(fixed_input_tags, 0), 100, random_seed32)
    with pytest.raises(OverflowError):
        secp256k1_surjectionproof_initialize(ctx, [ffi.addressof(fixed_input_tags, 0), ffi.addressof(fixed_input_tags, 1)], 0x10000000000000000, ffi.addressof(fixed_input_tags, 0), 100, random_seed32)
    with pytest.raises(OverflowError):
        secp256k1_surjectionproof_initialize(ctx, [ffi.addressof(fixed_input_tags, 0), ffi.addressof(fixed_input_tags, 1)], 1, ffi.addressof(fixed_input_tags, 0), -1, random_seed32)
    with pytest.raises(OverflowError):
        secp256k1_surjectionproof_initialize(ctx, [ffi.addressof(fixed_input_tags, 0), ffi.addressof(fixed_input_tags, 1)], 1, ffi.addressof(fixed_input_tags, 0), 0x10000000000000000, random_seed32)

def test_secp256k1_surjectionproof_generate():
    # Test generating surjection proof
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    input_tags = [bytes.fromhex('91040b4ac710c4ce715c89e400c1d583202b1bd1bba74b6a490675dc433d0225'), bytes.fromhex('136dd5da611b01cb0d5a0c74a2a3d4c98d4b56a517fab91becc6043fb8284d03')]
    fixed_input_tags = ffi.new('secp256k1_fixed_asset_tag []', 2)
    ffi.memmove(ffi.addressof(fixed_input_tags, 0), input_tags[0], ffi.sizeof('secp256k1_fixed_asset_tag'))
    ffi.memmove(ffi.addressof(fixed_input_tags, 1), input_tags[1], ffi.sizeof('secp256k1_fixed_asset_tag'))
    random_seed32 = bytes.fromhex('a5340621cf1a07699fecc1f82833d8a746992e4e1f61b5123b547a80d4e9a4e2')
    proof, input_index = secp256k1_surjectionproof_initialize(ctx, [ffi.addressof(fixed_input_tags, 0), ffi.addressof(fixed_input_tags, 1)], 1, ffi.addressof(fixed_input_tags, 0), 100, random_seed32)
    assert proof is not None
    input_blinding_key = [bytes.fromhex('d7d4229b219035c1688cebcade63819ac09eac31255edadb1050a64ec6dbc05d'), bytes.fromhex('152e9d3033d55edb416ee622eeb31f96776d9fe06eed68f754bac8638baa5be0')]
    ephemeral_input_tags = [secp256k1_generator_generate_blinded(ctx, input_tags[0], input_blinding_key[0]), secp256k1_generator_generate_blinded(ctx, input_tags[1], input_blinding_key[1])]
    assert all(ephemeral_input_tag is not None for ephemeral_input_tag in ephemeral_input_tags)
    output_blinding_key = bytes.fromhex('be8ea09e9f6d5311f4b332c9e45c7a70ac2784edf5206e856eafb0254b1f0af3')
    ephemeral_output_tag = secp256k1_generator_generate_blinded(ctx, input_tags[0], output_blinding_key)
    assert ephemeral_output_tag is not None
    valid_new_proof = secp256k1_surjectionproof_generate(ctx, proof, ephemeral_input_tags, ephemeral_output_tag, input_index, input_blinding_key[0], output_blinding_key)
    assert valid_new_proof is not None
    output = secp256k1_surjectionproof_serialize(ctx, valid_new_proof)
    assert output == bytes.fromhex('020001ca810eb35435b2e6422bbd813ddf849c34d68b8285850b2168b2ff1f389add36446d73e9f69d204ad18ed8e44b590efe48da58d8015e82f5a6e550c150bc86aa')

    # Test generating invalid surjection proof
    invalid_new_proof = secp256k1_surjectionproof_generate(ctx, proof, [secp256k1_generator_const_g], ephemeral_output_tag, 0, input_blinding_key[0], output_blinding_key)
    assert invalid_new_proof is None

    # Test generating surjection proof with invalid types
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_generate(None, proof, ephemeral_input_tags, ephemeral_output_tag, input_index, input_blinding_key[0], output_blinding_key)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_generate('string', proof, ephemeral_input_tags, ephemeral_output_tag, input_index, input_blinding_key[0], output_blinding_key)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_generate(ctx, None, ephemeral_input_tags, ephemeral_output_tag, input_index, input_blinding_key[0], output_blinding_key)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_generate(ctx, 'string', ephemeral_input_tags, ephemeral_output_tag, input_index, input_blinding_key[0], output_blinding_key)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_generate(ctx, proof, None, ephemeral_output_tag, input_index, input_blinding_key[0], output_blinding_key)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_generate(ctx, proof, 'string', ephemeral_output_tag, input_index, input_blinding_key[0], output_blinding_key)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_generate(ctx, proof, [1, 2, 3], ephemeral_output_tag, input_index, input_blinding_key[0], output_blinding_key)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_generate(ctx, proof, ephemeral_input_tags, None, input_index, input_blinding_key[0], output_blinding_key)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_generate(ctx, proof, ephemeral_input_tags, 'string', input_index, input_blinding_key[0], output_blinding_key)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_generate(ctx, proof, ephemeral_input_tags, ephemeral_output_tag, None, input_blinding_key[0], output_blinding_key)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_generate(ctx, proof, ephemeral_input_tags, ephemeral_output_tag, 'string', input_blinding_key[0], output_blinding_key)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_generate(ctx, proof, ephemeral_input_tags, ephemeral_output_tag, input_index, None, output_blinding_key)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_generate(ctx, proof, ephemeral_input_tags, ephemeral_output_tag, input_index, 'string', output_blinding_key)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_generate(ctx, proof, ephemeral_input_tags, ephemeral_output_tag, input_index, input_blinding_key[0], None)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_generate(ctx, proof, ephemeral_input_tags, ephemeral_output_tag, input_index, input_blinding_key[0], 'string')

    # Test generating surjection proof with invalid values
    with pytest.raises(OverflowError):
        secp256k1_surjectionproof_generate(ctx, proof, ephemeral_input_tags, ephemeral_output_tag, -1, input_blinding_key[0], output_blinding_key)
    with pytest.raises(OverflowError):
        secp256k1_surjectionproof_generate(ctx, proof, ephemeral_input_tags, ephemeral_output_tag, 0x10000000000000000, input_blinding_key[0], output_blinding_key)

def test_secp256k1_surjectionproof_verify():
    # Test verifying surjection proof
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    input_tags = [bytes.fromhex('91040b4ac710c4ce715c89e400c1d583202b1bd1bba74b6a490675dc433d0225'), bytes.fromhex('136dd5da611b01cb0d5a0c74a2a3d4c98d4b56a517fab91becc6043fb8284d03')]
    fixed_input_tags = ffi.new('secp256k1_fixed_asset_tag []', 2)
    ffi.memmove(ffi.addressof(fixed_input_tags, 0), input_tags[0], ffi.sizeof('secp256k1_fixed_asset_tag'))
    ffi.memmove(ffi.addressof(fixed_input_tags, 1), input_tags[1], ffi.sizeof('secp256k1_fixed_asset_tag'))
    random_seed32 = bytes.fromhex('a5340621cf1a07699fecc1f82833d8a746992e4e1f61b5123b547a80d4e9a4e2')
    proof, input_index = secp256k1_surjectionproof_initialize(ctx, [ffi.addressof(fixed_input_tags, 0), ffi.addressof(fixed_input_tags, 1)], 1, ffi.addressof(fixed_input_tags, 0), 100, random_seed32)
    assert proof is not None
    input_blinding_key = [bytes.fromhex('d7d4229b219035c1688cebcade63819ac09eac31255edadb1050a64ec6dbc05d'), bytes.fromhex('152e9d3033d55edb416ee622eeb31f96776d9fe06eed68f754bac8638baa5be0')]
    ephemeral_input_tags = [secp256k1_generator_generate_blinded(ctx, input_tags[0], input_blinding_key[0]), secp256k1_generator_generate_blinded(ctx, input_tags[1], input_blinding_key[1])]
    assert all(ephemeral_input_tag is not None for ephemeral_input_tag in ephemeral_input_tags)
    output_blinding_key = bytes.fromhex('be8ea09e9f6d5311f4b332c9e45c7a70ac2784edf5206e856eafb0254b1f0af3')
    ephemeral_output_tag = secp256k1_generator_generate_blinded(ctx, input_tags[0], output_blinding_key)
    assert ephemeral_output_tag is not None
    new_proof = secp256k1_surjectionproof_generate(ctx, proof, ephemeral_input_tags, ephemeral_output_tag, input_index, input_blinding_key[0], output_blinding_key)
    valid_result = secp256k1_surjectionproof_verify(ctx, new_proof, ephemeral_input_tags, ephemeral_output_tag)
    assert valid_result is True

    # Test verifying invalid surjection proof
    invalid_result = secp256k1_surjectionproof_verify(ctx, new_proof, ephemeral_input_tags, secp256k1_generator_const_g)
    assert invalid_result is False

    # Test generating surjection proof with invalid types
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_verify(None, new_proof, ephemeral_input_tags, ephemeral_output_tag)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_verify('string', new_proof, ephemeral_input_tags, ephemeral_output_tag)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_verify(ctx, None, ephemeral_input_tags, ephemeral_output_tag)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_verify(ctx, 'string', ephemeral_input_tags, ephemeral_output_tag)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_verify(ctx, new_proof, None, ephemeral_output_tag)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_verify(ctx, new_proof, 'string', ephemeral_output_tag)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_verify(ctx, new_proof, [1, 2, 3], ephemeral_output_tag)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_verify(ctx, new_proof, ephemeral_input_tags, None)
    with pytest.raises(TypeError):
        secp256k1_surjectionproof_verify(ctx, new_proof, ephemeral_input_tags, 'string')

def test_secp256k1_whitelist_signature_parse():
    # Test parsing whitelist signature
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    valid_input = bytes.fromhex('025293ef5c1a63d1326ae9154eb4955c8a9352091a3ed3d4647eb1c67120a457b9b75bf79ecc6a303f7f1f063c5d1d849dc1be03f4d0240562ac83f5b7f617f4e67164c6e8220d0082b39ec12a58c7016b30ed74f09fea50a0aaa09a13c0f2f7de')
    valid_sig = secp256k1_whitelist_signature_parse(ctx, valid_input)
    assert valid_sig is not None

    # Test parsing invalid whitelist signature
    invalid_input = bytes.fromhex('00')
    invalid_sig = secp256k1_whitelist_signature_parse(ctx, invalid_input)
    assert invalid_sig is None

    # Test parsing whitelist signature with invalid types
    with pytest.raises(TypeError):
        secp256k1_whitelist_signature_parse(None, valid_input)
    with pytest.raises(TypeError):
        secp256k1_whitelist_signature_parse('string', valid_input)
    with pytest.raises(TypeError):
        secp256k1_whitelist_signature_parse(ctx, None)
    with pytest.raises(TypeError):
        secp256k1_whitelist_signature_parse(ctx, 'string')

def test_secp256k1_whitelist_signature_n_keys():
    # Test getting whitelist signature number of keys
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    input = bytes.fromhex('025293ef5c1a63d1326ae9154eb4955c8a9352091a3ed3d4647eb1c67120a457b9b75bf79ecc6a303f7f1f063c5d1d849dc1be03f4d0240562ac83f5b7f617f4e67164c6e8220d0082b39ec12a58c7016b30ed74f09fea50a0aaa09a13c0f2f7de')
    sig = secp256k1_whitelist_signature_parse(ctx, input)
    assert sig is not None
    result = secp256k1_whitelist_signature_n_keys(sig)
    assert result == 2

    # Test getting whitelist signature number of keys with invalid types
    with pytest.raises(TypeError):
        secp256k1_whitelist_signature_n_keys(None)
    with pytest.raises(TypeError):
        secp256k1_whitelist_signature_n_keys('string')

def test_secp256k1_whitelist_signature_serialize():
    # Test serializing whitelist signature
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    input = bytes.fromhex('025293ef5c1a63d1326ae9154eb4955c8a9352091a3ed3d4647eb1c67120a457b9b75bf79ecc6a303f7f1f063c5d1d849dc1be03f4d0240562ac83f5b7f617f4e67164c6e8220d0082b39ec12a58c7016b30ed74f09fea50a0aaa09a13c0f2f7de')
    sig = secp256k1_whitelist_signature_parse(ctx, input)
    assert sig is not None
    output = secp256k1_whitelist_signature_serialize(ctx, sig)
    assert output == input

    # Test serializing whitelist signature with invalid types
    with pytest.raises(TypeError):
        secp256k1_whitelist_signature_serialize(None, sig)
    with pytest.raises(TypeError):
        secp256k1_whitelist_signature_serialize('string', sig)
    with pytest.raises(TypeError):
        secp256k1_whitelist_signature_serialize(ctx, None)
    with pytest.raises(TypeError):
        secp256k1_whitelist_signature_serialize(ctx, 'string')

def test_secp256k1_whitelist_sign():
    # Test creating whitelist signature with no nonce function
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    online_seckeys = [bytes.fromhex('6cf63f688b9fcd33b7ded2eeb64cba08cda4d8a23ef90e690ca406f772933252'), bytes.fromhex('53d0a17f5bc941ede5d54f6883b09a0dafd957a6dadb92b5e80ce3f2fde0d87a')]
    online_pubkeys = list(map(lambda online_seckey : secp256k1_ec_pubkey_create(ctx, online_seckey), online_seckeys))
    assert all(online_pubkey is not None for online_pubkey in online_pubkeys)
    offline_seckeys = [bytes.fromhex('c9b3b62dce086b162266340451dad96f8a86e3f0822a3caf927aa8685b8f1c44'), bytes.fromhex('6d3a2b8423a308ee14f14e90d45ed742ed665239e0b574bef394efa2a549416b')]
    offline_pubkeys = list(map(lambda offline_seckey : secp256k1_ec_pubkey_create(ctx, offline_seckey), offline_seckeys))
    assert all(offline_pubkey is not None for offline_pubkey in offline_pubkeys)
    sub_seckey = bytes.fromhex('4d6ac773f213535269ab376e5294c21ad0e8bcbb313344dfff32f5bdb222e162')
    sub_pubkey = secp256k1_ec_pubkey_create(ctx, sub_seckey)
    assert sub_pubkey is not None
    summed_seckeys = [secp256k1_ec_privkey_tweak_add(ctx, offline_seckeys[0], sub_seckey), secp256k1_ec_privkey_tweak_add(ctx, offline_seckeys[1], sub_seckey)]
    assert all(summed_seckey is not None for summed_seckey in summed_seckeys)
    no_nonce_function_sig = secp256k1_whitelist_sign(ctx, online_pubkeys, offline_pubkeys, sub_pubkey, online_seckeys[0], summed_seckeys[0], 0, None, None)
    assert no_nonce_function_sig is not None
    no_nonce_function_output = secp256k1_whitelist_signature_serialize(ctx, no_nonce_function_sig)
    assert no_nonce_function_output == bytes.fromhex('025293ef5c1a63d1326ae9154eb4955c8a9352091a3ed3d4647eb1c67120a457b9b75bf79ecc6a303f7f1f063c5d1d849dc1be03f4d0240562ac83f5b7f617f4e67164c6e8220d0082b39ec12a58c7016b30ed74f09fea50a0aaa09a13c0f2f7de')

    # Test creating whitelist signature with default nonce function
    default_nonce_function_sig = secp256k1_whitelist_sign(ctx, online_pubkeys, offline_pubkeys, sub_pubkey, online_seckeys[0], summed_seckeys[0], 0, secp256k1_nonce_function_default, None)
    assert default_nonce_function_sig is not None
    default_nonce_function_output = secp256k1_whitelist_signature_serialize(ctx, default_nonce_function_sig)
    assert default_nonce_function_output == bytes.fromhex('025293ef5c1a63d1326ae9154eb4955c8a9352091a3ed3d4647eb1c67120a457b9b75bf79ecc6a303f7f1f063c5d1d849dc1be03f4d0240562ac83f5b7f617f4e67164c6e8220d0082b39ec12a58c7016b30ed74f09fea50a0aaa09a13c0f2f7de')

    # Test creating whitelist signature with RFC6979 nonce function without nonce data
    rfc6979_nonce_function_without_noncedata_sig = secp256k1_whitelist_sign(ctx, online_pubkeys, offline_pubkeys, sub_pubkey, online_seckeys[0], summed_seckeys[0], 0, secp256k1_nonce_function_rfc6979, None)
    assert rfc6979_nonce_function_without_noncedata_sig is not None
    rfc6979_nonce_function_without_noncedata_output = secp256k1_whitelist_signature_serialize(ctx, rfc6979_nonce_function_without_noncedata_sig)
    assert rfc6979_nonce_function_without_noncedata_output == bytes.fromhex('025293ef5c1a63d1326ae9154eb4955c8a9352091a3ed3d4647eb1c67120a457b9b75bf79ecc6a303f7f1f063c5d1d849dc1be03f4d0240562ac83f5b7f617f4e67164c6e8220d0082b39ec12a58c7016b30ed74f09fea50a0aaa09a13c0f2f7de')

    # Test creating whitelist signature with RFC6979 nonce function with nonce data
    noncedata = bytes.fromhex('8368fb6bcd437e2685af0d5b71543d2c077bfac05b74307068b06ed96a08bb4f')
    rfc6979_nonce_function_with_noncedata_sig = secp256k1_whitelist_sign(ctx, online_pubkeys, offline_pubkeys, sub_pubkey, online_seckeys[0], summed_seckeys[0], 0, secp256k1_nonce_function_rfc6979, noncedata)
    assert rfc6979_nonce_function_with_noncedata_sig is not None
    rfc6979_nonce_function_with_noncedata_output = secp256k1_whitelist_signature_serialize(ctx, rfc6979_nonce_function_with_noncedata_sig)
    assert rfc6979_nonce_function_with_noncedata_output == bytes.fromhex('02451a4e3866a2b749a30c717261d6402e5562be88e7af9154d7699c80258aa35e1304381b9988859e099986b7f28bf8eea64af87ab11c3c1c01accf85b4400503d0d2a424cc6cfd96a5697d88648e0b5c3344f2ce668efab85c76cfd167d31b89')

    # Test creating invalid whitelist signature
    invalid_sig = secp256k1_whitelist_sign(ctx, online_pubkeys, offline_pubkeys, sub_pubkey, bytes.fromhex('ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'), summed_seckeys[0], 0, secp256k1_nonce_function_rfc6979, noncedata)
    assert invalid_sig is None

    # Test creating whitelist signature with invalid types
    with pytest.raises(TypeError):
        secp256k1_whitelist_sign(None, online_pubkeys, offline_pubkeys, sub_pubkey, online_seckeys[0], summed_seckeys[0], 0, None, None)
    with pytest.raises(TypeError):
        secp256k1_whitelist_sign('string', online_pubkeys, offline_pubkeys, sub_pubkey, online_seckeys[0], summed_seckeys[0], 0, None, None)
    with pytest.raises(TypeError):
        secp256k1_whitelist_sign(ctx, None, offline_pubkeys, sub_pubkey, online_seckeys[0], summed_seckeys[0], 0, None, None)
    with pytest.raises(TypeError):
        secp256k1_whitelist_sign(ctx, 'string', offline_pubkeys, sub_pubkey, online_seckeys[0], summed_seckeys[0], 0, None, None)
    with pytest.raises(TypeError):
        secp256k1_whitelist_sign(ctx, [1, 2, 3], offline_pubkeys, sub_pubkey, online_seckeys[0], summed_seckeys[0], 0, None, None)
    with pytest.raises(TypeError):
        secp256k1_whitelist_sign(ctx, online_pubkeys, None, sub_pubkey, online_seckeys[0], summed_seckeys[0], 0, None, None)
    with pytest.raises(TypeError):
        secp256k1_whitelist_sign(ctx, online_pubkeys, 'string', sub_pubkey, online_seckeys[0], summed_seckeys[0], 0, None, None)
    with pytest.raises(TypeError):
        secp256k1_whitelist_sign(ctx, online_pubkeys, [1, 2, 3], sub_pubkey, online_seckeys[0], summed_seckeys[0], 0, None, None)
    with pytest.raises(TypeError):
        secp256k1_whitelist_sign(ctx, online_pubkeys, offline_pubkeys, None, online_seckeys[0], summed_seckeys[0], 0, None, None)
    with pytest.raises(TypeError):
        secp256k1_whitelist_sign(ctx, online_pubkeys, offline_pubkeys, 'string', online_seckeys[0], summed_seckeys[0], 0, None, None)
    with pytest.raises(TypeError):
        secp256k1_whitelist_sign(ctx, online_pubkeys, offline_pubkeys, sub_pubkey, None, summed_seckeys[0], 0, None, None)
    with pytest.raises(TypeError):
        secp256k1_whitelist_sign(ctx, online_pubkeys, offline_pubkeys, sub_pubkey, 'string', summed_seckeys[0], 0, None, None)
    with pytest.raises(TypeError):
        secp256k1_whitelist_sign(ctx, online_pubkeys, offline_pubkeys, sub_pubkey, online_seckeys[0], None, 0, None, None)
    with pytest.raises(TypeError):
        secp256k1_whitelist_sign(ctx, online_pubkeys, offline_pubkeys, sub_pubkey, online_seckeys[0], 'string', 0, None, None)
    with pytest.raises(TypeError):
        secp256k1_whitelist_sign(ctx, online_pubkeys, offline_pubkeys, sub_pubkey, online_seckeys[0], summed_seckeys[0], None, None, None)
    with pytest.raises(TypeError):
        secp256k1_whitelist_sign(ctx, online_pubkeys, offline_pubkeys, sub_pubkey, online_seckeys[0], summed_seckeys[0], 'string', None, None)
    with pytest.raises(TypeError):
        secp256k1_whitelist_sign(ctx, online_pubkeys, offline_pubkeys, sub_pubkey, online_seckeys[0], summed_seckeys[0], 0, 'string', None)
    with pytest.raises(TypeError):
        secp256k1_whitelist_sign(ctx, online_pubkeys, offline_pubkeys, sub_pubkey, online_seckeys[0], summed_seckeys[0], 0, None, 'string')

    # Test creating whitelist signature with invalid values
    with pytest.raises(OverflowError):
        secp256k1_whitelist_sign(ctx, online_pubkeys, offline_pubkeys, sub_pubkey, online_seckeys[0], summed_seckeys[0], -1, None, None)
    with pytest.raises(OverflowError):
        secp256k1_whitelist_sign(ctx, online_pubkeys, offline_pubkeys, sub_pubkey, online_seckeys[0], summed_seckeys[0], 0x10000000000000000, None, None)

def test_secp256k1_whitelist_verify():
    # Test verifying whitelist signature
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY | SECP256K1_CONTEXT_SIGN)
    assert ctx is not None
    online_seckeys = [bytes.fromhex('6cf63f688b9fcd33b7ded2eeb64cba08cda4d8a23ef90e690ca406f772933252'), bytes.fromhex('53d0a17f5bc941ede5d54f6883b09a0dafd957a6dadb92b5e80ce3f2fde0d87a')]
    online_pubkeys = list(map(lambda online_seckey : secp256k1_ec_pubkey_create(ctx, online_seckey), online_seckeys))
    assert all(online_pubkey is not None for online_pubkey in online_pubkeys)
    offline_seckeys = [bytes.fromhex('c9b3b62dce086b162266340451dad96f8a86e3f0822a3caf927aa8685b8f1c44'), bytes.fromhex('6d3a2b8423a308ee14f14e90d45ed742ed665239e0b574bef394efa2a549416b')]
    offline_pubkeys = list(map(lambda offline_seckey : secp256k1_ec_pubkey_create(ctx, offline_seckey), offline_seckeys))
    assert all(offline_pubkey is not None for offline_pubkey in offline_pubkeys)
    valid_sub_seckey = bytes.fromhex('4d6ac773f213535269ab376e5294c21ad0e8bcbb313344dfff32f5bdb222e162')
    valid_sub_pubkey = secp256k1_ec_pubkey_create(ctx, valid_sub_seckey)
    assert valid_sub_pubkey is not None
    summed_seckeys = [secp256k1_ec_privkey_tweak_add(ctx, offline_seckeys[0], valid_sub_seckey), secp256k1_ec_privkey_tweak_add(ctx, offline_seckeys[1], valid_sub_seckey)]
    assert all(summed_seckey is not None for summed_seckey in summed_seckeys)
    sig = secp256k1_whitelist_sign(ctx, online_pubkeys, offline_pubkeys, valid_sub_pubkey, online_seckeys[0], summed_seckeys[0], 0, None, None)
    assert sig is not None
    valid_result = secp256k1_whitelist_verify(ctx, sig, online_pubkeys, offline_pubkeys, valid_sub_pubkey)
    assert valid_result is True

    # Test verifying invalid whitelist signature
    invalid_sub_seckey = bytes.fromhex('5d6ac773f213535269ab376e5294c21ad0e8bcbb313344dfff32f5bdb222e162')
    invalid_sub_pubkey = secp256k1_ec_pubkey_create(ctx, invalid_sub_seckey)
    assert invalid_sub_pubkey is not None
    invalid_result = secp256k1_whitelist_verify(ctx, sig, online_pubkeys, offline_pubkeys, invalid_sub_pubkey)
    assert invalid_result is False

    # Test verifying whitelist signature with invalid types
    with pytest.raises(TypeError):
        secp256k1_whitelist_verify(None, sig, online_pubkeys, offline_pubkeys, valid_sub_pubkey)
    with pytest.raises(TypeError):
        secp256k1_whitelist_verify('string', sig, online_pubkeys, offline_pubkeys, valid_sub_pubkey)
    with pytest.raises(TypeError):
        secp256k1_whitelist_verify(ctx, None, online_pubkeys, offline_pubkeys, valid_sub_pubkey)
    with pytest.raises(TypeError):
        secp256k1_whitelist_verify(ctx, 'string', online_pubkeys, offline_pubkeys, valid_sub_pubkey)
    with pytest.raises(TypeError):
        secp256k1_whitelist_verify(ctx, sig, None, offline_pubkeys, valid_sub_pubkey)
    with pytest.raises(TypeError):
        secp256k1_whitelist_verify(ctx, sig, 'string', offline_pubkeys, valid_sub_pubkey)
    with pytest.raises(TypeError):
        secp256k1_whitelist_verify(ctx, sig, [1, 2, 3], offline_pubkeys, valid_sub_pubkey)
    with pytest.raises(TypeError):
        secp256k1_whitelist_verify(ctx, sig, online_pubkeys, None, valid_sub_pubkey)
    with pytest.raises(TypeError):
        secp256k1_whitelist_verify(ctx, sig, online_pubkeys, 'string', valid_sub_pubkey)
    with pytest.raises(TypeError):
        secp256k1_whitelist_verify(ctx, sig, online_pubkeys, [1, 2, 3], valid_sub_pubkey)
    with pytest.raises(TypeError):
        secp256k1_whitelist_verify(ctx, sig, online_pubkeys, offline_pubkeys, None)
    with pytest.raises(TypeError):
        secp256k1_whitelist_verify(ctx, sig, online_pubkeys, offline_pubkeys, 'string')
