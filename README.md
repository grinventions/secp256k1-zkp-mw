# secp256k1-zkp-mw

This is an early stage version of Python CFFI wrapper of the [MW fork of secp256k1-zkp](https://github.com/mimblewimble/secp256k1-zkp). It is very much needed to develop the [mimblewimble-py](https://github.com/grinventions/mimblewimble-py). Similar way as it was done with [rust-secp256k1-zkp](https://github.com/mimblewimble/rust-secp256k1-zkp). It is also inspired and partially based on [secp256k1-py](https://github.com/rustyrussell/secp256k1-py). All of the code used here is under the MIT license and there is no license conflict.

For now only few methods are correctly wrapped. My attempts of wrapping more of them results with plenty of C compile errors which I don't always understand so any help is appreciated. Feel free to fork and PR or send me messages with some advices!

## Installation

The module will automatically download the tarball containing [MW fork of secp256k1-zkp](https://github.com/mimblewimble/secp256k1-zkp) at the commit that is supported and tested in this release.

```sh
pip install secp256k1-zkp-mw
```

and you're good to go!

If you're installing this module on Windows you'll need to temporarily change your `TEMP` environmental variable to something with a short path, like `C:\temp`, and create that folder before running the above command. This is required to workaround a limitation with the Visual Studio C/C++ compiler not being able to use files with long path names. You can revert the change to your `TEMP` environmental variable after the module is installed.

## Development

Locally, you may install this this module manually at arbitrary height of the [MW fork of secp256k1-zkp](https://github.com/mimblewimble/secp256k1-zkp) using submodule.

```sh
git clone https://github.com/grinventions/secp256k1-zkp-mw.git
cd secp256k1-zkp-mw
git submodule init
git submodule update
pip install .
```

## Try it!

Creating and destroying context

```python
from secp256k1_zkp_mw import *

print('Running secp256k1_context_create(SECP256K1_CONTEXT_NONE)')
ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE)

print('...and it returned ctx')
print(ctx)

print('Running secp256k1_context_destroy(ctx)')
res = secp256k1_context_destroy(ctx)
```

it will print

```
Running secp256k1_context_create(SECP256K1_CONTEXT_NONE)
...and it returned ctx
<cdata 'struct secp256k1_context_struct *' 0x561c4da348e0>
Running secp256k1_context_destroy(ctx)
```

## Exports

### Index

[SECP256K1_FLAGS_TYPE_MASK](#definitions)

[SECP256K1_FLAGS_TYPE_CONTEXT](#definitions)

[SECP256K1_FLAGS_TYPE_COMPRESSION](#definitions)

[SECP256K1_FLAGS_BIT_CONTEXT_VERIFY](#definitions)

[SECP256K1_FLAGS_BIT_CONTEXT_SIGN](#definitions)

[SECP256K1_FLAGS_BIT_COMPRESSION](#definitions)

[SECP256K1_CONTEXT_VERIFY](#definitions)

[SECP256K1_CONTEXT_SIGN](#definitions)

[SECP256K1_CONTEXT_NONE](#definitions)

[SECP256K1_EC_COMPRESSED](#definitions)

[SECP256K1_EC_UNCOMPRESSED](#definitions)

[SECP256K1_TAG_PUBKEY_EVEN](#definitions)

[SECP256K1_TAG_PUBKEY_ODD](#definitions)

[SECP256K1_TAG_PUBKEY_UNCOMPRESSED](#definitions)

[SECP256K1_TAG_PUBKEY_HYBRID_EVEN](#definitions)

[SECP256K1_TAG_PUBKEY_HYBRID_ODD](#definitions)

[SECP256K1_BULLETPROOF_MAX_DEPTH](#definitions)

[SECP256K1_BULLETPROOF_MAX_PROOF](#definitions)

[SECP256K1_SURJECTIONPROOF_MAX_N_INPUTS](#definitions)

[SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES](#definitions)

[SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES_MAX](#definitions)

[SECP256K1_WHITELIST_MAX_N_KEYS](#definitions)

[secp256k1_context_no_precomp](#constants)

[secp256k1_nonce_function_rfc6979](#constants)

[secp256k1_nonce_function_default](#constants)

[secp256k1_generator_h](#constants)

[secp256k1_generator_const_g](#constants)

[secp256k1_generator_const_h](#constants)

[secp256k1_context_create](#secp256k1_context_create)

[secp256k1_context_clone](#secp256k1_context_clone)

[secp256k1_context_destroy](#secp256k1_context_destroy)

[secp256k1_context_set_illegal_callback](#secp256k1_context_set_illegal_callback)

[secp256k1_context_set_error_callback](#secp256k1_context_set_error_callback)

[secp256k1_scratch_space_create](#secp256k1_scratch_space_create)

[secp256k1_scratch_space_destroy](#secp256k1_scratch_space_destroy)

[secp256k1_ec_pubkey_parse](#secp256k1_ec_pubkey_parse)

[secp256k1_ec_pubkey_serialize](#secp256k1_ec_pubkey_serialize)

[secp256k1_ecdsa_signature_parse_compact](#secp256k1_ecdsa_signature_parse_compact)

[secp256k1_ecdsa_signature_parse_der](#secp256k1_ecdsa_signature_parse_der)

[secp256k1_ecdsa_signature_serialize_der](#secp256k1_ecdsa_signature_serialize_der)

[secp256k1_ecdsa_signature_serialize_compact](#secp256k1_ecdsa_signature_serialize_compact)

[secp256k1_ecdsa_verify](#secp256k1_ecdsa_verify)

[secp256k1_ecdsa_signature_normalize](#secp256k1_ecdsa_signature_normalize)

[secp256k1_ecdsa_sign](#secp256k1_ecdsa_sign)

[secp256k1_ec_seckey_verify](#secp256k1_ec_seckey_verify)

[secp256k1_ec_pubkey_create](#secp256k1_ec_pubkey_create)

[secp256k1_ec_privkey_negate](#secp256k1_ec_privkey_negate)

[secp256k1_ec_pubkey_negate](#secp256k1_ec_pubkey_negate)

[secp256k1_ec_privkey_tweak_add](#secp256k1_ec_privkey_tweak_add)

[secp256k1_ec_pubkey_tweak_add](#secp256k1_ec_pubkey_tweak_add)

[secp256k1_ec_privkey_tweak_mul](#secp256k1_ec_privkey_tweak_mul)

[secp256k1_ec_pubkey_tweak_mul](#secp256k1_ec_pubkey_tweak_mul)

[secp256k1_context_randomize](#secp256k1_context_randomize)

[secp256k1_ec_pubkey_combine](#secp256k1_ec_pubkey_combine)

[secp256k1_ec_privkey_tweak_inv](#secp256k1_ec_privkey_tweak_inv)

[secp256k1_ec_privkey_tweak_neg](#secp256k1_ec_privkey_tweak_neg)

[secp256k1_aggsig_context_create](#secp256k1_aggsig_context_create)

[secp256k1_aggsig_context_destroy](#secp256k1_aggsig_context_destroy)

[secp256k1_aggsig_generate_nonce](#secp256k1_aggsig_generate_nonce)

[secp256k1_aggsig_export_secnonce_single](#secp256k1_aggsig_export_secnonce_single)

[secp256k1_aggsig_sign_single](#secp256k1_aggsig_sign_single)

[secp256k1_aggsig_partial_sign](#secp256k1_aggsig_partial_sign)

[secp256k1_aggsig_combine_signatures](#secp256k1_aggsig_combine_signatures)

[secp256k1_aggsig_add_signatures_single](#secp256k1_aggsig_add_signatures_single)

[secp256k1_aggsig_verify_single](#secp256k1_aggsig_verify_single)

[secp256k1_aggsig_verify](#secp256k1_aggsig_verify)

[secp256k1_aggsig_build_scratch_and_verify](#secp256k1_aggsig_build_scratch_and_verify)

[secp256k1_bulletproof_generators_create](#secp256k1_bulletproof_generators_create)

[secp256k1_bulletproof_generators_destroy](#secp256k1_bulletproof_generators_destroy)

[secp256k1_bulletproof_rangeproof_verify](#secp256k1_bulletproof_rangeproof_verify)

[secp256k1_bulletproof_rangeproof_verify_multi](#secp256k1_bulletproof_rangeproof_verify_multi)

[secp256k1_bulletproof_rangeproof_rewind](#secp256k1_bulletproof_rangeproof_rewind)

[secp256k1_bulletproof_rangeproof_prove](#secp256k1_bulletproof_rangeproof_prove)

[secp256k1_pedersen_commitment_parse](#secp256k1_pedersen_commitment_parse)

[secp256k1_pedersen_commitment_serialize](#secp256k1_pedersen_commitment_serialize)

[secp256k1_pedersen_commit](#secp256k1_pedersen_commit)

[secp256k1_pedersen_blind_commit](#secp256k1_pedersen_blind_commit)

[secp256k1_pedersen_blind_sum](#secp256k1_pedersen_blind_sum)

[secp256k1_pedersen_commit_sum](#secp256k1_pedersen_commit_sum)

[secp256k1_pedersen_verify_tally](#secp256k1_pedersen_verify_tally)

[secp256k1_pedersen_blind_generator_blind_sum](#secp256k1_pedersen_blind_generator_blind_sum)

[secp256k1_blind_switch](#secp256k1_blind_switch)

[secp256k1_pedersen_commitment_to_pubkey](#secp256k1_pedersen_commitment_to_pubkey)

[secp256k1_pubkey_to_pedersen_commitment](#secp256k1_pubkey_to_pedersen_commitment)

[secp256k1_ecdh](#secp256k1_ecdh)

[secp256k1_generator_parse](#secp256k1_generator_parse)

[secp256k1_generator_serialize](#secp256k1_generator_serialize)

[secp256k1_generator_generate](#secp256k1_generator_generate)

[secp256k1_generator_generate_blinded](#secp256k1_generator_generate_blinded)

[secp256k1_context_preallocated_size](#secp256k1_context_preallocated_size)

[secp256k1_context_preallocated_create](#secp256k1_context_preallocated_create)

[secp256k1_context_preallocated_clone_size](#secp256k1_context_preallocated_clone_size)

[secp256k1_context_preallocated_clone](#secp256k1_context_preallocated_clone)

[secp256k1_context_preallocated_destroy](#secp256k1_context_preallocated_destroy)

[secp256k1_rangeproof_verify](#secp256k1_rangeproof_verify)

[secp256k1_rangeproof_rewind](#secp256k1_rangeproof_rewind)

[secp256k1_rangeproof_sign](#secp256k1_rangeproof_sign)

[secp256k1_rangeproof_info](#secp256k1_rangeproof_info)

[secp256k1_ecdsa_recoverable_signature_parse_compact](#secp256k1_ecdsa_recoverable_signature_parse_compact)

[secp256k1_ecdsa_recoverable_signature_convert](#secp256k1_ecdsa_recoverable_signature_convert)

[secp256k1_ecdsa_recoverable_signature_serialize_compact](#secp256k1_ecdsa_recoverable_signature_serialize_compact)

[secp256k1_ecdsa_sign_recoverable](#secp256k1_ecdsa_sign_recoverable)

[secp256k1_ecdsa_recover](#secp256k1_ecdsa_recover)

[secp256k1_schnorrsig_serialize](#secp256k1_schnorrsig_serialize)

[secp256k1_schnorrsig_parse](#secp256k1_schnorrsig_parse)

[secp256k1_schnorrsig_sign](#secp256k1_schnorrsig_sign)

[secp256k1_schnorrsig_verify](#secp256k1_schnorrsig_verify)

[secp256k1_schnorrsig_verify_batch](#secp256k1_schnorrsig_verify_batch)

[secp256k1_surjectionproof_parse](#secp256k1_surjectionproof_parse)

[secp256k1_surjectionproof_serialize](#secp256k1_surjectionproof_serialize)

[secp256k1_surjectionproof_n_total_inputs](#secp256k1_surjectionproof_n_total_inputs)

[secp256k1_surjectionproof_n_used_inputs](#secp256k1_surjectionproof_n_used_inputs)

[secp256k1_surjectionproof_serialized_size](#secp256k1_surjectionproof_serialized_size)

[secp256k1_surjectionproof_initialize](#secp256k1_surjectionproof_initialize)

[secp256k1_surjectionproof_generate](#secp256k1_surjectionproof_generate)

[secp256k1_surjectionproof_verify](#secp256k1_surjectionproof_verify)

[secp256k1_whitelist_signature_parse](#secp256k1_whitelist_signature_parse)

[secp256k1_whitelist_signature_n_keys](#secp256k1_whitelist_signature_n_keys)

[secp256k1_whitelist_signature_serialize](#secp256k1_whitelist_signature_serialize)

[secp256k1_whitelist_sign](#secp256k1_whitelist_sign)

[secp256k1_whitelist_verify](#secp256k1_whitelist_verify)

### Definitions

| Name           | Type | Description |
|----------------|------|-------------|
| `SECP256K1_FLAGS_TYPE_MASK` | `int` | Used internally by other definitions. Should not be used directly. |
| `SECP256K1_FLAGS_TYPE_CONTEXT` | `int` | Used internally by other definitions. Should not be used directly. |
| `SECP256K1_FLAGS_TYPE_COMPRESSION` | `int` | Used internally by other definitions. Should not be used directly. |
| `SECP256K1_FLAGS_BIT_CONTEXT_VERIFY` | `int` | Used internally by other definitions. Should not be used directly. |
| `SECP256K1_FLAGS_BIT_CONTEXT_SIGN` | `int` | Used internally by other definitions. Should not be used directly. |
| `SECP256K1_FLAGS_BIT_COMPRESSION` | `int` | Used internally by other definitions. Should not be used directly. |
| `SECP256K1_CONTEXT_VERIFY` | `int` | Used as a bit-field in the `flags` argument for the `secp256k1_context_create`, `secp256k1_context_preallocated_size`, and `secp256k1_context_preallocated_create` functions to indicate that the context will be used for verifying. |
| `SECP256K1_CONTEXT_SIGN` | `int` | Used as a bit-field in the `flags` argument for the `secp256k1_context_create`, `secp256k1_context_preallocated_size`, and `secp256k1_context_preallocated_create` functions to indicate that the context will be used for signing. |
| `SECP256K1_CONTEXT_NONE` | `int` | Used as a bit-field in the `flags` argument for the `secp256k1_context_create`, `secp256k1_context_preallocated_size`, and `secp256k1_context_preallocated_create` functions to indicate that the context won't be used for verifying or signing. |
| `SECP256K1_EC_COMPRESSED` | `int` | Used as a bit-field in the `secp256k1_ec_pubkey_serialize` function to indicate that the public key should be compressed. |
| `SECP256K1_EC_UNCOMPRESSED` | `int` | Used as a bit-field in the `secp256k1_ec_pubkey_serialize` function to indicate that the public key should be uncompressed. |
| `SECP256K1_TAG_PUBKEY_EVEN` | `int` | Prefix byte for serialized even, compressed public keys. |
| `SECP256K1_TAG_PUBKEY_ODD` | `int` | Prefix byte for serialized odd, compressed public keys. |
| `SECP256K1_TAG_PUBKEY_UNCOMPRESSED` | `int` | Prefix byte for serialized uncompressed public keys. |
| `SECP256K1_TAG_PUBKEY_HYBRID_EVEN` | `int` | Prefix byte for serialized even, hybrid public keys. |
| `SECP256K1_TAG_PUBKEY_HYBRID_ODD` | `int` | Prefix byte for serialized odd, hybrid public keys. |
| `SECP256K1_BULLETPROOF_MAX_DEPTH` | `int` | Maximum depth of a Bulletproof. |
| `SECP256K1_BULLETPROOF_MAX_PROOF` | `int` | Maximum size in bytes of a Bulletproof. |
| `SECP256K1_SURJECTIONPROOF_MAX_N_INPUTS` | `int` | Maximum number of inputs in a surjection proof. |
| `SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES` | `function` | Function that provides the number of bytes required to serialized a surjection proof given the number of inputs and the number of used inputs. |
| `SECP256K1_SURJECTIONPROOF_SERIALIZATION_BYTES_MAX` | `int` | Maximum size in bytes of a serialized surjection proof. |
| `SECP256K1_WHITELIST_MAX_N_KEYS` | `int` | Maximum number of keys in a whitelist proof. |

### Constants

| Name           | Type | Description |
|----------------|------|-------------|
| `secp256k1_context_no_precomp` | `<cdata 'struct secp256k1_context *'>` | A context with no precomputed tables that can be used when a context won't be verifying or signing. |
| `secp256k1_nonce_function_rfc6979` | `<cdata 'secp256k1_nonce_function'>` | A nonce generation function that implements RFC6979. An optional 32 byte of extra entropy can be provided to this function as nonce data. |
| `secp256k1_nonce_function_default` | `<cdata 'secp256k1_nonce_function'>` | The default nonce generation function. |
| `secp256k1_generator_h` | `<cdata 'struct secp256k1_generator *'>` | Standard secp256k1 generator h. |
| `secp256k1_generator_const_g` | `<cdata 'struct secp256k1_generator *'>` | Standard secp256k1 generator g. |
| `secp256k1_generator_const_h` | `<cdata 'struct secp256k1_generator *'>` | Standard secp256k1 generator h. |

### Functions

All of the following functions will raise the following exceptions for the described reasons:
* `TypeError`: An argument doesn't have the correct type.
* `OverflowError`: An `int` argument is negative or too large.
* `AssertionError`: Something internally failed in an unexpected way.

#### secp256k1_context_create

> Returns a context that can perform the features indicated by the provided flags.

**Definition:** `secp256k1_context_create(flags)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `flags` | `int` | Bitwise combination of `SECP256K1_CONTEXT_VERIFY`, `SECP256K1_CONTEXT_SIGN`, and/or `SECP256K1_CONTEXT_NONE`. |

**Return on success:** `<cdata 'struct secp256k1_context *'>`

**Return on failure:** `None`

#### secp256k1_context_clone

> Returns a copy of a provided context.

**Definition:** `secp256k1_context_clone(ctx)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to copy. |

**Return on success:** `<cdata 'struct secp256k1_context *'>`

**Return on failure:** `None`

#### secp256k1_context_destroy

> Deallocates memory used by a provided context or does nothing if the provided context is `None`.

**Definition:** `secp256k1_context_destroy(ctx)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` or `None` | The context to destroy. |

**Return on success:** N/A

**Return on failure:** N/A

#### secp256k1_context_set_illegal_callback

> Sets a callback function to call when an illegal argument is passed to an internal API call, or restores the default handler if the callback function is `None`.

**Definition:** `secp256k1_context_set_illegal_callback(ctx, fun, data)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `fun` | `<ctype 'void(*)(char *, void *)'>` or `None` | The callback function to use. |
| `data` | `<cdata 'void *'>` or `None` | Data to pass to the callback function. |

**Return on success:** N/A

**Return on failure:** N/A

#### secp256k1_context_set_error_callback

> Sets a callback function to call when an internal consistency check fails, or restores the default handler if the callback function is `None`.

**Definition:** `secp256k1_context_set_error_callback(ctx, fun, data)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `fun` | `<ctype 'void(*)(char *, void *)'> or `None` | The callback function to use. |
| `data` | `<cdata 'void *'>` or `None` | Data to pass to the callback function. |

**Return on success:** N/A

**Return on failure:** N/A

#### secp256k1_scratch_space_create

> Returns a scratch space that is at most the provided max size.

**Definition:** `secp256k1_scratch_space_create(ctx, max_size)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `max_size` | `int` | The maximum amount of memory to allocate. |

**Return on success:** `<cdata 'struct secp256k1_scratch_space *'>`

**Return on failure:** `None`

#### secp256k1_scratch_space_destroy

> Deallocates memory used by a provided scratch space or does nothing if the scratch space is `None`.

**Definition:** `secp256k1_scratch_space_destroy(scratch)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `scratch` | `<cdata 'struct secp256k1_scratch_space *'>` or `None` | The scratch space to destroy. |

**Return on success:** N/A

**Return on failure:** N/A

#### secp256k1_ec_pubkey_parse

> Returns a public key if the provided input is a valid serialized public key.

**Definition:** `secp256k1_ec_pubkey_parse(ctx, input)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `input` | `bytes` | The serialized public key to parse. |

**Return on success:** `<cdata 'struct secp256k1_pubkey *'>`

**Return on failure:** `None`

#### secp256k1_ec_pubkey_serialize

> Returns the serialized version of a provided public key.

**Definition:** `secp256k1_ec_pubkey_serialize(ctx, pubkey, flags)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `pubkey` | `<cdata 'struct secp256k1_pubkey *'>` | The public key to serialize. |
| `flags` | `int` | `SECP256K1_EC_COMPRESSED` or `SECP256K1_EC_UNCOMPRESSED` |

**Return on success:** `bytes`

**Return on failure:** `None`

#### secp256k1_ecdsa_signature_parse_compact

> Returns an ECDSA signature if the provided input is a valid serialized ECDSA compact signature.

**Definition:** `secp256k1_ecdsa_signature_parse_compact(ctx, input64)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `input64` | `bytes` | The 64 byte serialized ECDSA compact signature to parse. |

**Return on success:** `<cdata 'struct secp256k1_ecdsa_signature *'>`

**Return on failure:** `None`

#### secp256k1_ecdsa_signature_parse_der

> Returns an ECDSA signature if the provided input is a valid serialized ECDSA DER signature.

**Definition:** `secp256k1_ecdsa_signature_parse_der(ctx, input)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `input` | `bytes` | The serialized ECDSA DER signature to parse. |

**Return on success:** `<cdata 'struct secp256k1_ecdsa_signature *'>`

**Return on failure:** `None`

#### secp256k1_ecdsa_signature_serialize_der

> Returns the serialized DER version of a provided ECDSA signature.

**Definition:** `secp256k1_ecdsa_signature_serialize_der(ctx, sig)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `sig` | `<cdata 'struct secp256k1_ecdsa_signature *'>` | The ECDSA signature to serialize. |

**Return on success:** `bytes`

**Return on failure:** `None`

#### secp256k1_ecdsa_signature_serialize_compact

> Returns the serialized compact version of a provided ECDSA signature.

**Definition:** `secp256k1_ecdsa_signature_serialize_compact(ctx, sig)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `sig` | `<cdata 'struct secp256k1_ecdsa_signature *'>` | The ECDSA signature to serialize. |

**Return on success:** `bytes`

**Return on failure:** `None`

#### secp256k1_ecdsa_verify

> Returns if the ECDSA signature is valid for the provided public key and message.

**Definition:** `secp256k1_ecdsa_verify(ctx, sig, msg32, pubkey)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `sig` | `<cdata 'struct secp256k1_ecdsa_signature *'>` | The ECDSA signature. |
| `msg32` | `bytes` | The 32 byte message that was signed. |
| `pubkey` | `<cdata 'struct secp256k1_pubkey *'>` | The public key corresponding to the secret key that signed the message. |

**Return on success:** `bool`

**Return on failure:** N/A

#### secp256k1_ecdsa_signature_normalize

> Returns the normalized version of the provided signature.

**Definition:** `secp256k1_ecdsa_signature_normalize(ctx, sigin)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `sigin` | `<cdata 'struct secp256k1_ecdsa_signature *'>` | The ECDSA signature to normalize. |

**Return on success:** `<cdata 'struct secp256k1_ecdsa_signature *'>`

**Return on failure:** N/A

#### secp256k1_ecdsa_sign

> Returns the ECDSA signature that signs a provided message with a provided secret key. A nonce function and nonce data can be provided to specify which nonce function to use.

**Definition:** `secp256k1_ecdsa_sign(ctx, msg32, seckey, noncefp, ndata)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `msg32` | `bytes` | The 32 byte message to sign. |
| `seckey` | `bytes` | The 32 byte secret key to sign the message with. |
| `noncefp` | `<cdata 'secp256k1_nonce_function'>` or `None` | The nonce function to use. Default to `secp256k1_nonce_function_default` if `None` is provided. |
| `ndata` | `bytes` or `None` | Data to use with the nonce function. |

**Return on success:** `<cdata 'struct secp256k1_ecdsa_signature *'>`

**Return on failure:** `None`

#### secp256k1_ec_seckey_verify

> Returns if a provided secret key is valid.

**Definition:** `secp256k1_ec_seckey_verify(ctx, seckey)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `seckey` | `bytes` | The 32 byte secret key to verify. |

**Return on success:** `bool`

**Return on failure:** N/A

#### secp256k1_ec_pubkey_create

> Returns the public key for a provided secret key.

**Definition:** `secp256k1_ec_pubkey_create(ctx, seckey)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `seckey` | `bytes` | The 32 byte secret key to get the public key of. |

**Return on success:** `<cdata 'struct secp256k1_pubkey *'>`

**Return on failure:** `None`

#### secp256k1_ec_privkey_negate

> Returns the negated version of a provided secret key. This function differs from its libsecp256k1-zkp equivalent in that it doesn't modify the provided secret key.

**Definition:** `secp256k1_ec_privkey_negate(ctx, seckey)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `seckey` | `bytes` | The 32 byte secret key to use. |

**Return on success:** `bytes`

**Return on failure:** `None`

#### secp256k1_ec_pubkey_negate

> Returns the negated version of a provided public key. This function differs from its libsecp256k1-zkp equivalent in that it doesn't modify the provided public key.

**Definition:** `secp256k1_ec_pubkey_negate(ctx, pubkey)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `pubkey` | `<cdata 'struct secp256k1_pubkey *'>` | The public key to use. |

**Return on success:** `<cdata 'struct secp256k1_pubkey *'>`

**Return on failure:** `None`

#### secp256k1_ec_privkey_tweak_add

> Returns the result of tweak adding with a provided secret key. This function differs from its libsecp256k1-zkp equivalent in that it doesn't modify the provided secret key.

**Definition:** `secp256k1_ec_privkey_tweak_add(ctx, seckey, tweak)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `seckey` | `bytes` | The 32 byte secret key to use. |
| `tweak` | `bytes` | The 32 byte tweak to use. |

**Return on success:** `bytes`

**Return on failure:** `None`

#### secp256k1_ec_pubkey_tweak_add

> Returns the result of tweak adding with a provided public key. This function differs from its libsecp256k1-zkp equivalent in that it doesn't modify the provided public key.

**Definition:** `secp256k1_ec_pubkey_tweak_add(ctx, pubkey, tweak)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `seckey` | `<cdata 'struct secp256k1_pubkey *'>` | The public key to use. |
| `tweak` | `bytes` | The 32 byte tweak to use. |

**Return on success:** `<cdata 'struct secp256k1_pubkey *'>`

**Return on failure:** `None`

#### secp256k1_ec_privkey_tweak_mul

> Returns the result of tweak multiplying with to a provided secret key. This function differs from its libsecp256k1-zkp equivalent in that it doesn't modify the provided secret key.

**Definition:** `secp256k1_ec_privkey_tweak_mul(ctx, seckey, tweak)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `seckey` | `bytes` | The 32 byte secret key to use. |
| `tweak` | `bytes` | The 32 byte tweak to use. |

**Return on success:** `bytes`

**Return on failure:** `None`

#### secp256k1_ec_pubkey_tweak_mul

> Returns the result of tweak multiplying with a provided public key. This function differs from its libsecp256k1-zkp equivalent in that it doesn't modify the provided public key.

**Definition:** `secp256k1_ec_pubkey_tweak_mul(ctx, pubkey, tweak)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `seckey` | `<cdata 'struct secp256k1_pubkey *'>` | The public key to use. |
| `tweak` | `bytes` | The 32 byte tweak to use. |

**Return on success:** `<cdata 'struct secp256k1_pubkey *'>`

**Return on failure:** `None`

#### secp256k1_context_randomize

> Returns the the randomized version of a provided context using an optional seed. This function differs from its libsecp256k1-zkp equivalent in that it doesn't modify the provided context.

**Definition:** `secp256k1_context_randomize(ctx, seed32)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `seed32` | `bytes` or `None` | The 32 byte seed to use. |

**Return on success:** `<cdata 'struct secp256k1_context *'>`

**Return on failure:** `None`

#### secp256k1_ec_pubkey_combine

> Returns the the result of combining a list if public keys.

**Definition:** `secp256k1_ec_pubkey_combine(ctx, ins)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `ins` | `list<<cdata 'struct secp256k1_pubkey *'>>` | The list of public keys to combine. |

**Return on success:** `<cdata 'struct secp256k1_pubkey *'>`

**Return on failure:** `None`

#### secp256k1_ec_privkey_tweak_inv

> Returns the result of tweak inverting a provided secret key. This function differs from its libsecp256k1-zkp equivalent in that it doesn't modify the provided secret key.

**Definition:** `secp256k1_ec_privkey_tweak_inv(ctx, seckey)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `seckey` | `bytes` | The 32 byte secret key to use. |

**Return on success:** `bytes`

**Return on failure:** `None`

#### secp256k1_ec_privkey_tweak_neg

> Returns the result of tweak negating a provided secret key. This function differs from its libsecp256k1-zkp equivalent in that it doesn't modify the provided secret key.

**Definition:** `secp256k1_ec_privkey_tweak_neg(ctx, seckey)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `seckey` | `bytes` | The 32 byte secret key to use. |

**Return on success:** `bytes`

**Return on failure:** `None`

#### secp256k1_aggsig_context_create

> Returns an aggsig context.

**Definition:** `secp256k1_aggsig_context_create(ctx, pubkeys, seed)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `pubkeys` | `list<<cdata 'struct secp256k1_pubkey *'>>` | The list of public keys that the context can aggregate the signatures for. |
| `seed` | `bytes` | The 32 byte seed used for nonce-generating. |

**Return on success:** `<cdata 'struct secp256k1_aggsig_context *'>`

**Return on failure:** `None`

#### secp256k1_aggsig_context_destroy

> Deallocates memory used by a provided aggsig context or does nothing if the provided aggsig context is `None`.

**Definition:** `secp256k1_aggsig_context_destroy(aggctx)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `aggctx` | `<cdata 'struct secp256k1_aggsig_context *'>` or `None` | The aggsig context to destroy. |

**Return on success:** N/A

**Return on failure:** N/A

#### secp256k1_aggsig_generate_nonce

> Returns if a nonce pair was successfully generated for the aggregate signature.

**Definition:** `secp256k1_aggsig_generate_nonce(ctx, aggctx, index)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `aggctx` | `<cdata 'struct secp256k1_aggsig_context *'>` | The aggsig context to use. |
| `index` | `int` | The index of the signature to generate the nonce for. |

**Return on success:** `bool`

**Return on failure:** N/A

#### secp256k1_aggsig_export_secnonce_single

> Returns a secret nonce.

**Definition:** `secp256k1_aggsig_export_secnonce_single(ctx, seed)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `seed` | `bytes` | The 32 byte random seed. |

**Return on success:** `bytes`

**Return on failure:** `None`

#### secp256k1_aggsig_sign_single

> Returns a single-signer signature.

**Definition:** `secp256k1_aggsig_sign_single(ctx, msg32, seckey32, secnonce32, extra32, pubnonce_for_e, pubnonce_total, pubkey_for_e, seed)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `msg32` | `bytes` | The 32 byte message to sign. |
| `seckey32` | `bytes` | The 32 byte secret key to sign the message with. |
| `secnonce32` | `bytes` or `None` | The 32 byte secret nonce to use. A nonce will be generated if `None` is used. |
| `extra32` | `bytes` or `None` | 32 bytes that will be added to s if not `None`. |
| `pubnonce_for_e` | `<cdata 'struct secp256k1_pubkey *'>` or `None` | This will be encoded in e instead of the derived if not `None`. |
| `pubnonce_total` | `<cdata 'struct secp256k1_pubkey *'>` or `None` | Allows this signature to be included in combined signature in all cases by negating secnonce32 if the this value isn't `None` and has Jacobi symbol -1. |
| `pubkey_for_e` | `<cdata 'struct secp256k1_pubkey *'>` or `None` | This will be encoded in e if not `None`. |
| `seed` | `bytes` | The 32 byte seed used for nonce-generating. |

**Return on success:** `<cdata 'struct secp256k1_ecdsa_signature *'>`

**Return on failure:** `None`

#### secp256k1_aggsig_partial_sign

> Returns a signature part in an aggregated signature.

**Definition:** `secp256k1_aggsig_partial_sign(ctx, aggctx, msg32, seckey32, index)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `aggctx` | `<cdata 'struct secp256k1_aggsig_context *'>` | The aggsig context to use. |
| `msg32` | `bytes` | The 32 byte message to sign. |
| `seckey32` | `bytes` | The 32 byte secret key to sign the message with. |
| `index` | `int` | The index of the signature in the aggregate signature. |

**Return on success:** `<cdata 'struct secp256k1_aggsig_partial_signature *'>`

**Return on failure:** `None`

#### secp256k1_aggsig_combine_signatures

> Returns aggregated signature created from multiple signature parts.

**Definition:** `secp256k1_aggsig_combine_signatures(ctx, aggctx, partial)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `aggctx` | `<cdata 'struct secp256k1_aggsig_context *'>` | The aggsig context to use. |
| `partial` | `list<<cdata 'struct secp256k1_aggsig_partial_signature *'>>` | List of partial signatures to aggregate. |

**Return on success:** `<cdata 'struct secp256k1_ecdsa_signature *'>`

**Return on failure:** `None`

#### secp256k1_aggsig_add_signatures_single

> Returns the result of adding two signatures into a single signature.

**Definition:** `secp256k1_aggsig_add_signatures_single(ctx, sigs, pubnonce_total)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `sigs` | `list<<cdata 'struct secp256k1_ecdsa_signature *'>>` | List of signatures to add. |
| `pubnonce_total` | `<cdata 'struct secp256k1_pubkey *'>` | The total of all public nonces. |

**Return on success:** `<cdata 'struct secp256k1_ecdsa_signature *'>`

**Return on failure:** `None`

#### secp256k1_aggsig_verify_single

> Returns if a single-signer signature verifies a provided message.

**Definition:** `secp256k1_aggsig_verify_single(ctx, sig64, msg32, pubnonce, pubkey, pubkey_total, extra_pubkey, is_partial)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `sig64` | `<cdata 'struct secp256k1_ecdsa_signature *'>` | The signature to verify the message. |
| `msg32` | `bytes` | The 32 byte message to verify. |
| `pubnonce` | `<cdata 'struct secp256k1_pubkey *'>` or `None` | This value overrides the public nonce used to calculate e if not `None`. |
| `pubkey` | `<cdata 'struct secp256k1_pubkey *'>` | The public key of the secret key that signed the message. |
| `pubkey_total` | `<cdata 'struct secp256k1_pubkey *'>` or `None` | This value is encoded in e if not `None`. |
| `extra_pubkey` | `<cdata 'struct secp256k1_pubkey *'>` or `None` | This value value is subtracted from sG if not `None`. |
| `is_partial` | `bool` | Allows verifying partial signatures that may have had their secret nonces negated. |

**Return on success:** `bool`

**Return on failure:** N/A

#### secp256k1_aggsig_verify

> Returns if an aggregated signature verifies a provided message.

**Definition:** `secp256k1_aggsig_verify(ctx, scratch, sig64, msg32, pubkeys)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `scratch` | `<cdata 'struct secp256k1_scratch_space *'>` | Scratch space to use. |
| `sig64` | `<cdata 'struct secp256k1_ecdsa_signature *'>` | The signature to verify the message. |
| `msg32` | `bytes` | The 32 byte message to verify. |
| `pubkeys` | `list<<cdata 'struct secp256k1_pubkey *'>>` | List of public keys of the secret keys that signed the message. |

**Return on success:** `bool`

**Return on failure:** N/A

#### secp256k1_aggsig_build_scratch_and_verify

> Returns if an aggregated signature verifies a provided message without needing a provided scratch space.

**Definition:** `secp256k1_aggsig_build_scratch_and_verify(ctx, sig64, msg32, pubkeys)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `sig64` | `<cdata 'struct secp256k1_ecdsa_signature *'>` | The signature to verify the message. |
| `msg32` | `bytes` | The 32 byte message to verify. |
| `pubkeys` | `list<<cdata 'struct secp256k1_pubkey *'>>` | List of public keys of the secret keys that signed the message. |

**Return on success:** `bool`

**Return on failure:** N/A

#### secp256k1_bulletproof_generators_create

> Returns a Bulletproof generators with the provided number of generators.

**Definition:** `secp256k1_bulletproof_generators_create(ctx, blinding_gen, n)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `blinding_gen` | `<cdata 'secp256k1_generator *'>` | The generator that the blinding factors will be multiplied by. |
| `n` | `int` | The number of generators to produce. |

**Return on success:** `<cdata 'struct secp256k1_bulletproof_generators *'>`

**Return on failure:** `None`

#### secp256k1_bulletproof_generators_destroy

> Deallocates memory used by a provided Bulletproof generators or does nothing if the Bulletproof generators is `None`.

**Definition:** `secp256k1_bulletproof_generators_destroy(ctx, gen)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `gen` | `<cdata 'struct secp256k1_bulletproof_generators *'>` or `None` | The Bulletproof generators to destroy. |

**Return on success:** N/A

**Return on failure:** N/A

#### secp256k1_bulletproof_rangeproof_verify

> Returns if a provided Bulletproof is valid.

**Definition:** `secp256k1_bulletproof_rangeproof_verify(ctx, scratch, gens, proof, min_value, commit, nbits, value_gen, extra_commit)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `scratch` | `<cdata 'struct secp256k1_scratch_space *'>` | The scratch space to use. |
| `gens` | `<cdata 'struct secp256k1_bulletproof_generators *'>` | The Bulletproof generators set to use. |
| `proof` | `bytes` | The Bulletproof to verify. |
| `min_value` | `list<int>` or `None` | The list of minimum values to prove the range is above. Defaults to all zeros if `None`.  |
| `commit` | `list<<cdata 'struct secp256k1_pedersen_commitment *'>>` | The list of Pedersen commitments that the Bulletproof is over. |
| `nbits` | `int` | The number of bits proven by the Bulletproof. |
| `value_gen` | `<cdata 'struct secp256k1_generator *'>` | The generator multiplied by the value in the Pedersen commitments. |
| `extra_commit` | `bytes` or `None` | The optional additional data committed to by the Bulletproof. |

**Return on success:** `bool`

**Return on failure:** N/A

#### secp256k1_bulletproof_rangeproof_verify_multi

> Returns if all provided Bulletproofs are valid.

**Definition:** `secp256k1_bulletproof_rangeproof_verify_multi(ctx, scratch, gens, proof, min_value, commit, nbits, value_gen, extra_commit)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `scratch` | `<cdata 'struct secp256k1_scratch_space *'>` | The scratch space to use. |
| `gens` | `<cdata 'struct secp256k1_bulletproof_generators *'>` | The Bulletproof generators set to use. |
| `proof` | `list<bytes>` | The list of Bulletproofs to verify. |
| `min_value` | `list<list<int>>` or `None` | The list of list of minimum values to prove each range is above. Defaults to all zeros if `None`.  |
| `commit` | `list<list<<cdata 'struct secp256k1_pedersen_commitment *'>>>` | The list of list of Pedersen commitments that each Bulletproof is over. |
| `nbits` | `int` | The number of bits proven by each Bulletproof. |
| `value_gen` | `list<<cdata 'struct secp256k1_generator *'>>` | The list of generators multiplied by the value in each Pedersen commitments. |
| `extra_commit` | `list<bytes>` or `None` | The list of optional additional data committed to by each Bulletproof. |

**Return on success:** `bool`

**Return on failure:** N/A

#### secp256k1_bulletproof_rangeproof_rewind

> Returns the value, blinding factor, and message from a provided Bulletproof.

**Definition:** `secp256k1_bulletproof_rangeproof_rewind(ctx, proof, min_value, commit, value_gen, nonce, extra_commit)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `proof` | `bytes` | The proof to get the information for. |
| `min_value` | `int` | The minimum value that the Bulletproof ranges over.  |
| `commit` | `<cdata 'struct secp256k1_pedersen_commitment *'>` | The Pedersen commitment that the Bulletproof is over. |
| `value_gen` | `<cdata 'struct secp256k1_generator *'>` | The generator multiplied by the value in the Pedersen commitment. |
| `nonce` | `bytes` | The 32 byte random seed used to derive blinding factors. |
| `extra_commit` | `bytes` or `None` | The optional additional data committed to by the Bulletproof. |

**Return on success:** `tuple<int, bytes, bytes>`

**Return on failure:** `None`

#### secp256k1_bulletproof_rangeproof_prove

> Returns a Bulletproof that proves the provided committed values.

**Definition:** `secp256k1_bulletproof_rangeproof_prove(ctx, scratch, gens, tau_x, t_one, t_two, value, min_value, blind, commits, value_gen, nbits, nonce, private_nonce, extra_commit, message)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `scratch` | `<cdata 'struct secp256k1_scratch_space *'>` | The scratch space to use. |
| `gens` | `<cdata 'struct secp256k1_bulletproof_generators *'>` | The Bulletproof generators set to use. |
| `tau_x` | `bytes` or `None` | The 32 byte tau x to use for a multi-party proof. |
| `t_one` | `<cdata 'struct secp256k1_pubkey *'>` or `None` | The t one to use for a multi-party proof. |
| `t_two` | `<cdata 'struct secp256k1_pubkey *'>` or `None` | The t two to use for a multi-party proof. |
| `value` | `list<int>` | The list of values to commit. |
| `min_value` | `list<int>` or `None` | The list of minimum values to prove the range is above. Defaults to all zeros if `None`.  |
| `blind` | `list<bytes>` | The list of 32 byte blinding factors for the Pedersen commitments. |
| `commits` | `list<<cdata 'struct secp256k1_pedersen_commitment *'>>` or `None` | The list of Pedersen commitments to use for a multi-party proof. |
| `value_gen` | `<cdata 'struct secp256k1_generator *'>` | The generator to multiply by the value in the Pedersen commitments. |
| `nbits` | `int` | The number of bits proven by the Bulletproof. |
| `nonce` | `bytes` | The 32 byte random seed used to derive blinding factors. |
| `private_nonce` | `bytes` or `None` | The 32 byte random seed used to derive private blinding factors for a multi-party proof. |
| `extra_commit` | `bytes` or `None` | The optional additional data committed to by the Bulletproof. |
| `message` | `bytes` or `None` | The optional 20 byte message that can be recovered by rewinding the Bulletproof. Defaults to all zeros if `None`. |

**Return on success:** `bytes`

**Return on failure:** `None`

#### secp256k1_pedersen_commitment_parse

> Returns a commit if the provided input is a valid serialized commit.

**Definition:** `secp256k1_pedersen_commitment_parse(ctx, input)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `input` | `bytes` | The serialized commit to parse. |

**Return on success:** `<cdata 'struct secp256k1_pedersen_commitment *'>`

**Return on failure:** `None`

#### secp256k1_pedersen_commitment_serialize

> Returns the serialized version of a provided commit.

**Definition:** `secp256k1_pedersen_commitment_serialize(ctx, commit)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `commit` | `<cdata 'struct secp256k1_pedersen_commitment *'>` | The commit to serialize. |

**Return on success:** `bytes`

**Return on failure:** `None`

#### secp256k1_pedersen_commit

> Returns a commit for the provided number value.

**Definition:** `secp256k1_pedersen_commit(ctx, blind, value, value_gen, blind_gen)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `blind` | `bytes` | The 32 byte blinding factor to use. |
| `value` | `int` | The value to get the commit for. |
| `value_gen` | `<cdata 'struct secp256k1_generator *'>` | The value generator to use. |
| `blind_gen` | `<cdata 'struct secp256k1_generator *'>` | The blind generator to use. |

**Return on success:** `<cdata 'struct secp256k1_pedersen_commitment *'>`

**Return on failure:** `None`

#### secp256k1_pedersen_blind_commit

> Returns a commit for the provided blinding factor value.

**Definition:** `secp256k1_pedersen_blind_commit(ctx, blind, value, value_gen, blind_gen)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `blind` | `bytes` | The 32 byte blinding factor to use. |
| `value` | `bytes` | The 32 byte value to get the commit for. |
| `value_gen` | `<cdata 'struct secp256k1_generator *'>` | The value generator to use. |
| `blind_gen` | `<cdata 'struct secp256k1_generator *'>` | The blind generator to use. |

**Return on success:** `<cdata 'struct secp256k1_pedersen_commitment *'>`

**Return on failure:** `None`

#### secp256k1_pedersen_blind_sum

> Returns the sum of provided blinding factors.

**Definition:** `secp256k1_pedersen_blind_sum(ctx, blinds, npositive)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `blinds` | `list<bytes>` | The list of 32 byte blinding factor to use. |
| `npositive` | `int` | How many of the blinding factors should be treated as being positive. |

**Return on success:** `bytes`

**Return on failure:** `None`

#### secp256k1_pedersen_commit_sum

> Returns the sum of provided positive and negative commits.

**Definition:** `secp256k1_pedersen_commit_sum(ctx, commits, ncommits)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `commits` | `list<<cdata 'struct secp256k1_pedersen_commitment *'>>` | The list of positive commits to use. |
| `ncommits` | `list<<cdata 'struct secp256k1_pedersen_commitment *'>>` | The list of negative commits to use. |

**Return on success:** `<cdata 'struct secp256k1_pedersen_commitment *'>`

**Return on failure:** `None`

#### secp256k1_pedersen_verify_tally

> Returns if the provided positive and negative commits sum to zero.

**Definition:** `secp256k1_pedersen_verify_tally(ctx, pos, neg)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `pos` | `list<<cdata 'struct secp256k1_pedersen_commitment *'>>` | The list of positive commits to use. |
| `neg` | `list<<cdata 'struct secp256k1_pedersen_commitment *'>>` | The list of negative commits to use. |

**Return on success:** `bool`

**Return on failure:** N/A

#### secp256k1_pedersen_blind_generator_blind_sum

> Returns the final blinding factor value needed to get the total sum to zero. This function differs from its libsecp256k1-zkp equivalent in that it doesn't modify the provided blinding factor.

**Definition:** `secp256k1_pedersen_blind_generator_blind_sum(ctx, value, generator_blind, blinding_factor, n_inputs)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `value` | `list<int>` | The list of values to use. |
| `generator_blind` | `list<bytes>` | The list of asset blinding factors to use. |
| `blinding_factor` | `list<bytes>` | List of commitment blinding factors to use. |
| `n_inputs` | `int`| The number of values that will be negated in the final sum. |

**Return on success:** `bytes`

**Return on failure:** `None`

#### secp256k1_blind_switch

> Returns the blinding factor used in the switch commit.

**Definition:** `secp256k1_blind_switch(ctx, blind, value, value_gen, blind_gen, switch_pubkey)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `blind` | `bytes` | The 32 byte blinding factor to use. |
| `value` | `int` | The value to commit to. |
| `value_gen` | `<cdata 'struct secp256k1_generator *'>` | The value generator to use. |
| `blind_gen` | `<cdata 'struct secp256k1_generator *'>` | The blind generator to use. |
| `switch_pubkey` | `<cdata 'struct secp256k1_pubkey *'>`| The public key to use. |

**Return on success:** `bytes`

**Return on failure:** `None`

#### secp256k1_pedersen_commitment_to_pubkey

> Returns the public key version of a provided commit.

**Definition:** `secp256k1_pedersen_commitment_to_pubkey(ctx, commit)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `commit` | `<cdata 'struct secp256k1_pedersen_commitment *'>` | The commit to use. |

**Return on success:** `<cdata 'struct secp256k1_pubkey *'>`

**Return on failure:** `None`

#### secp256k1_pubkey_to_pedersen_commitment

> Returns the commit version of a provided public key.

**Definition:** `secp256k1_pubkey_to_pedersen_commitment(ctx, pubkey)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `pubkey` | `<cdata 'struct secp256k1_pubkey *'>` | The public key to use. |

**Return on success:** `<cdata 'struct secp256k1_pedersen_commitment *'>`

**Return on failure:** `None`

#### secp256k1_ecdh

> Returns the EC Diffie-Hellman shared secret for the provided public key and private key.

**Definition:** `secp256k1_ecdh(ctx, pubkey, privkey)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `pubkey` | `<cdata 'struct secp256k1_pubkey *'>` | The public key to use. |
| `privkey` | `bytes` | The 32 byte secret key to use. |

**Return on success:** `bytes`

**Return on failure:** `None`

#### secp256k1_generator_parse

> Returns a generator if the provided input is a valid serialized generator.

**Definition:** `secp256k1_generator_parse(ctx, input)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `input` | `bytes` | The serialized generator to parse. |

**Return on success:** `<cdata 'struct secp256k1_generator *'>`

**Return on failure:** `None`

#### secp256k1_generator_serialize

> Returns the serialized version of a provided generator.

**Definition:** `secp256k1_generator_serialize(ctx, commit)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `commit` | `<cdata 'struct secp256k1_generator *'>` | The generator to serialize. |

**Return on success:** `bytes`

**Return on failure:** `None`

#### secp256k1_generator_generate

> Returns a generator created with a provided seed.

**Definition:** `secp256k1_generator_generate(ctx, seed32)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `seed32` | `bytes` | The 32 byte seed to use. |

**Return on success:** `<cdata 'struct secp256k1_generator *'>`

**Return on failure:** `None`

#### secp256k1_generator_generate_blinded

> Returns a blinded generator created with a provided key and blinding factor.

**Definition:** `secp256k1_generator_generate_blinded(ctx, key32, blind32)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `key32` | `bytes` | The 32 byte key to use. |
| `blind32` | `bytes` | The 32 byte blinding factor to use. |

**Return on success:** `<cdata 'struct secp256k1_generator *'>`

**Return on failure:** `None`

#### secp256k1_context_preallocated_size

> Returns the size in bytes required to create the type of preallocated context indicated by the provided flags.

**Definition:** `secp256k1_context_preallocated_size(flags)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `flags` | `int` | Bitwise combination of `SECP256K1_CONTEXT_VERIFY`, `SECP256K1_CONTEXT_SIGN`, and/or `SECP256K1_CONTEXT_NONE`. |

**Return on success:** `int`

**Return on failure:** N/A

#### secp256k1_context_preallocated_create

> Returns a context that uses the preallocated memory provided which can perform the features indicated by the provided flags.

**Definition:** `secp256k1_context_preallocated_create(prealloc, flags)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `prealloc` | `<cdata 'void *'>` | The preallocated memory for the context to use. |
| `flags` | `int` | Bitwise combination of `SECP256K1_CONTEXT_VERIFY`, `SECP256K1_CONTEXT_SIGN`, and/or `SECP256K1_CONTEXT_NONE`. |

**Return on success:** `<cdata 'struct secp256k1_context *'>`

**Return on failure:** `None`

#### secp256k1_context_preallocated_clone_size

> Returns the size in bytes required to create a preallocated context to clone a provided context.

**Definition:** `secp256k1_context_preallocated_clone_size(ctx)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to get the preallocated size of. |

**Return on success:** `int`

**Return on failure:** N/A

#### secp256k1_context_preallocated_clone

> Returns a copy of a provided context that uses the preallocated memory provided.

**Definition:** `secp256k1_context_preallocated_clone(ctx, prealloc)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to copy. |
| `prealloc` | `<cdata 'void *'>` | The preallocated memory for the context to use. |

**Return on success:** `<cdata 'struct secp256k1_context *'>`

**Return on failure:** `None`

#### secp256k1_context_preallocated_destroy

> Destroys a provided preallocated context or does nothing if the provided preallocated context is `None`.

**Definition:** `secp256k1_context_preallocated_destroy(ctx)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` or `None` | The preallocated context to destroy. |

**Return on success:** N/A

**Return on failure:** N/A

#### secp256k1_rangeproof_verify

> Returns the min and max values for a provided committed value if the provided rangeproof is valid for it.

**Definition:** `secp256k1_rangeproof_verify(ctx, commit, proof, extra_commit, gen)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `commit` | `<cdata 'struct secp256k1_pedersen_commitment *'>` | The commit for the committed value. |
| `proof` | `bytes` | The rangeproof to verify. |
| `extra_commit` | `bytes` or `None` | The optional additional data covered in the rangeproof. |
| `gen` | `<cdata 'struct secp256k1_generator *'>` | The additional generator. |

**Return on success:** `tuple<int, int>`

**Return on failure:** `None`

#### secp256k1_rangeproof_rewind

> Returns the blinding factor, value, message, min value, and max value for a provided rangeproof. The returned message's length isn't the actual length of the message, and this bug is inherent to libsecp256k1-zkp.

**Definition:** `secp256k1_rangeproof_rewind(ctx, nonce, commit, proof, extra_commit, gen)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `nonce` | `bytes` | The 32 byte secret nonce used to create the rangeproof. |
| `commit` | `<cdata 'struct secp256k1_pedersen_commitment *'>` | The commit for the committed value. |
| `proof` | `bytes` | The rangeproof to get values for. |
| `extra_commit` | `bytes` or `None` | The optional additional data covered in the rangeproof. |
| `gen` | `<cdata 'struct secp256k1_generator *'>` | The additional generator. |

**Return on success:** `tuple<bytes, int, bytes, int, int>`

**Return on failure:** `None`

#### secp256k1_rangeproof_sign

> Returns a rangeproof that proves a committed value is within a range.

**Definition:** `secp256k1_rangeproof_sign(ctx, min_value, commit, blind, nonce, exp, min_bits, value, message, extra_commit, gen)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `min_value` | `int` | The min value for the rangeproof to prove. |
| `commit` | `<cdata 'struct secp256k1_pedersen_commitment *'>` | The commit for the committed value. |
| `blind` | `bytes` | The 32 byte blinding factor used by the commit. |
| `nonce` | `bytes` | The 32 byte secret nonce to use. |
| `exp` | `int` | The exponent to use. |
| `min_bits` | `int` | The number of bits of the value to keep private. (0 = auto/minimal, - 64). |
| `value` | `int` | The committed value. |
| `message` | `bytes` or `None` | The optional 4096 byte message to embed in the rangeproof. |
| `extra_commit` | `bytes` or `None` | The optional additional data to cover in the rangeproof. |
| `gen` | `<cdata 'struct secp256k1_generator *'>` | The additional generator. |

**Return on success:** `bytes`

**Return on failure:** `None`

#### secp256k1_rangeproof_info

> Returns the exponent, mantissa, min value, and max value for a provided rangeproof.

**Definition:** `secp256k1_rangeproof_info(ctx, proof)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `proof` | `bytes` | The rangeproof to get info for. |

**Return on success:** `tuple<int, int, int, int>`

**Return on failure:** `None`

#### secp256k1_ecdsa_recoverable_signature_parse_compact

> Returns a recoverable signature if the provided input is a valid serialized recoverable signature.

**Definition:** `secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, input64, recid)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `input64` | `bytes` | The 64 byte serialized recoverable signature to parse. |
| `recid` | `int` | The recovery ID. |

**Return on success:** `<cdata 'struct secp256k1_ecdsa_recoverable_signature *'>`

**Return on failure:** `None`

#### secp256k1_ecdsa_recoverable_signature_convert

> Returns the ECDSA signature version of a provided recoverable signature.

**Definition:** `secp256k1_ecdsa_recoverable_signature_convert(ctx, sigin)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `sigin` | `<cdata 'struct secp256k1_ecdsa_recoverable_signature *'>` | The recoverable signature to convert. |

**Return on success:** `<cdata 'struct secp256k1_ecdsa_signature *'>`

**Return on failure:** `None`

#### secp256k1_ecdsa_recoverable_signature_serialize_compact

> Returns the serialized version and recovery ID of a provided recoverable signature.

**Definition:** `secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, sig)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `sig` | `<cdata 'struct secp256k1_ecdsa_recoverable_signature *'>` | The recoverable signature to serialize. |

**Return on success:** `tuple<bytes, int>`

**Return on failure:** `None`

#### secp256k1_ecdsa_sign_recoverable

> Returns the recoverable signature that signs a provided message with a provided secret key. A nonce function and nonce data can be provided to specify which nonce function to use.

**Definition:** `secp256k1_ecdsa_sign_recoverable(ctx, msg32, seckey, noncefp, ndata)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `msg32` | `bytes` | The 32 byte message to sign. |
| `seckey` | `bytes` | The 32 byte secret key to sign the message with. |
| `noncefp` | `<cdata 'secp256k1_nonce_function'>` or `None` | The nonce function to use. Default to `secp256k1_nonce_function_default` if `None` is provided. |
| `ndata` | `bytes` or `None` | Data to use with the nonce function. |

**Return on success:** `<cdata 'struct secp256k1_ecdsa_recoverable_signature *'>`

**Return on failure:** `None`

#### secp256k1_ecdsa_recover

> Returns a public key obtained from a provided recoverable signature and message.

**Definition:** `secp256k1_ecdsa_recover(ctx, sig, msg32)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `sig` | `<cdata 'struct secp256k1_ecdsa_recoverable_signature *'>` | The recoverable signature to get the public key from. |
| `msg32` | `bytes` | The 32 byte message to that was signed. |

**Return on success:** `<cdata 'struct secp256k1_pubkey *'>`

**Return on failure:** `None`

#### secp256k1_schnorrsig_serialize

> Returns the serialized version of a provided Schnorr signature.

**Definition:** `secp256k1_schnorrsig_serialize(ctx, sig)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `sig` | `<cdata 'struct secp256k1_schnorrsig *'>` | The Schnorr signature to serialize. |

**Return on success:** `bytes`

**Return on failure:** `None`

#### secp256k1_schnorrsig_parse

> Returns a Schnorr signature if the provided input is a valid serialized Schnorr signature.

**Definition:** `secp256k1_schnorrsig_parse(ctx, in64)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `in64` | `bytes` | The 64 byte serialized Schnorr signature to parse. |

**Return on success:** `<cdata 'struct secp256k1_schnorrsig *'>`

**Return on failure:** `None`

#### secp256k1_schnorrsig_sign

> Returns the Schnorr signature that signs a provided message with a provided secret key and if the nonce is negated. A nonce function and nonce data can be provided to specify which nonce function to use.

**Definition:** `secp256k1_schnorrsig_sign(ctx, msg32, seckey, noncefp, ndata)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `msg32` | `bytes` | The 32 byte message to sign. |
| `seckey` | `bytes` | The 32 byte secret key to sign the message with. |
| `noncefp` | `<cdata 'secp256k1_nonce_function'>` or `None` | The nonce function to use. Default to `secp256k1_nonce_function_bipschnorr` if `None` is provided. |
| `ndata` | `bytes` or `None` | Data to use with the nonce function. |

**Return on success:** `tuple<<cdata 'struct secp256k1_schnorrsig *'>, bool>`

**Return on failure:** `None`

#### secp256k1_schnorrsig_verify

> Returns if the Schnorr signature is valid for the provided public key and message.

**Definition:** `secp256k1_schnorrsig_verify(ctx, sig, msg32, pubkey)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `sig` | `<cdata 'struct secp256k1_schnorrsig *'>` | The Schnorr signature. |
| `msg32` | `bytes` | The 32 byte message that was signed. |
| `pubkey` | `<cdata 'struct secp256k1_pubkey *'>` | The public key corresponding to the secret key that signed the message. |

**Return on success:** `bool`

**Return on failure:** N/A

#### secp256k1_schnorrsig_verify_batch

> Returns if all the Schnorr signatures are valid for the provided public keys and messages.

**Definition:** `secp256k1_schnorrsig_verify_batch(ctx, scratch, sig, msg32, pk)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `scratch` | `<cdata 'struct secp256k1_scratch_space *'>` | Scratch space to use. |
| `sig` | `list<<cdata 'struct secp256k1_schnorrsig *'>>` | The Schnorr signatures. |
| `msg32` | `list<bytes>` | The 32 byte messages that were signed. |
| `pk` | `list<<cdata 'struct secp256k1_pubkey *'>>` | The public keys corresponding to the secret keys that signed the messages. |

**Return on success:** `bool`

**Return on failure:** N/A

#### secp256k1_surjectionproof_parse

> Returns a surjection proof if the provided input is a valid serialized surjection proof.

**Definition:** `secp256k1_surjectionproof_parse(ctx, input)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `input` | `bytes` | The serialized surjection proof to parse. |

**Return on success:** `<cdata 'struct secp256k1_surjectionproof *'>`

**Return on failure:** `None`

#### secp256k1_surjectionproof_serialize

> Returns the serialized version of a provided surjection proof.

**Definition:** `secp256k1_surjectionproof_serialize(ctx, proof)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `proof` | `<cdata 'struct secp256k1_surjectionproof *'>` | The surjection proof to serialize. |

**Return on success:** `bytes`

**Return on failure:** `None`

#### secp256k1_surjectionproof_n_total_inputs

> Returns the number of total inputs for a provided surjection proof.

**Definition:** `secp256k1_surjectionproof_n_total_inputs(ctx, proof)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `proof` | `<cdata 'struct secp256k1_surjectionproof *'>` | The surjection proof to get the number of total inputs for. |

**Return on success:** `int`

**Return on failure:** N/A

#### secp256k1_surjectionproof_n_used_inputs

> Returns the number of used inputs for a provided surjection proof.

**Definition:** `secp256k1_surjectionproof_n_used_inputs(ctx, proof)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `proof` | `<cdata 'struct secp256k1_surjectionproof *'>` | The surjection proof to get the number of used inputs for. |

**Return on success:** `int`

**Return on failure:** N/A

#### secp256k1_surjectionproof_serialized_size

> Returns the size in bytes required to serialize a provided surjection proof.

**Definition:** `secp256k1_surjectionproof_serialized_size(ctx, proof)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `proof` | `<cdata 'struct secp256k1_surjectionproof *'>` | The surjection proof to get the serialized size for. |

**Return on success:** `int`

**Return on failure:** N/A

#### secp256k1_surjectionproof_initialize

> Returns an initialized surjection proof and its input index.

**Definition:** `secp256k1_surjectionproof_initialize(ctx, fixed_input_tags, n_input_tags_to_use, fixed_output_tag, n_max_iterations, random_seed32)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `fixed_input_tags` | `list<<cdata 'struct secp256k1_fixed_asset_tag *'>>` | The fixed input tags for all inputs. |
| `n_input_tags_to_use` | `int` | The number of inputs to select randomly to put in the anonymity set. |
| `fixed_output_tag` | `<cdata 'struct secp256k1_fixed_asset_tag *'>` | The fixed output tag. |
| `n_max_iterations` | `int` | The max number of iterations to do before giving up. |
| `random_seed32` | `bytes` | The 32 byte random seed to use for input selection. |

**Return on success:** `tuple<<cdata 'struct secp256k1_surjectionproof *'>, int>`

**Return on failure:** `None`

#### secp256k1_surjectionproof_generate

> Returns the generated version of a provided initialized surjection proof. This function differs from its libsecp256k1-zkp equivalent in that it doesn't modify the provided proof.

**Definition:** `secp256k1_surjectionproof_generate(ctx, proof, ephemeral_input_tags, ephemeral_output_tag, input_index, input_blinding_key, output_blinding_key)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `proof` | `<cdata 'struct secp256k1_surjectionproof *'>` | The initialized surjection proof to use. |
| `ephemeral_input_tags` | `list<<cdata 'struct secp256k1_generator *'>>` | The ephemeral asset tags for all inputs. |
| `ephemeral_output_tag` | `<cdata 'struct secp256k1_generator *'>` | The ephemeral asset tag for the output. |
| `input_index` | `int` | The index of the input that actually maps to the output. |
| `input_blinding_key` | `bytes` | The 32 byte blinding key of the input. |
| `output_blinding_key` | `bytes` | The 32 byte blinding key of the output. |

**Return on success:** `<cdata 'struct secp256k1_surjectionproof *'>`

**Return on failure:** `None`

#### secp256k1_surjectionproof_verify

> Returns if verifying a provided surjection proof was successful.

**Definition:** `secp256k1_surjectionproof_verify(ctx, proof, ephemeral_input_tags, ephemeral_output_tag)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `proof` | `<cdata 'struct secp256k1_surjectionproof *'>` | The surjection proof to verify. |
| `ephemeral_input_tags` | `list<<cdata 'struct secp256k1_generator *'>>` | The ephemeral asset tags for all inputs. |
| `ephemeral_output_tag` | `<cdata 'struct secp256k1_generator *'>` | The ephemeral asset tag for the output. |

**Return on success:** `bool`

**Return on failure:** N/A

#### secp256k1_whitelist_signature_parse

> Returns a whitelist signature if the provided input is a valid serialized whitelist signature.

**Definition:** `secp256k1_whitelist_signature_parse(ctx, input)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `input` | `bytes` | The serialized whitelist signature to parse. |

**Return on success:** `<cdata 'struct secp256k1_whitelist_signature *'>`

**Return on failure:** `None`

#### secp256k1_whitelist_signature_n_keys

> Returns the number of keys for a provided whitelist signature.

**Definition:** `secp256k1_whitelist_signature_n_keys(sig)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `sig` | `<cdata 'struct secp256k1_whitelist_signature *'>` | The whitelist signature to get the number of keys for. |

**Return on success:** `int`

**Return on failure:** N/A

#### secp256k1_whitelist_signature_serialize

> Returns the serialized version of a provided whitelist signature.

**Definition:** `secp256k1_whitelist_signature_serialize(ctx, sig)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `sig` | `<cdata 'struct secp256k1_whitelist_signature *'>` | The whitelist signature to serialize. |

**Return on success:** `bytes`

**Return on failure:** `None`

#### secp256k1_whitelist_sign

> Returns the whitelist signature that signs a provided public key with a provided secret key from a group. A nonce function and nonce data can be provided to specify which nonce function to use.

**Definition:** `secp256k1_whitelist_sign(ctx, online_pubkeys, offline_pubkeys, sub_pubkey, online_seckey, summed_seckey, index, noncefp, noncedata)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `online_pubkeys` | `list<<cdata 'struct secp256k1_pubkey *'>>` | The list of online public keys. |
| `offline_pubkeys` | `list<<cdata 'struct secp256k1_pubkey *'>>` | The list of offline public keys. |
| `sub_pubkey` | `<cdata 'struct secp256k1_pubkey *'>` | The public key to be whitelisted. |
| `online_seckey` | `bytes` | The 32 byte online secret key to sign the public key with. |
| `summed_seckey` | `bytes` | The 32 byte secret key to the sum of the whitelisted public key's secret key and the offline secret key. |
| `index` | `int` | The index of the signer's key in the list of keys. |
| `noncefp` | `<cdata 'secp256k1_nonce_function'>` or `None` | The nonce function to use. Default to `secp256k1_nonce_function_default` if `None` is provided. |
| `noncedata` | `bytes` or `None` | Data to use with the nonce function. |

**Return on success:** `<cdata 'struct secp256k1_whitelist_signature *'>`

**Return on failure:** `None`

#### secp256k1_whitelist_verify

> Returns the whitelist signature verifies that a provided public key is whitelisted.

**Definition:** `secp256k1_whitelist_verify(ctx, sig, online_pubkeys, offline_pubkeys, sub_pubkey)`

**Parameters:**
| Name           | Type | Description |
|----------------|------|-------------|
| `ctx` | `<cdata 'struct secp256k1_context *'>` | The context to use. |
| `online_pubkeys` | `list<<cdata 'struct secp256k1_pubkey *'>>` | The list of online public keys. |
| `offline_pubkeys` | `list<<cdata 'struct secp256k1_pubkey *'>>` | The list of offline public keys. |
| `sub_pubkey` | `<cdata 'struct secp256k1_pubkey *'>` | The public key to verify. |

**Return on success:** `bool`

**Return on failure:** N/A
