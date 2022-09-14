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
secp256k1_context_clone
secp256k1_context_create
secp256k1_context_destroy
secp256k1_context_set_error_callback
secp256k1_context_set_illegal_callback

Running lib.secp256k1_context_create(lib.SECP256K1_CONTEXT_NONE)
...and it returned
<cdata 'struct secp256k1_context_struct *' 0x7f9432704440>
```
