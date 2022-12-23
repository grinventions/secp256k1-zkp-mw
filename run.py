from secp256k1_zkp_mw import ffi, lib

print('Generated definitions from C')
print()
for d in dir(lib):
    print(d)

print()
print('Running lib.secp256k1_context_create(lib.SECP256K1_CONTEXT_NONE)')
res = lib.secp256k1_context_create(lib.SECP256K1_CONTEXT_NONE)

print('...and it returned')
print(res)
