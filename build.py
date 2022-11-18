import os
import sys

from cffi import FFI, VerificationError

ffi = FFI()

dirs = ['/secp256k1-zkp/include']
c_files = []
h_files = []

# os.environ['USE_NUM_NONE'] = '1'

for d in dirs:
    root_dir = os.path.abspath(os.path.dirname(__file__)) + d
    cwd = str(os.getcwdb())

    for root, dirs, _files in os.walk(root_dir):
        for f in _files:
            path = os.path.join(os.path.relpath(root), f)
            if (f.endswith('.h')):
                h_files.append(path)

c_files = [
    'secp256k1-zkp/contrib/lax_der_parsing.c',
    'secp256k1-zkp/src/secp256k1.c'
]

definitions = [
    ('USE_NUM_NONE', '1'),
    ('USE_FIELD_INV_BUILTIN', '1'),
    ('USE_SCALAR_INV_BUILTIN', '1'),
    ('USE_FIELD_10X26', '1'),
    ('USE_SCALAR_8X32', '1'),
    ('USE_ENDOMORPHISM', '1'),
    ('ENABLE_MODULE_ECDH', '1'),
    ('ENABLE_MODULE_GENERATOR', '1'),
    ('ENABLE_MODULE_RECOVERY', '1'),
    ('ENABLE_MODULE_RANGEPROOF', '1'),
    ('ENABLE_MODULE_BULLETPROOF', '1'),
    ('ENABLE_MODULE_AGGSIG', '1'),
    ('ENABLE_MODULE_SCHNORRSIG', '1'),
    ('ENABLE_MODULE_COMMITMENT', '1'),
    ('ENABLE_MODULE_WHITELIST', '1'),
    ('ENABLE_MODULE_SURJECTIONPROOF', '1')
]

include = ''
for f in h_files:
     include += '#include "{0}"\n'.format(f)

with open('defs.c', 'rt') as fid:
    _source = fid.read()
    ffi.cdef(_source)

ffi.set_source(
    "secp256k1_mw",
    include,
    include_dirs=['secp256k1-zkp', 'secp256k1-zkp/src', 'secp256k1-zkp/include'],
    extra_compile_args=['-g', '-Wno-unused-function', '-Wno-nonnull-compare', '-Wno-maybe-uninitialized'],
    sources=c_files,
    define_macros=definitions
)

ffi.compile()
