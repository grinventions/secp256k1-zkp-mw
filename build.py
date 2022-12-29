import os
import sys
import shutil
import tarfile

from io import BytesIO

try:
    from urllib2 import urlopen, URLError
except ImportError:
    from urllib.request import urlopen
    from urllib.error import URLError

from cffi import FFI, VerificationError

LIB_COMMIT = '8d1f5bb152580446a3438cd705caebacc2a5d850'
LIB_TARBALL_URL = 'https://github.com/mimblewimble/secp256k1-zkp/archive/{0}.tar.gz'.format(LIB_COMMIT)

def download_library(basepath):
    libdir = os.path.join(os.path.abspath(basepath), 'secp256k1-zkp')
    if os.path.exists(os.path.join(libdir, 'autogen.sh')):
        return
    try:
        r = urlopen(LIB_TARBALL_URL)
        if r.getcode() == 200:
            content = BytesIO(r.read())
            content.seek(0)
            with tarfile.open(fileobj=content) as tf:
                dirname = tf.getnames()[0].partition('/')[0]
                tf.extractall()
                tarpath = os.path.join(basepath, dirname)
                os.rename(tarpath, libdir)
        else:
            raise SystemExit(
                'Unable to download secp256k1 library: HTTP-Status: {0}'.format(str(r.getcode())))
    except URLError as ex:
        raise SystemExit('Unable to download secp256k1 library: {0}'.format(ex.message))

basepath = os.path.abspath(os.path.dirname(__file__))

download_library(basepath)

ffi = FFI()

dirs = ['/secp256k1-zkp/include']
c_files = []
h_files = []

for d in dirs:
    root_dir = basepath + d
    cwd = str(os.getcwdb())

    for root, dirs, _files in os.walk(root_dir):
        for f in _files:
            path = os.path.join(os.path.abspath(root), f)
            if (f.endswith('.h')):
                h_files.append(path)

c_files = [
    basepath + '/secp256k1-zkp/contrib/lax_der_parsing.c',
    basepath + '/secp256k1-zkp/src/secp256k1.c'
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

with open(basepath + '/defs.c', 'rt') as fid:
    _source = fid.read()
    ffi.cdef(_source)

ffi.set_source(
    "_secp256k1_zkp_mw",
    include,
    include_dirs=[
        basepath + '/secp256k1-zkp',
        basepath + '/secp256k1-zkp/src',
        basepath + '/secp256k1-zkp/include'
    ],
    extra_compile_args=['-g'],
    sources=c_files,
    define_macros=definitions
)

if __name__ == "__main__":
    ffi.compile()
