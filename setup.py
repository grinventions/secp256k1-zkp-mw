import os
import sys

from setuptools import setup, find_packages, Extension

setup(
    name="secp256k1-zkp-mw",
    version="0.1.0",

    description='FFI bindings to libsecp256k1-zkp for Mimblewimble protocol',
    url='https://github.com/grinventions/secp256k1-zkp-mw',
    author='Marek Narozniak',
    author_email='marek.yggdrasil@gmail.com',
    license='MIT',

    setup_requires=['cffi>=1.3.0'],
    install_requires=['cffi>=1.3.0'],

    packages=find_packages(),
    ext_package='secp256k1_zkp_mw',
    cffi_modules=[
        'build.py:ffi'
    ],

    classifiers=[
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 2",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: Implementation :: CPython",
        "Programming Language :: Python :: Implementation :: PyPy",
        "Topic :: Software Development :: Libraries",
        "Topic :: Security :: Cryptography"
    ]
)