import os
import sys

from setuptools import setup, find_packages, Extension

setup(
    name="secp256k1-zkp-mw",
    version="0.4.2",
    description='FFI bindings to libsecp256k1-zkp for Mimblewimble protocol',
    long_description=open('README.md').read(),
    long_description_content_type="text/markdown",
    url='https://github.com/grinventions/secp256k1-zkp-mw',
    author='Marek Narozniak',
    author_email='marek.yggdrasil@gmail.com',
    maintainer='Nicolas Flamel',
    maintainer_email='nicolasflamel@mwcwallet.com',
    license='MIT',

    setup_requires=['cffi>=1.3.0'],
    install_requires=['cffi>=1.3.0'],

    packages=find_packages(),
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
