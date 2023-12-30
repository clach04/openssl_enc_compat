#!/usr/bin/env python
# -*- coding: us-ascii -*-
# vim:ts=4:sw=4:softtabstop=4:smarttab:expandtab

import os
import sys
try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

if len(sys.argv) <= 1:
    print("""
Suggested setup.py parameters:

    * build
    * install
    * sdist  --formats=zip
    * sdist  # NOTE requires tar/gzip commands

    python -m pip install -e .

PyPi:

    twine upload dist/*

""")

readme_filename = 'README.md'
if os.path.exists(readme_filename):
    f = open(readme_filename)
    long_description = f.read()
    f.close()
else:
    long_description = None

project_name = 'openssl_enc_compat'
exec(open(os.path.join(os.path.abspath(os.path.dirname(__file__)), project_name, '_version.py')).read())  # get __version__

setup(
    name=project_name,
    version=__version__,
    author='clach04',
    url='https://github.com/clach04/' + project_name,
    description='Pure Python read/write encryption/decryption of encrypted OpenSSL 1.1.1 files',
    long_description=long_description,
    long_description_content_type='text/markdown',
    packages=[project_name],
    py_modules=[project_name, ],
    #data_files=[('.', [readme_filename])],  # does not work :-( Also tried setup.cfg [metadata]\ndescription-file = README.md # Maybe try include_package_data = True and a MANIFEST.in?
    classifiers=[  # See http://pypi.python.org/pypi?%3Aaction=list_classifiers
        'Development Status :: 4 - Beta',
        'License :: OSI Approved :: GNU Lesser General Public License v2 (LGPLv2)',
        'Operating System :: OS Independent',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.8',
        'Programming Language :: Python :: 3.12',
        # FIXME TODO more
        ],
    platforms='any',  # or distutils.util.get_platform()
    #install_requires=['pycryptodome'],  # pycryptodome (and/or PyCrypto)
)
