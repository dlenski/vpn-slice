#!/usr/bin/env python3

import os
import sys

try:
    from setuptools import setup
except ImportError:
    from distutils.core import setup

if sys.version_info < (3, 3):
    sys.exit("Python 3.3+ is required; you are using %s" % sys.version)

########################################

version_py = os.path.join('vpn_slice', 'version.py')

d = {}
with open(version_py, 'r') as fh:
    exec(fh.read(), d)
    version_pep = d['__version__']

########################################

setup(
    name="vpn-slice",
    version=version_pep,
    description=("vpnc-script replacement for easy split-tunnel VPN setup"),
    long_description=open('README.md').read(),
    long_description_content_type='text/markdown',
    author="Daniel Lenski",
    author_email="dlenski@gmail.com",
    extras_require={
        "setproctitle": ["setproctitle"],
        "dnspython": ["dnspython"],
    },
    install_requires=["setproctitle", "dnspython"],
    license='GPL v3 or later',
    url="https://github.com/dlenski/vpn-slice",
    packages=["vpn_slice"],
    include_package_data=True,
    entry_points={'console_scripts': ['vpn-slice=vpn_slice.__main__:main']},
    classifiers={
        'Development Status :: 4 - Beta',
        'Environment :: Console',
        'Topic :: System :: Networking',
        'Topic :: System :: Systems Administration',
        'Operating System :: POSIX :: Linux',
        'Operating System :: POSIX :: BSD',
        'Operating System :: MacOS :: MacOS X',
        'License :: OSI Approved :: GNU General Public License v3 or later (GPLv3+)',
    }
)
