#!/usr/bin/env python3

import sys
try:
  from setuptools import setup
except ImportError:
  from distutils.core import setup

if sys.version_info < (3,3):
    sys.exit("Python 3.3+ is required; you are using %s" % sys.version)

setup(name="vpn_slice",
      version="0.1",
      description=("vpnc-script replacement for easy split-tunnel VPN setup"),
      long_description=open('README.md').read(),
      author="Daniel Lenski",
      author_email="dlenski@gmail.com",
      install_requires=[],
      license='GPL v3 or later',
      url="https://github.com/dlenski/vpn-slice",
      packages=["vpn_slice"],
      include_package_data = True,
      entry_points={ 'console_scripts': [ 'vpn-slice=vpn_slice.main:main' ] }
      )
