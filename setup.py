##############################################################################
#
# Copyright (c) 2011, 2012 Wapolabs
# All Rights Reserved.
#
##############################################################################
__version__ = '0.1.4'

import os

from setuptools import setup, find_packages

here = os.path.abspath(os.path.dirname(__file__))
README = open(os.path.join(here, 'README.txt')).read()
CHANGES = open(os.path.join(here, 'CHANGES.txt')).read()

setup(name='pyramid_facebookauthentication',
      version=__version__,
      description='Pyramid authentication policies for facebook',
      long_description=README + '\n\n' +  CHANGES,
      classifiers=[
        "Intended Audience :: Developers",
        "Programming Language :: Python",
        "Framework :: Pyramid",
        ],
      keywords='web wsgi pyramid pylons facebook authentication',
      author="Thomas Burke, WapoLabs",
      author_email="tburke@wapolabs.com",
      url="http://wapolabs.com",
      license="",
      packages=find_packages(),
      include_package_data=True,
      zip_safe=False,
      tests_require = ['pyramid',
                       'facebook-python-sdk',
                      ],
      install_requires=['pyramid',
                        'facebook-python-sdk',
                       ],
      test_suite="pyramid_facebookauthentication",
      entry_points = """\
      """
      )

