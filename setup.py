#!/usr/bin/env python

import sys
#from distutils.core import setup
from setuptools import setup

rh = open('README', 'r')
long_description = rh.read()
rh.close()

setup(name='MapResources',
      version='1.1',
      description='Whois resource mapping utility',
      author='Suresh Krishnaswamy',
      author_email='suresh@tislabs.com',
      url='https://securerouting.net',
      license='See LICENSE',
      long_description=long_description,
      packages=['map_resources'],
      scripts=['map_whois.py', 'query_resources.py'],
      platforms='any',
      install_requires=[
#          'pymongo',
#          'pprint',
#          'urllib',
#          'requests',
#          'xmltodict',
#          'pygraphviz',
#          'networkx',
#          'matplotlib',
#          'json2html',
#          'sqlite3',
#          'ipaddress',
      ],
     )
