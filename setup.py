from setuptools import setup, find_packages  # Always prefer setuptools over distutils
from codecs import open  # To use a consistent encoding
from os import path
import subprocess
from setuptools.command.install import install

here = path.abspath(path.dirname(__file__))

# Get the long description from the relevant file
with open(path.join(here, 'README'), encoding='utf-8') as f:
    long_description = f.read()

setup(
  name = 'bluecatopenstack',
  packages = ['bluecatopenstack'], # this must be the same as the name above
  entry_points={ 'neutron.ipam_drivers': [ 'bluecat = bluecatopenstack.driver:NeutronDbPool' ],},
  version = '0.1',
  license='Apache License, Version 2.0',
  description = 'BlueCat Networks - OpenStack Drivers',
  author = 'Brian Shorland',
  author_email = 'bshorland@bluecatnetworks.com',
  url = 'https://github.com/peterldowns/mypackage', # use the URL to the github repo
  download_url = 'https://github.com/peterldowns/mypackage/archive/0.1.tar.gz', # I'll explain this in a second
  install_requires = ['dnspython','configparser','suds','pprint','librabbitmq','ipaddress'],
	
  keywords = ['BlueCat', 'OpenStack', 'Driver'], # arbitrary keywords
  classifiers = [ 
  "Development Status :: 4 - Beta",
  "License :: OSI Approved :: Apache Software License",
  "Programming Language :: Python :: 2.7",
],
include_package_data=True,
package_data={
	'bluecatopenstack':[
		'driver.ini',
		'bluecat.conf',
		],
	'devstack':[
		'local.conf'
	],
},


)
