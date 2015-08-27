from setuptools import setup

setup(name='RedHatSecurityAdvisory',
      version='0.1',
      description='Script that automatically checks the RedHat security advisories to see if a CVE applies',
      author='Pieter-Jan Moreels',
      url='https://github.com/PidgeyL/RedHat-Advisory-Checker',
      entry_points={'console_scripts': ['rhsa = RHSA:redhatAdvisory.main']},
      packages=['RHSA'],
      license="Modified BSD license",
     )
