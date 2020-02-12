#!/usr/bin/python3

import os
from setuptools import setup


def _open_project_file(filename):
    proj_path = os.path.abspath(os.path.dirname(__file__))
    return open(os.path.join(proj_path, filename))


NAME = 'Honeyris'
VERSION = _open_project_file('VERSION').read().strip()
README = _open_project_file('README.md').read()
DESCRIPTION = (
    'A cost effective way to detect intrusion in your network '
    'in the form of a "Honeypot as a SIEM" (HaaS)'
)
AUTHOR = 'David Soria (@Sibwara)'
EMAIL = ''
URL = 'https://github.com/astar-security/Honeyris'
MODULES = [
    'honeyris'
]
PACKAGES = []
REQUIREMENTS = [
    'pyshark',
    'scapy',
]
ENTRY_POINTS = {
    "console_scripts": [
        "honeyris = honeyris:main",
    ],
}
CLASSIFIERS = [  # see https://pypi.org/classifiers/
    'Development Status :: 3 - Alpha',
    'Intended Audience :: Information Technology',
    'Intended Audience :: Other Audience',
    'Intended Audience :: System Administrators',
    'License :: OSI Approved :: GNU General Public License v3 (GPLv3)',
    'Natural Language :: English',
    'Operating System :: POSIX :: Linux',
    'Programming Language :: Python :: 3',
    'Topic :: Security',
    'Topic :: System :: Networking',
    'Topic :: Utilities',
]

if __name__ == '__main__':
    setup(
        name=NAME,
        version=VERSION,
        description=DESCRIPTION,
        long_description=README,
        author=AUTHOR,
        author_email=EMAIL,
        url=URL,
        py_modules=MODULES,
        packages=PACKAGES,
        install_requires=REQUIREMENTS,
        entry_points=ENTRY_POINTS,
        classifiers=CLASSIFIERS,
    )
