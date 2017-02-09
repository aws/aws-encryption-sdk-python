#!/usr/bin/env python
import os
import re

from setuptools import setup, find_packages

VERSION_RE = re.compile(r'''__version__ = ['"]([0-9.]+)['"]''')
HERE = os.path.abspath(os.path.dirname(__file__))


def read(*args):
    return open(os.path.join(HERE, *args)).read()


def get_version():
    init = read('aws_encryption_sdk', 'identifiers.py')
    return VERSION_RE.search(init).group(1)


setup(
    name='aws-encryption-sdk',
    packages=find_packages(exclude=['test*']),
    version=get_version(),
    author='Amazon Web Services',
    maintainer='Amazon Web Services',
    url='https://github.com/awslabs/aws-encryption-sdk-python',
    description='AWS Encryption SDK implementation for Python',
    long_description=read('README.md'),
    keywords='aws-encryption-sdk aws kms encryption',
    license='Apache License 2.0',
    install_requires=[
        'boto3>=1.4.4',
        'cryptography>=1.4.0',
        'attrs>=16.3.0'
    ],
    classifiers=[
        'Development Status :: 5 - Production/Stable',
        'Intended Audience :: Developers',
        'Natural Language :: English',
        'License :: OSI Approved :: Apache Software License',
        'Programming Language :: Python',
        'Programming Language :: Python :: 2',
        'Programming Language :: Python :: 2.7',
        'Programming Language :: Python :: 3',
        'Programming Language :: Python :: 3.4',
        'Programming Language :: Python :: Implementation :: CPython',
        'Topic :: Security',
        'Topic :: Security :: Cryptography'
    ]
)
