"""AWS Encryption SDK for Python."""
import os
import re

from setuptools import find_packages, setup

VERSION_RE = re.compile(r'''__version__ = ['"]([0-9.]+)['"]''')
HERE = os.path.abspath(os.path.dirname(__file__))


def read(*args):
    """Reads complete file contents."""
    return open(os.path.join(HERE, *args)).read()


def get_version():
    """Reads the version from this module."""
    init = read('src', 'aws_encryption_sdk', 'identifiers.py')
    return VERSION_RE.search(init).group(1)


def get_requirements():
    """Reads the requirements file."""
    requirements = read('requirements.txt')
    return [r for r in requirements.strip().splitlines()]


setup(
    name='aws-encryption-sdk',
    packages=find_packages('src'),
    package_dir={'': 'src'},
    version=get_version(),
    author='Amazon Web Services',
    maintainer='Amazon Web Services',
    author_email='aws-cryptools@amazon.com',
    url='https://github.com/awslabs/aws-encryption-sdk-python',
    description='AWS Encryption SDK implementation for Python',
    long_description=read('README.rst'),
    keywords='aws-encryption-sdk aws kms encryption',
    license='Apache License 2.0',
    install_requires=get_requirements(),
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
