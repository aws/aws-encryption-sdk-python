"""API Gateway + Lambda decryption oracle using the AWS Encryption SDK for Python."""
import os
import re

from setuptools import find_packages, setup

VERSION_RE = re.compile(r"""__version__ = ['"]([0-9.]+)['"]""")
HERE = os.path.abspath(os.path.dirname(__file__))


def read(*args):
    """Read complete file contents."""
    return open(os.path.join(HERE, *args)).read() # pylint: disable=consider-using-with


def get_version():
    """Read the version from this module."""
    init = read("src", "aws_encryption_sdk_decrypt_oracle", "__init__.py")
    return VERSION_RE.search(init).group(1)


def get_requirements():
    """Read the requirements file."""
    requirements = read("requirements-actual.txt")
    return list(requirements.strip().splitlines())


setup(
    name="aws-encryption-sdk-decrypt-oracle",
    packages=find_packages("src"),
    package_dir={"": "src"},
    version=get_version(),
    author="Amazon Web Services",
    maintainer="Amazon Web Services",
    author_email="aws-cryptools@amazon.com",
    url="https://github.com/awslabs/aws-encryption-sdk-python",
    description="API Gateway + Lambda decryption oracle using the AWS Encryption SDK for Python",
    long_description=read("README.rst"),
    keywords="aws-encryption-sdk aws kms encryption",
    license="Apache License 2.0",
    install_requires=get_requirements(),
    classifiers=[
        "Development Status :: 5 - Production/Stable",
        "Intended Audience :: Developers",
        "Natural Language :: English",
        "License :: OSI Approved :: Apache Software License",
        "Programming Language :: Python",
        "Programming Language :: Python :: 3.6",
        "Programming Language :: Python :: Implementation :: CPython",
        "Topic :: Security",
        "Topic :: Security :: Cryptography",
    ],
)
