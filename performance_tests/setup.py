"""Performance test for the AWS Encryption SDK for Python."""
import os
import re

from setuptools import find_packages, setup

VERSION_RE = re.compile(r"""__version__ = ['"]([0-9.]+)['"]""")
HERE = os.path.abspath(os.path.dirname(__file__))


def read(*args):
    """Read complete file contents."""
    return open(os.path.join(HERE, *args), encoding="utf-8").read()  # pylint: disable=consider-using-with


def get_version():
    """Read the version from this module."""
    init = read("src", "aws_encryption_sdk_performance_tests", "__init__.py")
    return VERSION_RE.search(init).group(1)


setup(
    name="aws-encryption-sdk-performance-tests",
    packages=find_packages("src"),
    package_dir={"": "src"},
    author="Amazon Web Services",
    maintainer="Amazon Web Services",
    author_email="aws-cryptools@amazon.com",
    url="https://github.com/awslabs/aws-encryption-sdk-python",
    description="Performance tests for the AWS Encryption SDK for Python",
    keywords="aws-encryption-sdk aws kms encryption",
    license="Apache License 2.0",
    version=get_version(),
)
