"""Detects whether the MPL is installed for use by internal ESDK code.
External customers should not need to interact with this.
"""


def has_mpl():
    """Returns True if the aws-cryptographic-material-providers library is installed, False otherwise."""
    try:
        _import_mpl()
        return True
    except ImportError:
        return False


def _import_mpl():
    """Private wrapper for import.
    This only exists to help with unit test coverage.
    This is not directly tested.
    """
    # pylint:disable=unused-import,import-outside-toplevel,import-error
    import aws_cryptographic_materialproviders  # noqa F401
