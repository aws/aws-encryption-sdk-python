def has_mpl():
    """Returns True if the aws_cryptographic_materialproviders library is installed, False otherwise."""
    try:
        _import_mpl()
        return True
    except ImportError:
        return False

def _import_mpl():
    """Private wrapper for import to help with unit test coverage.
    
    This is not directly tested.
    """
    import aws_cryptographic_materialproviders