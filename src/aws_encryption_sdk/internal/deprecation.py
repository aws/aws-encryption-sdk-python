import warnings
import functools

def deprecated(reason):
    def decorator(cls):
        # Define a new constructor that issues a deprecation warning
        @functools.wraps(cls.__init__)
        def new_init(self, *args, **kwargs):
            warnings.warn(f"{cls.__name__} is deprecated: {reason}",
                        category=DeprecationWarning, stacklevel=2)
            cls.__init__(self, *args, **kwargs)
        # Update the constructor of the class
        cls.__init__ = new_init
        return cls
    return decorator