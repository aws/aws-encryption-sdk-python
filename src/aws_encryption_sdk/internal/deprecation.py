import warnings
import functools

def deprecated(reason):
    def decorator(cls):
        original_init = cls.__init__  # Save the original __init__

        @functools.wraps(cls.__init__)
        def new_init(self, *args, **kwargs):
            # Emit the deprecation warning whenever the class is instantiated
            warnings.warn(f"{cls.__name__} is deprecated: {reason}",
                          category=DeprecationWarning, stacklevel=2)
            original_init(self, *args, **kwargs)  # Call the original __init__

        cls.__init__ = new_init
        return cls
    return decorator