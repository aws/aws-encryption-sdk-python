import warnings
import functools

def deprecated(reason):
    def decorator(cls):
        @functools.wraps(cls)
        def new_cls(*args, **kwargs):
            warnings.warn(f"{cls.__name__} is deprecated: {reason}", category=DeprecationWarning, stacklevel=2)
            return cls(*args, **kwargs)
        return new_cls
    return decorator