import warnings
import functools

def deprecated(reason):
    def decorator(cls):
        if cls.__init__ is object.__init__:
            # If cls.__init__ is object.__init__, define a basic __init__ to wrap
            def new_init(self, *args, **kwargs):
                warnings.warn(f"{cls.__name__} is deprecated: {reason}",
                              category=DeprecationWarning, stacklevel=2)
        else:
            original_init = cls.__init__  # Save the original __init__

            @functools.wraps(cls.__init__)
            def new_init(self, *args, **kwargs):
                warnings.warn(f"{cls.__name__} is deprecated: {reason}",
                              category=DeprecationWarning, stacklevel=2)
                original_init(self, *args, **kwargs)  # Call the original __init__

        cls.__init__ = new_init
        return cls
    
    return decorator