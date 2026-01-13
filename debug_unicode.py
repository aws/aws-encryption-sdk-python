#!/usr/bin/env python3
"""Minimal reproduction for Windows x86 Unicode crash"""

import warnings
import sys

def test_unicode_warning():
    """Test that triggers Unicode in warnings system"""
    unicode_string = "\U00010002abc--abc\u79d8\u5bc6\u4ee3\u7801-\u79d8\u5bc6\u4ee3\u7801"
    
    print(f"Python version: {sys.version}")
    print(f"Platform: {sys.platform}")
    print(f"Architecture: {sys.maxsize > 2**32}")
    print(f"Unicode string: {repr(unicode_string)}")
    
    # Trigger a warning with Unicode content
    warnings.warn(f"Test warning with Unicode: {unicode_string}")
    
    print("Test completed successfully")

if __name__ == "__main__":
    test_unicode_warning()
