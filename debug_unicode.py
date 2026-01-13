#!/usr/bin/env python3
"""Minimal reproduction for Windows x86 Unicode crash"""

import warnings
import sys

def test_unicode_warning():
    """Test that triggers Unicode in warnings system - matches actual test behavior"""
    unicode_string = "\U00010002abc--abc\u79d8\u5bc6\u4ee3\u7801-\u79d8\u5bc6\u4ee3\u7801"
    
    # Don't print Unicode - just process it like the real test does
    print(f"Python version: {sys.version}")
    print(f"Platform: {sys.platform}")
    print(f"Architecture: {'x64' if sys.maxsize > 2**32 else 'x86'}")
    print(f"Unicode string length: {len(unicode_string)}")
    
    # Process the Unicode data (like the real test does)
    result = unicode_string.encode('utf-8')
    decoded = result.decode('utf-8')
    assert decoded == unicode_string
    
    # Trigger a warning with Unicode content (this is what causes the crash)
    warnings.warn(f"Test warning: {unicode_string}")
    
    print("Test completed successfully")

if __name__ == "__main__":
    test_unicode_warning()

