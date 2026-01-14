import pytest

@pytest.mark.parametrize('key1,key2', [
    ('\U00010002abc2', 'abc\u79d8\u5bc6\u4ee3\u78012'),
    ('test1_2', 'test2_2'),
    ('\U00010002_2', '\u79d8\u5bc6\u4ee3\u7801-abc\U00010002-\U00010002abc\u79d8\u5bc6\u4ee3\u7801123\U00010002-\u79d8\u5bc6\u4ee3\u7801abc\U00010002'),
])
def test_unicode_params_2(key1, key2):
    assert len(key1) > 0
    assert len(key2) > 0
    import warnings
    warnings.warn(f'Test warning {key1} {key2}')
