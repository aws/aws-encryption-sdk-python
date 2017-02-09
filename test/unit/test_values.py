"""Values to use in various unit test suites."""
import copy
import struct

from mock import MagicMock
import six

import aws_encryption_sdk.internal.defaults
from aws_encryption_sdk.identifiers import (
    Algorithm, ContentType, ObjectType, SerializationVersion
)
from aws_encryption_sdk.internal.structures import (
    EncryptedData, MessageHeaderAuthentication,
    MessageNoFrameBody, MessageFrameBody, MessageFooter
)
from aws_encryption_sdk.structures import DataKey, MessageHeader, EncryptedDataKey, MasterKeyInfo


def array_byte(source):
    if six.PY2:
        return six.b(source)
    else:
        return source


VALUES = {
    'header': b'serialized_header',
    'header_auth': b'serialized header auth',
    'body_single_block': b'serialized single block body',
    'body_frame': b'frame body',
    'body_final_frame': b'final frame body',
    'footer': b'footer',
    'data_128': six.b(
        '\xa3\xf6\xbc\x89\x95\x15(\xc8}\\\x8d=zu^{JA\xc1\xe9\xf0&m\xe6TD\x03'
        '\x165F\x85\xae\x96\xd9~ \xa6\x13\x88\xf8\xdb\xc9\x0c\xd8\xd8\xd4\xe0'
        '\x02\xe9\xdb+\xd4l\xeaq\xf6\xba.cg\xda\xe4V\xd9\x9a\x96\xe8\xf4:\xf5'
        '\xfd\xd7\xa6\xfa\xd1\x85\xa7o\xf5\x94\xbcE\x14L\xa1\x87\xd9T\xa6\x95'
        'eZVv\xfe[\xeeJ$a<9\x1f\x97\xe1\xd6\x9dQc\x8b7n\x0f\x1e\xbd\xf5\xba'
        '\x0e\xae|%\xd8L]\xa2\xa2\x08\x1f'
    ),
    'provider_id': 'ex-provider',
    'key_info': b'ex-key-info',
    'key_info2': b'ex-key-info2',
    'ciphertext_len': b'\x00\x00\x00\x80',
    'ciphertext_len_single_block': b'\x00\x00\x00\x00\x00\x00\x00\x80',
    'block_size': 128,
    'iv_len': 12,
    'tag_len': 16,
    'data_key_len': 32,
    'content_len': 32,
    'small_frame_length': 32,
    'algorithm_id': 0x0378,
    'encryption_context': {
        'key_a': 'value_a',
        'key_b': 'value_b',
        'key_c': 'value_c'
    },
    'serialized_encryption_context': six.b(
        '\x00\x04'
        '\x00\x15aws-crypto-public-key\x00DAmZvwV/dN6o9p/usAnJdRcdnE12UbaDHuEFPeyVkw5FC1ULGlSznzDdD3FP8SW1UMg=='
        '\x00\x05key_a\x00\x07value_a'
        '\x00\x05key_b\x00\x07value_b'
        '\x00\x05key_c\x00\x07value_c'
    ),
    'serialized_encryption_context_duplicate_key': six.b(
        '\x00\x04'
        '\x00\x05key_a\x00\x07value_a'
        '\x00\x05key_b\x00\x07value_b'
        '\x00\x05key_c\x00\x07value_c'
        '\x00\x05key_c\x00\x07value_c'
    ),
    'encoded_curve_point': 'AmZvwV/dN6o9p/usAnJdRcdnE12UbaDHuEFPeyVkw5FC1ULGlSznzDdD3FP8SW1UMg==',
    'arn': b'arn:aws:kms:us-east-1:248168362296:key/ce78d3b3-f800-4785-a3b9-63e30bb4b183',
    'arn_str': 'arn:aws:kms:us-east-1:248168362296:key/ce78d3b3-f800-4785-a3b9-63e30bb4b183',
    'data_key': six.b(
        '\x00\xfa\x8c\xdd\x08Au\xc6\x92_4\xc5\xfb\x90\xaf\x8f\xa1D\xaf\xcc\xd25\xa8\x0b\x0b\x16\x92\x91W\x01\xb7\x84'
    ),
    'encrypted_data_key': six.b(
        '\n \x8b\xc6\xfd\x91\xc7\xd5\xdc+S\x15n\xd9P\x99n\x1d\xb2\xdd\x15\xeaW'
        '\xc3\x13k2\xf6\x02\xd0\x0f\x85\xec\x9e\x12\xa7\x01\x01\x01\x01\x00x'
        '\x8b\xc6\xfd\x91\xc7\xd5\xdc+S\x15n\xd9P\x99n\x1d\xb2\xdd\x15\xeaW'
        '\xc3\x13k2\xf6\x02\xd0\x0f\x85\xec\x9e\x00\x00\x00~0|\x06\t*\x86H'
        '\x86\xf7\r\x01\x07\x06\xa0o0m\x02\x01\x000h\x06\t*\x86H\x86\xf7\r'
        '\x01\x07\x010\x1e\x06\t`\x86H\x01e\x03\x04\x01.0\x11\x04\x0c\xc9rP'
        '\xa1\x08t6{\xf2\xfd\xf1\xb3\x02\x01\x10\x80;D\xa4\xed`qP~c\x0f\xa0d'
        '\xd5\xa2Kj\xc7\xb2\xc6\x1e\xec\xfb\x0fK\xb2*\xd5\t2\x81pR\xee\xd1'
        '\x1a\xde<"\x1b\x98\x88\x8b\xf4&\xdaB\x95I\xd2\xff\x10\x13\xfc\x1aX'
        '\x08,/\x8b\x8b'
    ),
    'serialized_encrypted_data_key': six.b(
        '\x00\x07'
        'aws-kms'
        '\x00K'
        'arn:aws:kms:us-east-1:248168362296:key/ce78d3b3-f800-4785-a3b9-63e30bb4b183'
        '\x00\xcc'
        '\n \x8b\xc6\xfd\x91\xc7\xd5\xdc+S\x15n\xd9P\x99n\x1d\xb2\xdd\x15\xea'
        'W\xc3\x13k2\xf6\x02\xd0\x0f\x85\xec\x9e\x12\xa7\x01\x01\x01\x01\x00x'
        '\x8b\xc6\xfd\x91\xc7\xd5\xdc+S\x15n\xd9P\x99n\x1d\xb2\xdd\x15\xeaW'
        '\xc3\x13k2\xf6\x02\xd0\x0f\x85\xec\x9e\x00\x00\x00~0|\x06\t*\x86H'
        '\x86\xf7\r\x01\x07\x06\xa0o0m\x02\x01\x000h\x06\t*\x86H\x86\xf7\r'
        '\x01\x07\x010\x1e\x06\t`\x86H\x01e\x03\x04\x01.0\x11\x04\x0c\xc9rP'
        '\xa1\x08t6{\xf2\xfd\xf1\xb3\x02\x01\x10\x80;D\xa4\xed`qP~c\x0f\xa0d'
        '\xd5\xa2Kj\xc7\xb2\xc6\x1e\xec\xfb\x0fK\xb2*\xd5\t2\x81pR\xee\xd1'
        '\x1a\xde<"\x1b\x98\x88\x8b\xf4&\xdaB\x95I\xd2\xff\x10\x13\xfc\x1aX'
        '\x08,/\x8b\x8b'
    ),
    'message_id': b'_\xfd\xb3%\xa5}yd\x80}\xe2\x90\xf9\x0e&\x8f',
    'serialized_header': six.b(
        '\x01\x80\x03x_\xfd\xb3%\xa5}yd\x80}\xe2\x90\xf9\x0e&\x8f\x00\x8f\x00'
        '\x04\x00\x15aws-crypto-public-key\x00DAmZvwV/dN6o9p/usAnJdRcdnE12Uba'
        'DHuEFPeyVkw5FC1ULGlSznzDdD3FP8SW1UMg==\x00\x05key_a\x00\x07value_a'
        '\x00\x05key_b\x00\x07value_b\x00\x05key_c\x00\x07value_c\x00\x01\x00'
        '\x07aws-kms\x00Karn:aws:kms:us-east-1:248168362296:key/ce78d3b3-f800'
        '-4785-a3b9-63e30bb4b183\x00\xcc\n \x8b\xc6\xfd\x91\xc7\xd5\xdc+S\x15'
        'n\xd9P\x99n\x1d\xb2\xdd\x15\xeaW\xc3\x13k2\xf6\x02\xd0\x0f\x85\xec'
        '\x9e\x12\xa7\x01\x01\x01\x01\x00x\x8b\xc6\xfd\x91\xc7\xd5\xdc+S\x15'
        'n\xd9P\x99n\x1d\xb2\xdd\x15\xeaW\xc3\x13k2\xf6\x02\xd0\x0f\x85\xec'
        '\x9e\x00\x00\x00~0|\x06\t*\x86H\x86\xf7\r\x01\x07\x06\xa0o0m\x02\x01'
        '\x000h\x06\t*\x86H\x86\xf7\r\x01\x07\x010\x1e\x06\t`\x86H\x01e\x03'
        '\x04\x01.0\x11\x04\x0c\xc9rP\xa1\x08t6{\xf2\xfd\xf1\xb3\x02\x01\x10'
        '\x80;D\xa4\xed`qP~c\x0f\xa0d\xd5\xa2Kj\xc7\xb2\xc6\x1e\xec\xfb\x0fK'
        '\xb2*\xd5\t2\x81pR\xee\xd1\x1a\xde<"\x1b\x98\x88\x8b\xf4&\xdaB\x95I'
        '\xd2\xff\x10\x13\xfc\x1aX\x08,/\x8b\x8b\x02\x00\x00\x00\x00\x0c\x00'
        '\x00\x10\x00'
    ),
    'serialized_header_small_frame': six.b(
        '\x01\x80\x03x_\xfd\xb3%\xa5}yd\x80}\xe2\x90\xf9\x0e&\x8f\x00\x8f\x00'
        '\x04\x00\x15aws-crypto-public-key\x00DAmZvwV/dN6o9p/usAnJdRcdnE12Uba'
        'DHuEFPeyVkw5FC1ULGlSznzDdD3FP8SW1UMg==\x00\x05key_a\x00\x07value_a'
        '\x00\x05key_b\x00\x07value_b\x00\x05key_c\x00\x07value_c\x00\x01\x00'
        '\x07aws-kms\x00Karn:aws:kms:us-east-1:248168362296:key/ce78d3b3-f800'
        '-4785-a3b9-63e30bb4b183\x00\xcc\n \x8b\xc6\xfd\x91\xc7\xd5\xdc+S\x15'
        'n\xd9P\x99n\x1d\xb2\xdd\x15\xeaW\xc3\x13k2\xf6\x02\xd0\x0f\x85\xec'
        '\x9e\x12\xa7\x01\x01\x01\x01\x00x\x8b\xc6\xfd\x91\xc7\xd5\xdc+S\x15'
        'n\xd9P\x99n\x1d\xb2\xdd\x15\xeaW\xc3\x13k2\xf6\x02\xd0\x0f\x85\xec'
        '\x9e\x00\x00\x00~0|\x06\t*\x86H\x86\xf7\r\x01\x07\x06\xa0o0m\x02\x01'
        '\x000h\x06\t*\x86H\x86\xf7\r\x01\x07\x010\x1e\x06\t`\x86H\x01e\x03'
        '\x04\x01.0\x11\x04\x0c\xc9rP\xa1\x08t6{\xf2\xfd\xf1\xb3\x02\x01\x10'
        '\x80;D\xa4\xed`qP~c\x0f\xa0d\xd5\xa2Kj\xc7\xb2\xc6\x1e\xec\xfb\x0fK'
        '\xb2*\xd5\t2\x81pR\xee\xd1\x1a\xde<"\x1b\x98\x88\x8b\xf4&\xdaB\x95I'
        '\xd2\xff\x10\x13\xfc\x1aX\x08,/\x8b\x8b\x02\x00\x00\x00\x00\x0c\x00'
        '\x00\x00 '
    ),
    'header_auth_base': EncryptedData(
        iv=b's\x15<P\xaa\x94\xb8\x931P\xeb\xa0',
        ciphertext=b'',
        tag=b'\x91\xc5\xf7<\x7f\xc9\xb1k\x0e\xe2{\xe4\x97\x9d\xdbU'
    ),
    'serialized_header_auth': b's\x15<P\xaa\x94\xb8\x931P\xeb\xa0\x91\xc5\xf7<\x7f\xc9\xb1k\x0e\xe2{\xe4\x97\x9d\xdbU',
    'single_block_aac': six.b(
        '_\xfd\xb3%\xa5}yd\x80}\xe2\x90\xf9\x0e&\x8fAWSKMSEncryptionClient'
        ' Single Block\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00 '
    ),
    'frame_aac': six.b(
        '_\xfd\xb3%\xa5}yd\x80}\xe2\x90\xf9\x0e&\x8fAWSKMSEncryptionClient'
        ' Frame\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00 '
    ),
    'final_frame_aac': six.b(
        '_\xfd\xb3%\xa5}yd\x80}\xe2\x90\xf9\x0e&\x8fAWSKMSEncryptionClient'
        ' Final Frame\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00 '
    ),
    'final_frame_base': EncryptedData(
        iv=b'#O|\x9cb]\x14-\x17?"\x8c',
        ciphertext=six.b(
            "p/q\xb6\x98z\x9e\x1fG\xc1\xa1\xb9\xcd|%'\xda\x92h\xb4\xa8=DqM"
            "\x0f\x81\xf8\x99fvd\x8f\x0fF3\xb2\x81\x85\xa1\xe5\xe8\xbf\r\x98"
            "\xbc\xbb\xbb{\x85\xea7\xe4\xc9m\x94|\xea\xabX\xf7B?\x05k\x0c\xdc"
            "\xd6D\x8a\xfbH~d\x8d\xcf\x04\x9b\x08&\xe2\x00\x1d\xf1\x85\x89"
            "\x9c6\x841\x9d\xae~,,w\x05\xa6\x8e\x13\x13\xee\x92\x91\xfc\x81\\"
            "\xf0;\x04\x08`\xf2\xe8\x999\xcd^\t\xce\xb2\xf7\xab$F\x19!K"
        ),
        tag=b'\xe9\xae*E\x8b\xfa\xa3SE+\xe5\xfa\xa3R\x02D'
    ),
    'signature': six.b(
        "0f\x021\x00\xa6\xe9\xe5\xff\xec1\x9c\xbfK\x0f\xb9\xd5\xf0\x14\xd1"
        "\xba2\x06Fd\x9e\x18\xbfS(\xa5\xe1\x83\xd9A-\x16\xbf\xa2\xe7h\xa7\xbf"
        "\x04j\xa7\x99\x16\xdc\x83\xfd\x00r\x021\x00\xa4\r\x94\xef\x8f\xdf"
        "\xa9\x1e'\xab\x95\x1cF\xb3tG\x98N\xb1\xa4\x88\x04\xba\xe0Jp\xe2\xc7"
        "\xff\x8fn\x95\xf0\xf0E\x91Uj\xb0E3=\x0e\x1a\xf1'4\xf6"
    ),
    'signature_len': b'\x00h'
}
VALUES['updated_encryption_context'] = copy.deepcopy(VALUES['encryption_context'])
VALUES['updated_encryption_context']['aws-crypto-public-key'] = VALUES['encoded_curve_point']
VALUES['single_block_base'] = VALUES['final_frame_base']
VALUES['serialized_single_block_start'] = b''.join([
    VALUES['final_frame_base'].iv,
    VALUES['ciphertext_len_single_block']
])
VALUES['serialized_single_block_close'] = VALUES['final_frame_base'].tag
VALUES['serialized_single_block'] = b''.join([
    VALUES['serialized_single_block_start'],
    VALUES['final_frame_base'].ciphertext,
    VALUES['serialized_single_block_close']
])
VALUES['frame_base'] = EncryptedData(
    iv=VALUES['final_frame_base'].iv,
    ciphertext=VALUES['final_frame_base'].ciphertext[:VALUES['small_frame_length']],
    tag=VALUES['final_frame_base'].tag
)
VALUES['serialized_frame'] = b''.join([
    b'\x00\x00\x00\x01',
    VALUES['frame_base'].iv,
    VALUES['frame_base'].ciphertext,
    VALUES['frame_base'].tag
])
VALUES['serialized_final_frame'] = b''.join([
    b'\xff\xff\xff\xff',
    b'\x00\x00\x00\x01',
    VALUES['final_frame_base'].iv,
    VALUES['ciphertext_len'],
    VALUES['final_frame_base'].ciphertext,
    VALUES['final_frame_base'].tag
])
VALUES['serialized_footer'] = b''.join([
    VALUES['signature_len'],
    VALUES['signature']
])
VALUES['key_provider'] = MasterKeyInfo(
    'aws-kms',
    VALUES['arn']
)
VALUES['data_key_obj'] = DataKey(
    VALUES['key_provider'],
    VALUES['data_key'],
    VALUES['encrypted_data_key']
)
VALUES['encrypted_data_key_obj'] = EncryptedDataKey(
    VALUES['key_provider'],
    VALUES['encrypted_data_key']
)
VALUES['data_keys'] = [
    VALUES['data_key_obj']
]
VALUES['message_single_block'] = b''.join([
    VALUES['header'],
    VALUES['header_auth'],
    VALUES['body_single_block'],
    VALUES['footer']
])
VALUES['message_single_frame'] = b''.join([
    VALUES['header'],
    VALUES['header_auth'],
    VALUES['body_final_frame'],
    VALUES['footer']
])
VALUES['message_multi_frame'] = b''.join([
    VALUES['header'],
    VALUES['header_auth'],
    VALUES['body_frame'],
    VALUES['body_frame'],
    VALUES['body_final_frame'],
    VALUES['footer']
])
VALUES['message_truncated_frames'] = b''.join([
    VALUES['header'],
    VALUES['header_auth'],
    VALUES['body_frame'],
    VALUES['body_frame'],
    VALUES['footer']
])
VALUES['deserialized_header_block_no_signature'] = MessageHeader(
    version=SerializationVersion.V1,
    type=ObjectType.CUSTOMER_AE_DATA,
    algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
    message_id=VALUES['message_id'],
    encryption_context=VALUES['encryption_context'],
    encrypted_data_keys=set([EncryptedDataKey(
        key_provider=VALUES['data_keys'][0].key_provider,
        encrypted_data_key=VALUES['data_keys'][0].encrypted_data_key
    )]),
    content_type=ContentType.NO_FRAMING,
    content_aad_length=0,
    header_iv_length=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384.iv_len,
    frame_length=0
)
VALUES['deserialized_header_block'] = MessageHeader(
    version=SerializationVersion.V1,
    type=ObjectType.CUSTOMER_AE_DATA,
    algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
    message_id=VALUES['message_id'],
    encryption_context=VALUES['updated_encryption_context'],
    encrypted_data_keys=set([EncryptedDataKey(
        key_provider=VALUES['data_keys'][0].key_provider,
        encrypted_data_key=VALUES['data_keys'][0].encrypted_data_key
    )]),
    content_type=ContentType.NO_FRAMING,
    content_aad_length=0,
    header_iv_length=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384.iv_len,
    frame_length=0
)
mock_content_type = MagicMock()
mock_content_type.__class__ = ContentType
VALUES['deserialized_header_unknown_content_type'] = MessageHeader(
    version=SerializationVersion.V1,
    type=ObjectType.CUSTOMER_AE_DATA,
    algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
    message_id=VALUES['message_id'],
    encryption_context=VALUES['updated_encryption_context'],
    encrypted_data_keys=set([EncryptedDataKey(
        key_provider=VALUES['data_keys'][0].key_provider,
        encrypted_data_key=VALUES['data_keys'][0].encrypted_data_key
    )]),
    content_type=mock_content_type,
    content_aad_length=0,
    header_iv_length=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384.iv_len,
    frame_length=VALUES['small_frame_length']
)
VALUES['deserialized_header_frame'] = MessageHeader(
    version=SerializationVersion.V1,
    type=ObjectType.CUSTOMER_AE_DATA,
    algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
    message_id=VALUES['message_id'],
    encryption_context=VALUES['updated_encryption_context'],
    encrypted_data_keys=set([EncryptedDataKey(
        key_provider=VALUES['data_keys'][0].key_provider,
        encrypted_data_key=VALUES['data_keys'][0].encrypted_data_key
    )]),
    content_type=ContentType.FRAMED_DATA,
    content_aad_length=0,
    header_iv_length=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384.iv_len,
    frame_length=VALUES['small_frame_length']
)
VALUES['deserialized_header_small_frame'] = MessageHeader(
    version=SerializationVersion.V1,
    type=ObjectType.CUSTOMER_AE_DATA,
    algorithm=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384,
    message_id=VALUES['message_id'],
    encryption_context=VALUES['updated_encryption_context'],
    encrypted_data_keys=set([EncryptedDataKey(
        key_provider=VALUES['data_keys'][0].key_provider,
        encrypted_data_key=VALUES['data_keys'][0].encrypted_data_key
    )]),
    content_type=ContentType.FRAMED_DATA,
    content_aad_length=0,
    header_iv_length=Algorithm.AES_256_GCM_IV12_TAG16_HKDF_SHA384_ECDSA_P384.iv_len,
    frame_length=32
)
VALUES['deserialized_header_auth_block'] = MessageHeaderAuthentication(
    iv=VALUES['header_auth_base'].iv,
    tag=VALUES['header_auth_base'].tag
)
VALUES['deserialized_body_block'] = MessageNoFrameBody(
    iv=VALUES['single_block_base'].iv,
    ciphertext=VALUES['single_block_base'].ciphertext,
    tag=VALUES['single_block_base'].tag
)
VALUES['deserialized_footer'] = MessageFooter(VALUES['signature'])
VALUES['deserialized_body_final_frame_single'] = MessageFrameBody(
    iv=VALUES['final_frame_base'].iv,
    ciphertext=VALUES['final_frame_base'].ciphertext,
    tag=VALUES['final_frame_base'].tag,
    sequence_number=1,
    final_frame=True
)
VALUES['deserialized_body_frame_1'] = MessageFrameBody(
    iv=VALUES['frame_base'].iv,
    ciphertext=VALUES['frame_base'].ciphertext,
    tag=VALUES['frame_base'].tag,
    sequence_number=1,
    final_frame=False
)
VALUES['deserialized_body_frame_2'] = MessageFrameBody(
    iv=VALUES['frame_base'].iv,
    ciphertext=VALUES['frame_base'].ciphertext,
    tag=VALUES['frame_base'].tag,
    sequence_number=2,
    final_frame=False
)
VALUES['deserialized_body_final_frame_3'] = MessageFrameBody(
    iv=VALUES['final_frame_base'].iv,
    ciphertext=VALUES['final_frame_base'].ciphertext,
    tag=VALUES['final_frame_base'].tag,
    sequence_number=3,
    final_frame=True
)
VALUES['serialized_header_invalid_object_type'] = bytearray(VALUES['serialized_header'])
struct.pack_into('>B', VALUES['serialized_header_invalid_object_type'], 1, 0)
VALUES['serialized_header_invalid_object_type'] = array_byte(VALUES['serialized_header_invalid_object_type'])
VALUES['serialized_header_invalid_version'] = bytearray(VALUES['serialized_header'])
struct.pack_into('>B', VALUES['serialized_header_invalid_version'], 0, 0)
VALUES['serialized_header_invalid_version'] = array_byte(VALUES['serialized_header_invalid_version'])
VALUES['serialized_header_invalid_algorithm'] = VALUES['serialized_header']
VALUES['serialized_header_disallowed_algorithm'] = VALUES['serialized_header']
VALUES['serialized_header_unknown_content_type'] = bytearray(VALUES['serialized_header'])
header_value_position = 22
header_value_position += len(VALUES['serialized_encryption_context'])
header_value_position += 2
header_value_position += len(VALUES['serialized_encrypted_data_key'])
struct.pack_into('>B', VALUES['serialized_header_unknown_content_type'], header_value_position, 0)
VALUES['serialized_header_unknown_content_type'] = array_byte(VALUES['serialized_header_unknown_content_type'])
header_value_position += 1
VALUES['serialized_header_bad_reserved_space'] = bytearray(VALUES['serialized_header'])
struct.pack_into('>I', VALUES['serialized_header_bad_reserved_space'], header_value_position, 5)
VALUES['serialized_header_bad_reserved_space'] = array_byte(VALUES['serialized_header_bad_reserved_space'])
header_value_position += 4
VALUES['serialized_header_bad_iv_len'] = bytearray(VALUES['serialized_header'])
struct.pack_into('>B', VALUES['serialized_header_bad_iv_len'], header_value_position, 0)
VALUES['serialized_header_bad_iv_len'] = array_byte(VALUES['serialized_header_bad_iv_len'])
VALUES['encryption_context_too_large'] = {
    str(i): str(i)
    for i in
    range(aws_encryption_sdk.internal.defaults.MAX_BYTE_ARRAY_SIZE)
}
VALUES['encryption_context_too_many_elements'] = copy.copy(VALUES['encryption_context_too_large'])
VALUES['encryption_context_too_many_elements'][str(
    aws_encryption_sdk.internal.defaults.MAX_BYTE_ARRAY_SIZE
)] = str(aws_encryption_sdk.internal.defaults.MAX_BYTE_ARRAY_SIZE)
VALUES['wrapped_keys'] = {
    'raw': {
        'provider_id': b'asoghis',
        'key_info': b'asdfhasiufhiasuhviawurhgiuawrhefiuawhf',
        'iv': b'asd3efrjnmvs',
        'ciphertext': b'asodfhiaufghiuhfishdfoisdfasodfjoasijdfoiadoifsaodfj',
        'tag': b'dvboisdjgfosijeo'
    }
}
VALUES['wrapped_keys']['serialized'] = {
    'key_info': b'asdfhasiufhiasuhviawurhgiuawrhefiuawhf\x00\x00\x00\x80\x00\x00\x00\x0casd3efrjnmvs',
    'key_info_symmetric_nonmatch': b'asdfhaasuhviawurhgiuawrhefiuawhf\x00\x00\x00\x80\x00\x00\x00\x0casd3efrjnmvs',
    'key_info_prefix': b'asdfhasiufhiasuhviawurhgiuawrhefiuawhf\x00\x00\x00\x80\x00\x00\x00\x0c',
    'key_ciphertext': VALUES['wrapped_keys']['raw']['ciphertext'] + VALUES['wrapped_keys']['raw']['tag'],
    'key_info_bad_iv_len': b'asdfhasiufhiasuhviawurhgiuawrhefiuawhf\x00\x00\x00\x80\x00\x00\x10\x0casd3efrjnmvs',
    'key_info_incomplete': b'asdfhasiufhiasuhviawurhgiuawrhefiuawhf\x00\x00\x00\x80\x00\x00',
    'key_info_incomplete_iv': b'asdfhasiufhiasuhviawurhgiuawrhefiuawhf\x00\x00\x00\x80\x00\x00\x00\x0casd3efrjnm',
    'key_ciphertext_incomplete_tag': b'',
    'key_ciphertext_incomplete_tag2': b'sdfs'
}

VALUES['wrapped_keys']['structures'] = {
    'wrapped_encrypted_data': EncryptedData(
        iv=VALUES['wrapped_keys']['raw']['iv'],
        ciphertext=VALUES['wrapped_keys']['raw']['ciphertext'],
        tag=VALUES['wrapped_keys']['raw']['tag']
    ),
    'wrapped_encrypted_data_key_asymmetric': EncryptedDataKey(
        key_provider=MasterKeyInfo(
            provider_id=VALUES['wrapped_keys']['raw']['provider_id'],
            key_info=VALUES['wrapped_keys']['raw']['key_info']
        ),
        encrypted_data_key=VALUES['wrapped_keys']['raw']['ciphertext']
    ),
    'wrapped_encrypted_data_key_symmetric': EncryptedDataKey(
        key_provider=MasterKeyInfo(
            provider_id=VALUES['wrapped_keys']['raw']['provider_id'],
            key_info=VALUES['wrapped_keys']['serialized']['key_info']
        ),
        encrypted_data_key=VALUES['wrapped_keys']['serialized']['key_ciphertext']
    ),
    'wrapped_encrypted_data_key_symmetric_bad_iv_len': EncryptedDataKey(
        key_provider=MasterKeyInfo(
            provider_id=VALUES['wrapped_keys']['raw']['provider_id'],
            key_info=VALUES['wrapped_keys']['serialized']['key_info_bad_iv_len']
        ),
        encrypted_data_key=VALUES['wrapped_keys']['serialized']['key_ciphertext']
    ),
    'wrapped_encrypted_data_key_symmetric_bad_tag': EncryptedDataKey(
        key_provider=MasterKeyInfo(
            provider_id=VALUES['wrapped_keys']['raw']['provider_id'],
            key_info=VALUES['wrapped_keys']['serialized']['key_info_bad_iv_len']
        ),
        encrypted_data_key=VALUES['wrapped_keys']['serialized']['key_ciphertext']
    ),
    'wrapped_encrypted_data_key_symmetric_incomplete_info': EncryptedDataKey(
        key_provider=MasterKeyInfo(
            provider_id=VALUES['wrapped_keys']['raw']['provider_id'],
            key_info=VALUES['wrapped_keys']['serialized']['key_info_incomplete']
        ),
        encrypted_data_key=VALUES['wrapped_keys']['serialized']['key_ciphertext']
    ),
    'wrapped_encrypted_data_key_symmetric_incomplete_iv': EncryptedDataKey(
        key_provider=MasterKeyInfo(
            provider_id=VALUES['wrapped_keys']['raw']['provider_id'],
            key_info=VALUES['wrapped_keys']['serialized']['key_info_incomplete_iv']
        ),
        encrypted_data_key=VALUES['wrapped_keys']['serialized']['key_ciphertext']
    ),
    'wrapped_encrypted_data_key_symmetric_incomplete_tag': EncryptedDataKey(
        key_provider=MasterKeyInfo(
            provider_id=VALUES['wrapped_keys']['raw']['provider_id'],
            key_info=VALUES['wrapped_keys']['serialized']['key_info']
        ),
        encrypted_data_key=VALUES['wrapped_keys']['serialized']['key_ciphertext_incomplete_tag']
    ),
    'wrapped_encrypted_data_key_symmetric_incomplete_tag2': EncryptedDataKey(
        key_provider=MasterKeyInfo(
            provider_id=VALUES['wrapped_keys']['raw']['provider_id'],
            key_info=VALUES['wrapped_keys']['serialized']['key_info']
        ),
        encrypted_data_key=VALUES['wrapped_keys']['serialized']['key_ciphertext_incomplete_tag2']
    )
}
