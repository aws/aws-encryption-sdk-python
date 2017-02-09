"""Public data structures for aws_encryption_sdk."""
import attr


@attr.s
class EncryptedData(object):
    """Holds encrypted data.

    :param bytes iv: Initialization Vector
    :param bytes ciphertext: Ciphertext
    :param bytes tag: Encryption tag
    """
    iv = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(bytes)))
    ciphertext = attr.ib(validator=attr.validators.instance_of(bytes))
    tag = attr.ib(validator=attr.validators.optional(attr.validators.instance_of(bytes)))


@attr.s
class MessageHeaderAuthentication(object):
    """Deserialized message header authentication

    :param bytes iv: Initialization Vector
    :param bytes tag: Encryption Tag
    """
    iv = attr.ib(validator=attr.validators.instance_of(bytes))
    tag = attr.ib(validator=attr.validators.instance_of(bytes))


@attr.s
class MessageFrameBody(object):
    """Deserialized message frame

    :param bytes iv: Initialization Vector
    :param bytes ciphertext: Ciphertext
    :param bytes tag: Encryption Tag
    :param int sequence_number: Frame sequence number
    :param bool final_frame: Identifies final frames
    """
    iv = attr.ib(validator=attr.validators.instance_of(bytes))
    ciphertext = attr.ib(validator=attr.validators.instance_of(bytes))
    tag = attr.ib(validator=attr.validators.instance_of(bytes))
    sequence_number = attr.ib(validator=attr.validators.instance_of(int))
    final_frame = attr.ib(validator=attr.validators.instance_of(bool))


@attr.s
class MessageNoFrameBody(object):
    """Deserialized message body with no framing

    :param bytes iv: Initialization Vector
    :param bytes ciphertext: Ciphertext
    :param bytes tag: Encryption Tag
    """
    iv = attr.ib(validator=attr.validators.instance_of(bytes))
    ciphertext = attr.ib(validator=attr.validators.instance_of(bytes))
    tag = attr.ib(validator=attr.validators.instance_of(bytes))
    sequence_number = 1
    final_frame = True  # Never used, but set here to provide a consistent API with MessageFrameBody


@attr.s
class MessageFooter(object):
    """Deserialized message footer

    :param bytes signature: Message signature
    """
    signature = attr.ib(validator=attr.validators.instance_of(bytes))
