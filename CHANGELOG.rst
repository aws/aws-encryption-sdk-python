*********
Changelog
*********

3.1.1 -- 2022-06-20
===================

Maintenance
-----------
* Replace deprecated cryptography ``verify_interface`` with ``isinstance``
  `#467 <https://github.com/aws/aws-encryption-sdk-python/pull/467>`_

3.1.0 -- 2021-11-10
===================

Deprecation
-----------
The AWS Encryption SDK for Python no longer supports Python 3.5
as of version 3.1; only Python 3.6+ is supported. Customers using
Python 3.5 can still use the 2.x line of the AWS Encryption SDK for Python,
which will continue to receive security updates, in accordance
with our `Support Policy <https://github.com/aws/aws-encryption-sdk-python/blob/master/SUPPORT_POLICY.rst>`__.

Feature
-----------
* Warn on Deprecated Python usage
  `#368 <https://github.com/aws/aws-encryption-sdk-python/pull/368>`_
* Add Python 3.10 to CI
* Remove Python 3.5 from testing


3.0.0 -- 2021-07-01
===================

Deprecation
-----------
The AWS Encryption SDK for Python no longer supports Python 2 or Python 3.4
as of major version 3.x; only Python 3.5+ is supported. Customers using Python 2
or Python 3.4 can still use the 2.x line of the AWS Encryption SDK for Python,
which will continue to receive security updates for the next 12 months, in accordance
with our `Support Policy <https://github.com/aws/aws-encryption-sdk-python/blob/master/SUPPORT_POLICY.rst>`__.

Maintenance
-----------
* Move away from deprecated cryptography ``int_from_bytes``
  `#355 <https://github.com/aws/aws-encryption-sdk-python/pull/355>`_


2.4.0 -- 2021-07-01
===================

Deprecation Announcement
------------------------
The AWS Encryption SDK for Python is discontinuing support for Python 2. Future major versions of this library
will drop support for Python 2 and begin to adopt changes that are known to break Python 2.

Support for Python 3.4 will be removed at the same time. Moving forward, we will support Python 3.5+.

Security updates will still be available for the Encryption SDK 2.x line for the next 12 months, in accordance with our `Support Policy <https://github.com/aws/aws-encryption-sdk-python/blob/master/SUPPORT_POLICY.rst>`__.


2.3.0 -- 2021-06-16
===================

Features
--------
* AWS KMS multi-Region Key support

  Added new the master key MRKAwareKMSMasterKey
  and the new master key providers MRKAwareStrictAwsKmsMasterKeyProvider
  and MRKAwareDiscoveryAwsKmsMasterKeyProvider
  that support AWS KMS multi-Region Keys.

  See https://docs.aws.amazon.com/kms/latest/developerguide/multi-region-keys-overview.html
  for more details about AWS KMS multi-Region Keys.
  See https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/configure.html#config-mrks
  for more details about how the AWS Encryption SDK interoperates
  with AWS KMS multi-Region keys.

2.2.0 -- 2021-05-27
===================

Features
--------
* Improvements to the message decryption process

  See https://github.com/aws/aws-encryption-sdk-python/security/advisories/GHSA-x5h4-9gqw-942j.

2.1.0 -- 2020-04-20
===================

Maintenance
-----------
* New minimum cryptography dependency 2.5.0 since we're using newer byte type checking
  `#308 <https://github.com/aws/aws-encryption-sdk-python/pull/308>`_
* New minimum boto dependency 1.10.0 to ensure KMS Decrypt APIs know about the KeyId parameter
  `#317 <https://github.com/aws/aws-encryption-sdk-python/pull/317>`_
* Add python 3.8 and 3.9 to CI and update setup.py to clarify we support them
  `#329 <https://github.com/aws/aws-encryption-sdk-python/pull/329>`_
* Update decrypt oracle and test vector handlers with 2.0.0 changes
  `#303 <https://github.com/aws/aws-encryption-sdk-python/pull/303>`_
* Added a number of CodeBuild specs to support integration tests and release processes

2.0.0 -- 2020-09-24
===================

Features
--------
* Updates to the AWS Encryption SDK. 73cce71

Breaking Changes
^^^^^^^^^^^^^^^^
* ``KMSMasterKeyProvider`` is removed. Customers must use ``StrictAwsKmsMasterKeyProvider``
  with explicit key ids, or ``DiscoveryAwsKmsMasterKeyProvider`` to allow decryption of any
  ciphertext to which the application has access.
* The ``encrypt``, ``decrypt``, and ``stream`` methods in the ``aws_encryption_sdk`` module
  are removed, replaced by identically named methods on the new ``EncryptionSDKClient`` class.
* Key committing algorithm suites are now default.

See `Migration guide <https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/migration.html>`_
for more details.

1.7.0 -- 2020-09-24
===================

Features
--------
* Updates to the AWS Encryption SDK. ef90351

Deprecations
^^^^^^^^^^^^
* ``KMSMasterKeyProvider`` is deprecated. Customers should move to ``StrictAwsKmsMasterKeyProvider``
  with explicit key ids, or ``DiscoveryAwsKmsMasterKeyProvider`` to allow decryption of any
  ciphertext to which the application has access.
* The ``encrypt``, ``decrypt``, and ``stream`` methods in the ``aws_encryption_sdk`` module are
  deprecated. Customers should move to the identically named methods on the new ``EncryptionSDKClient``
  class.

See `Migration guide <https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/migration.html>`_
for more details.

1.4.1 -- 2019-09-20
===================

Bugfixes
--------

* Fix region configuration override in botocore sessions.
  `#190 <https://github.com/aws/aws-encryption-sdk-python/issues/190>`_
  `#193 <https://github.com/aws/aws-encryption-sdk-python/pull/193>`_

Minor
-----

* Caching CMM must require that max age configuration value is greater than 0.
  `#147 <https://github.com/aws/aws-encryption-sdk-python/issues/147>`_
  `#172 <https://github.com/aws/aws-encryption-sdk-python/pull/172>`_

1.4.0 -- 2019-05-23
===================

Minor
-----

* Remove dependence on all ``source_stream`` APIs except for ``read()``.
  `#103 <https://github.com/aws/aws-encryption-sdk-python/issues/103>`_

Potentially Backwards Incompatible
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^

* Encryption streams no longer close the ``source_stream`` when they themselves close.
  If you are using context managers for all of your stream handling,
  this change will not affect you.
  However, if you have been relying on the ``StreamDecryptor``
  or ``StreamEncryptor`` to close your ``source_stream`` for you,
  you will now need to close those streams yourself.
* ``StreamDecryptor.body_start`` and ``StreamDecryptor.body_end``,
  deprecated in a prior release,
  have now been removed.

Maintenance
-----------

* Move all remaining ``unittest`` tests to ``pytest``.
  `#99 <https://github.com/aws/aws-encryption-sdk-python/issues/99>`_


Bugfixes
--------

* Fix ``MasterKeyprovider.decrypt_data_key_from_list`` error handling.
  `#150 <https://github.com/aws/aws-encryption-sdk-python/issues/150>`_


1.3.8 -- 2018-11-15
===================

Bugfixes
--------

* Remove debug logging that may contain input data when encrypting non-default unframed messages.
  `#105 <https://github.com/aws/aws-encryption-sdk-python/pull/105>`_

Minor
-----

* Add support to remove clients from :class:`KMSMasterKeyProvider` client cache if they fail to connect to endpoint.
  `#86 <https://github.com/aws/aws-encryption-sdk-python/pull/86>`_
* Add support for SHA384 and SHA512 for use with RSA OAEP wrapping algorithms.
  `#56 <https://github.com/aws/aws-encryption-sdk-python/issues/56>`_
* Fix ``streaming_client`` classes to properly interpret short reads in source streams.
  `#24 <https://github.com/aws/aws-encryption-sdk-python/issues/24>`_

1.3.7 -- 2018-09-20
===================

Bugfixes
--------

* Fix KMSMasterKeyProvider to determine the default region before trying to create the requested master keys.
  `#83 <https://github.com/aws/aws-encryption-sdk-python/issues/83>`_


1.3.6 -- 2018-09-04
===================

Bugfixes
--------
* :class:`StreamEncryptor` and :class:`StreamDecryptor` should always report as readable if they are open.
  `#73 <https://github.com/aws/aws-encryption-sdk-python/issues/73>`_
* Allow duck-typing of source streams.
  `#75 <https://github.com/aws/aws-encryption-sdk-python/issues/75>`_

1.3.5 -- 2018-08-01
===================
* Move the ``aws-encryption-sdk-python`` repository from ``awslabs`` to ``aws``.

1.3.4 -- 2018-04-12
===================

Bugfixes
--------
* AWS KMS master key/provider user agent extension fixed.
  `#47 <https://github.com/aws/aws-encryption-sdk-python/pull/47>`_

Maintenance
-----------
* New minimum pytest version 3.3.1 to avoid bugs in 3.3.0
  `#32 <https://github.com/aws/aws-encryption-sdk-python/issues/32>`_
* New minimum attrs version 17.4.0 to allow use of ``converter`` rather than ``convert``
  `#39 <https://github.com/aws/aws-encryption-sdk-python/issues/39>`_
* Algorithm Suites are modeled as collections of sub-suites now
  `#36 <https://github.com/aws/aws-encryption-sdk-python/pull/36>`_
* Selecting test suites is more sane now, with pytest markers.
  `#41 <https://github.com/aws/aws-encryption-sdk-python/pull/41>`_

1.3.3 -- 2017-12-05
===================

Bugfixes
--------
* Remove use of attrs functionality deprecated in 17.3.0
  `#29 <https://github.com/aws/aws-encryption-sdk-python/issues/29>`_

Maintenance
-----------
* Blacklisted pytest 3.3.0
  `#32 <https://github.com/aws/aws-encryption-sdk-python/issues/32>`_
  `pytest-dev/pytest#2957 <https://github.com/pytest-dev/pytest/issues/2957>`_

1.3.2 -- 2017-09-28
===================
* Addressed `issue #13 <https://github.com/aws/aws-encryption-sdk-python/issues/13>`_
  to properly handle non-seekable source streams.

1.3.1 -- 2017-09-12
===================

Reorganization
--------------
* Moved source into ``src``.
* Moved examples into ``examples``.
* Broke out ``internal.crypto`` into smaller, feature-oriented, modules.

Tooling
-------
* Added `tox`_ configuration to support automation and development tooling.
* Added `pylint`_, `flake8`_, and `doc8`_ configuration to enforce style rules.

Maintenance
-----------
* Updated ``internal.crypto.authentication.Verifier`` to use ``Prehashed``.
* Addressed `docstring issue #7 <https://github.com/aws/aws-encryption-sdk-python/issues/7>`_.
* Addressed `docstring issue #8 <https://github.com/aws/aws-encryption-sdk-python/issues/8>`_.
* Addressed `logging issue #10 <https://github.com/aws/aws-encryption-sdk-python/issues/10>`_.
* Addressed assorted linting issues to bring source, tests, examples, and docs up to configured
  linting standards.

1.3.0 -- 2017-08-04
===================

Major
-----
* Added cryptographic materials managers as a concept
* Added data key caching
* Moved to deterministic IV generation

Minor
-----
* Added changelog
* Fixed attrs usage to provide consistent behavior with 16.3.0 and 17.x
* Fixed performance bug which caused KDF calculations to be performed too frequently
* Removed ``line_length`` as a configurable parameter of ``EncryptingStream`` and
  ``DecryptingStream`` objects to simplify class APIs after it was found in further
  testing to have no measurable impact on performance
* Added deterministic length eliptic curve signature generation
* Added support for calculating ciphertext message length from header
* Migrated README from md to rst

1.2.2 -- 2017-05-23
===================
* Fixed ``attrs`` version to 16.3.0 to avoid `breaking changes in attrs 17.1.0`_

1.2.0 -- 2017-03-21
===================
* Initial public release

.. _breaking changes in attrs 17.1.0: https://attrs.readthedocs.io/en/stable/changelog.html
.. _tox: https://tox.readthedocs.io/en/latest/
.. _pylint: https://www.pylint.org/
.. _flake8: http://flake8.pycqa.org/en/latest/
.. _doc8: https://launchpad.net/doc8
