*********
Changelog
*********

4.0.0 -- 2024-10-28
===================

Features
--------
* Add support for constructs from the `AWS Cryptographic Material Providers Library (MPL) <https://github.com/aws/aws-cryptographic-material-providers-library>`_.
  The MPL contains new constructs for encrypting and decrypting your data.
  We highly recommend installing the MPL. See `Installing <https://github.com/aws/aws-encryption-sdk-python/tree/master?tab=readme-ov-file#installation>`_ for instructions.

Breaking Changes
^^^^^^^^^^^^^^^^
* Messages constructed with the MPL's Required Encryption Context Cryptographic Materials Manager ("required EC CMM") will not be readable from versions of the ESDK <4.0.0.
  The MPL introduces the "required EC CMM" as a new construct for protecting your data.
  It requires that, for a specified set of encryption context keys, a decryptor must supply the same encryption context pairs that were used when encrypting the message.
  No version of ESDK < 4.0.0 supports reading messages encrypted with the required EC CMM.
  A message that is encrypted with the required EC CMM from the MPL must be decrypted with a CMM from the MPL.

Fixes
-----------
* fix: MKPs attempt to decrypt with remaining keys if a preceding raw RSA key failed to decrypt
  `#707 <https://github.com/aws/aws-encryption-sdk-python/pull/707>`_

3.3.0 -- 2024-05-20
===================

Deprecation
-----------
The AWS Encryption SDK for Python no longer supports Python 3.7
as of version 3.3; only Python 3.8+ is supported.

Fixes
-----------
* fix: Handle errors when decrypting multiple EDKs with raw RSA MKPs (#672 (https://github.com/aws/aws-encryption-sdk-python/pull/672))
* chore: Updated description of decrypt() usage in src/aws_encryption_sdk/__init__.py (#660 (https://github.com/aws/aws-encryption-sdk-python/pull/660))
* fix(CI): removed appveyor.yml (#668 (https://github.com/aws/aws-encryption-sdk-python/pull/668))
* fix(CI): updated ci_test-vector-handler.yaml and ci_tests.yaml (#665 (https://github.com/aws/aws-encryption-sdk-python/pull/665))

Maintenance
-----------
* feat: remove Python3.7 support (#648 (https://github.com/aws/aws-encryption-sdk-python/pull/648))
* chore: Update copyright headers (#677 (https://github.com/aws/aws-encryption-sdk-python/pull/677))
* chore(CFN): Changes for MPL TestVectors (#653 (https://github.com/aws/aws-encryption-sdk-python/pull/653))

3.2.0 -- 2024-03-18
===================

Features
-----------
* test Python 3.12 in CI (#623 (https://github.com/josecorella/aws-encryption-sdk-python/issues/623)) (93a67d8 (https://github.com/josecorella/aws-encryption-sdk-python/commit/93a67d8a3806f560ead950e6d8898e53c4c4f9df))
* update requirements and README (#638 (https://github.com/josecorella/aws-encryption-sdk-python/issues/638)) (bcead77 (https://github.com/josecorella/aws-encryption-sdk-python/commit/bcead776b022566ad8211a08e1a458375b23a356))

Fixes
-----------
* CI for Decrypt Oracle (#558 (https://github.com/josecorella/aws-encryption-sdk-python/issues/558)) (6c6b732 (https://github.com/josecorella/aws-encryption-sdk-python/commit/6c6b732379197e91d2137af9f018f670a1ce500a))
* deprecate python36 from chalice (#539 (https://github.com/josecorella/aws-encryption-sdk-python/issues/539)) (f8aa29f (https://github.com/josecorella/aws-encryption-sdk-python/commit/f8aa29fe98d419dac916846d7ff207685ea95307))
* test: correctly invoke ec.generate_private_key (#585 (https://github.com/josecorella/aws-encryption-sdk-python/issues/585)) (560e714 (https://github.com/josecorella/aws-encryption-sdk-python/commit/560e7143ac7caf98e190b17ce2af97b7eea6be16))
* update pyca range (#507 (https://github.com/josecorella/aws-encryption-sdk-python/issues/507)) (aced92c (https://github.com/josecorella/aws-encryption-sdk-python/commit/aced92c3d87dddf3e0920b9dfad4cedd2473604a))
* Use FORBID_ENCRYPT_ALLOW_DECRYPT policy for decrypt oracle (#538 (https://github.com/josecorella/aws-encryption-sdk-python/issues/538)) (e91838f (https://github.com/josecorella/aws-encryption-sdk-python/commit/e91838f65705867fc95506a4323054bca24e9521))
* wrong formatting python warning (#546 (https://github.com/josecorella/aws-encryption-sdk-python/issues/546)) (9b618d3 (https://github.com/josecorella/aws-encryption-sdk-python/commit/9b618d3a5e517435304a891393fefcbbd89faf65))

Maintenance
-----------
* Add example for custom KMS client config (#440 (https://github.com/josecorella/aws-encryption-sdk-python/issues/440)) (08f305a (https://github.com/josecorella/aws-encryption-sdk-python/commit/08f305a9b7b5fc897d9cafac55fb98f3f2a6fe13))
* Add Thread safety section to README (#562 (https://github.com/josecorella/aws-encryption-sdk-python/issues/562)) (7a07b16 (https://github.com/josecorella/aws-encryption-sdk-python/commit/7a07b161d51900066c131627f9f7330acb926d3b))
* bump deps & document upstream test (#646 (https://github.com/josecorella/aws-encryption-sdk-python/issues/646)) (a93ffe7 (https://github.com/josecorella/aws-encryption-sdk-python/commit/a93ffe7a98f8913040f6a693701ba287dd1570fb))
* CFN: Commit existing CFN (#636 (https://github.com/josecorella/aws-encryption-sdk-python/issues/636)) (c122076 (https://github.com/josecorella/aws-encryption-sdk-python/commit/c12207621d295b335fdfb500c2b02694cc6786d8))
* ci: skip pyenv installation if already exists (#627 (https://github.com/josecorella/aws-encryption-sdk-python/issues/627)) (1006758 (https://github.com/josecorella/aws-encryption-sdk-python/commit/10067581cd3316fbb379929806db6867e4cb0feb))
* deps: bump actions/checkout from 3 to 4 (#607 (https://github.com/josecorella/aws-encryption-sdk-python/issues/607)) (e5c331b (https://github.com/josecorella/aws-encryption-sdk-python/commit/e5c331b68590825b55b5300ffab6dc80fbd20818))
* deps: bump actions/setup-python from 2 to 4.2.0 (#491 (https://github.com/josecorella/aws-encryption-sdk-python/issues/491)) (d064bf8 (https://github.com/josecorella/aws-encryption-sdk-python/commit/d064bf8813d25e1ba4a8cce7269b8ee48acfd79a))
* deps: bump cryptography from 39.0.0 to 39.0.1 in /test (#559 (https://github.com/josecorella/aws-encryption-sdk-python/issues/559)) (6468137 (https://github.com/josecorella/aws-encryption-sdk-python/commit/646813786c6250a525afb67bebc486eda206edd8))
* deps: bump cryptography from 39.0.1 to 41.0.2 in /test (#592 (https://github.com/josecorella/aws-encryption-sdk-python/issues/592)) (3ba8019 (https://github.com/josecorella/aws-encryption-sdk-python/commit/3ba8019681ed95c41bb9448f0c3897d1aecc7559))
* deps: bump cryptography from 41.0.2 to 41.0.6 in /test (#626 (https://github.com/josecorella/aws-encryption-sdk-python/issues/626)) (c67e6bd (https://github.com/josecorella/aws-encryption-sdk-python/commit/c67e6bd471b30e13cc7f1b724ce7d19df2380c22))
* deps: bump dependabot/fetch-metadata from 1.3.0 to 1.3.6 (#549 (https://github.com/josecorella/aws-encryption-sdk-python/issues/549)) (2a6bd9d (https://github.com/josecorella/aws-encryption-sdk-python/commit/2a6bd9d70c779655077985c544df3db6a3518443))
* deps: bump flake8-bugbear in /dev_requirements (#512 (https://github.com/josecorella/aws-encryption-sdk-python/issues/512)) (93f01d6 (https://github.com/josecorella/aws-encryption-sdk-python/commit/93f01d655d6bce704bd8779cc9c4acb5f96b980c))
* deps: bump flake8-docstrings in /dev_requirements (#555 (https://github.com/josecorella/aws-encryption-sdk-python/issues/555)) (bd8f270 (https://github.com/josecorella/aws-encryption-sdk-python/commit/bd8f270c8717e5d4a787d33bcfda8b53bbe7751e))
* deps: bump flake8-print from 4.0.0 to 5.0.0 in /dev_requirements (#554 (https://github.com/josecorella/aws-encryption-sdk-python/issues/554)) (2326531 (https://github.com/josecorella/aws-encryption-sdk-python/commit/232653188558379bceeb884b3f74b56b07560f62))
* deps: bump isort from 5.10.1 to 5.11.4 in /dev_requirements (#551 (https://github.com/josecorella/aws-encryption-sdk-python/issues/551)) (36a0ea2 (https://github.com/josecorella/aws-encryption-sdk-python/commit/36a0ea2199872d6590691b53fbea7aee2236a99e))
* deps: bump pytest from 7.0.1 to 7.2.0 in /dev_requirements (#524 (https://github.com/josecorella/aws-encryption-sdk-python/issues/524)) (af98302 (https://github.com/josecorella/aws-encryption-sdk-python/commit/af983024fdd800e6b2c4ae41cdf1617c982e4916))
* deps: bump pytest from 7.2.0 to 7.2.1 in /dev_requirements (#553 (https://github.com/josecorella/aws-encryption-sdk-python/issues/553)) (48f96d5 (https://github.com/josecorella/aws-encryption-sdk-python/commit/48f96d58eeb712a5faa631ce4f4930d5d23bb649))
* deps: bump pytest-cov from 3.0.0 to 4.0.0 in /dev_requirements (#550 (https://github.com/josecorella/aws-encryption-sdk-python/issues/550)) (6e436e1 (https://github.com/josecorella/aws-encryption-sdk-python/commit/6e436e13ce250759a499c3d9c820384cfc26283c))
* deps: bump readme-renderer from 34.0 to 37.3 in /dev_requirements (#526 (https://github.com/josecorella/aws-encryption-sdk-python/issues/526)) (38aa063 (https://github.com/josecorella/aws-encryption-sdk-python/commit/38aa06309ad8ad709044c86ac6b4951739fbf996))
* deps: bump setuptools from 62.0.0 to 66.1.1 in /dev_requirements (#547 (https://github.com/josecorella/aws-encryption-sdk-python/issues/547)) (04e8c16 (https://github.com/josecorella/aws-encryption-sdk-python/commit/04e8c167273357a9548ff474c527805d8764a661))
* deps: bump sphinx from 4.4.0 to 5.3.0 in /dev_requirements (#523 (https://github.com/josecorella/aws-encryption-sdk-python/issues/523)) (51cb2ce (https://github.com/josecorella/aws-encryption-sdk-python/commit/51cb2ce148bc7e048587b013337f2440b53c1387))
* deps: bump tox from 3.24.5 to 3.27.1 in /dev_requirements (#528 (https://github.com/josecorella/aws-encryption-sdk-python/issues/528)) (e2c834a (https://github.com/josecorella/aws-encryption-sdk-python/commit/e2c834ac5c4a9ca65db2b225e794f7ddf4d89cc4))
* deps: bump urllib3 from 1.26.14 to 1.26.18 in /test (#618 (https://github.com/josecorella/aws-encryption-sdk-python/issues/618)) (bbb2281 (https://github.com/josecorella/aws-encryption-sdk-python/commit/bbb2281ed61f8fc8700e31d9828753531c8e586f))
* deps: bump vulture from 2.3 to 2.6 in /dev_requirements (#533 (https://github.com/josecorella/aws-encryption-sdk-python/issues/533)) (2822364 (https://github.com/josecorella/aws-encryption-sdk-python/commit/28223646b4c48b2508ca46e3084689988abd2d27))
* deps: bump wheel from 0.37.1 to 0.38.4 in /dev_requirements (#536 (https://github.com/josecorella/aws-encryption-sdk-python/issues/536)) (1922650 (https://github.com/josecorella/aws-encryption-sdk-python/commit/19226506ad33f5b964fe6632604425923f6ba8c1))
* drop py3.6 from Oracle & Test Vectors (#529 (https://github.com/josecorella/aws-encryption-sdk-python/issues/529)) (8b6a493 (https://github.com/josecorella/aws-encryption-sdk-python/commit/8b6a49388c85785a22d59430007b7873ac8acf96))
* drop py36 support (#530 (https://github.com/josecorella/aws-encryption-sdk-python/issues/530)) (a753ff8 (https://github.com/josecorella/aws-encryption-sdk-python/commit/a753ff884fe3000881c7d3a2392a0b5d65cfa138))
* release: add api token to prod release process (#503 (https://github.com/josecorella/aws-encryption-sdk-python/issues/503)) (333c85b (https://github.com/josecorella/aws-encryption-sdk-python/commit/333c85b40b8ee20ed6303b9775e7fb9a6c6d2c63))
* release: add api token to staging release process (#502 (https://github.com/josecorella/aws-encryption-sdk-python/issues/502)) (78e43b3 (https://github.com/josecorella/aws-encryption-sdk-python/commit/78e43b38a5b9df9a925084242a230fccf91476f2))
* rm upstream-py27 (#564 (https://github.com/josecorella/aws-encryption-sdk-python/issues/564)) (b378508 (https://github.com/josecorella/aws-encryption-sdk-python/commit/b3785085b7c00fef27a250abf78549d6e7928802))
* SupportPolicy: Mark 1.x & 2.x End-of-Support (#501 (https://github.com/josecorella/aws-encryption-sdk-python/issues/501)) (ca58e5e (https://github.com/josecorella/aws-encryption-sdk-python/commit/ca58e5e0ce373e9ae5132bb5ce95b6886a0a37d3))


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
