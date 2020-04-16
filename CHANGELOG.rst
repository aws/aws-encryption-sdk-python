*********
Changelog
*********

1.5.0 -- 2020-xx-xx
===================

Major Features
--------------

* Add `keyrings`_.
* Change one-step APIs to return a :class:`CryptoResult` rather than a tuple.

    * Modified APIs: ``aws_encryption_sdk.encrypt`` and ``aws_encryption_sdk.decrypt``.

.. note::

    For backwards compatibility,
    :class:`CryptoResult` also unpacks like a 2-member tuple.
    This allows for backwards compatibility with the previous outputs
    so this change should not break any existing consumers
    unless you are specifically relying on the output being an instance of :class:`tuple`.

Deprecations
------------

* Deprecate master key providers in favor of keyrings.

    * We still support using master key providers and are not removing them yet.
      When we decide to remove them,
      we will communicate that as defined in our versioning policy.

* Deprecate support for Python 3.4.

    * This does not mean that this library will no longer work or install with 3.4,
      but we are no longer testing against or advertising support for 3.4.

Documentation
-------------

* Added new examples demonstrating how to use
  APIs, keyrings, cryptographic materials managers, and master key providers.
  `#221 <https://github.com/aws/aws-encryption-sdk-python/pull/221>`_
  `#236 <https://github.com/aws/aws-encryption-sdk-python/pull/236>`_
  `#239 <https://github.com/aws/aws-encryption-sdk-python/pull/239>`_

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
.. _keyrings: https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/choose-keyring.html
