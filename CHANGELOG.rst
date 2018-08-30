*********
Changelog
*********

1.3.6 -- 2018-08-xx
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
