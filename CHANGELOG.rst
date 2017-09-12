*********
Changelog
*********

1.3.1
=====

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
* Addressed `docstring issue #7 https://github.com/awslabs/aws-encryption-sdk-python/issues/7`_.
* Addressed `docstring issue #8 https://github.com/awslabs/aws-encryption-sdk-python/issues/8`_.
* Addressed `logging issue #10 https://github.com/awslabs/aws-encryption-sdk-python/issues/10`_.
* Addressed assorted linting issues to bring source, tests, examples, and docs up to configured
   linting standards.

1.3.0
=====

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

1.2.2
=====
* Fixed ``attrs`` version to 16.3.0 to avoid `breaking changes in attrs 17.1.0`_

1.2.0
=====
* Initial public release

.. _breaking changes in attrs 17.1.0: https://attrs.readthedocs.io/en/stable/changelog.html
.. _tox: https://tox.readthedocs.io/en/latest/
.. _pylint: https://www.pylint.org/
.. _flake8: http://flake8.pycqa.org/en/latest/
.. _doc8: https://launchpad.net/doc8
