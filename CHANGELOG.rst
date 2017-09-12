*********
Changelog
*********

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
