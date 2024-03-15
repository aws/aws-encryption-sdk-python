AWS Crypto Tools maintains `test/upstream-requirements-py<VERSION>.txt` in our Python products such that 
our Cryptographic Primitive Provider for Python ([pyca/cryptography](https://github.com/pyca/cryptography))
may execute downstream tests against AWS Crypto Tools Python products.
These files allow pyca to install and test the Crypto Tools products.
Additionally, Crypto Tools should maintain a test configuration that can be completed without using any AWS resources.
If Crypto Tools needs to contact pyca about this expectation,
they should cut a issue to the pyca/cryptography repo.
