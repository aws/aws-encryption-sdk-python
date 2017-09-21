************************************
aws-encryption-sdk Integration Tests
************************************

In order to run these integration tests successfully, these things which must be configured.

#. Ensure that AWS credentials are available in one of the `automatically discoverable credential locations`_.
#. Set environment variable ``AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_KEY_ID`` to valid
   `AWS KMS key id`_ to use for integration tests.
#. Set environment variable ``AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_CONTROL`` to ``RUN``.

.. _automatically discoverable credential locations: http://boto3.readthedocs.io/en/latest/guide/configuration.html
.. _AWS KMS key id: http://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html
