************************************
aws-encryption-sdk Integration Tests
************************************

In order to run these integration tests successfully, these things must be configured.

#. Ensure that AWS credentials are available in one of the `automatically discoverable credential locations`_.
#. Set environment variable ``AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_KEY_ID``
   and ``AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_KEY_ID_2`` to valid
   `AWS KMS key id`_ to use for integration tests.
   These should be AWS KMS CMK ARNs in two different regions.
   They will be used for integration tests.

.. _automatically discoverable credential locations: http://boto3.readthedocs.io/en/latest/guide/configuration.html
.. _AWS KMS key id: http://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html
