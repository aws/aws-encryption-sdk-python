************************************
aws-encryption-sdk Integration Tests
************************************

In order to run these integration tests successfully, these things must be configured.

#. Ensure that AWS credentials are available in one of the `automatically discoverable credential locations`_.
#. Set environment the following environment variables to valid
   `AWS KMS key id`_ to use for integration tests:

    * AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_KEY_ID
    * AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_KEY_ID_2

#.  Set environment the following environment variables to two related
    AWS KMS Multi-Region key ids in different regions to use for integration tests:

    * AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_MRK_KEY_ID_1
    * AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_AWS_KMS_MRK_KEY_ID_2

.. _automatically discoverable credential locations: http://boto3.readthedocs.io/en/latest/guide/configuration.html
.. _AWS KMS key id: http://docs.aws.amazon.com/kms/latest/APIReference/API_Encrypt.html
