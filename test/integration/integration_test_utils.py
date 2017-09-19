# Copyright 2017 Amazon.com, Inc. or its affiliates. All Rights Reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License"). You
# may not use this file except in compliance with the License. A copy of
# the License is located at
#
# http://aws.amazon.com/apache2.0/
#
# or in the "license" file accompanying this file. This file is
# distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF
# ANY KIND, either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
"""Utility functions to handle configuration, credentials setup, and test skip
decision making for integration tests."""
import os

import botocore.session
from six.moves.configparser import ConfigParser, NoOptionError  # six.moves confuses pylint: disable=import-error
from aws_encryption_sdk.key_providers.kms import KMSMasterKeyProvider

SKIP_MESSAGE = 'Skipping tests due to blocking environment variable'


def skip_tests():
    blocker_var_name = 'AWS_ENCRYPTION_SDK_PYTHON_INTEGRATION_TEST_CONTROL'
    blocker_val = os.environ.get(blocker_var_name, None)
    if blocker_val != 'RUN':
        return True
    return False


def read_test_config():
    """Reads the test_values config file."""
    config = ConfigParser()
    config_file = os.sep.join([os.path.dirname(__file__), 'test_values.conf'])
    config_readme = os.sep.join([os.path.dirname(__file__), 'README'])
    if not os.path.isfile(config_file):
        raise OSError('Integration test config file missing.  See setup instructions in {}'.format(config_readme))
    config.read(config_file)
    return config


def get_cmk_arn(config):
    """Retrieves the target CMK ARN from the received config."""
    return config.get('TestKMSThickClientIntegration', 'cmk_arn')


def setup_botocore_session(config):
    """Configures a botocore session based on the received config."""
    aws_params = {}
    for key in ['aws_access_key_id', 'aws_secret_access_key', 'aws_session_token']:
        try:
            aws_params[key] = config.get('TestKMSThickClientIntegration', key)
        except NoOptionError:
            pass
    botocore_session = botocore.session.Session()
    if aws_params:
        botocore_session.set_credentials(
            access_key=aws_params['aws_access_key_id'],
            secret_key=aws_params['aws_secret_access_key'],
            token=aws_params['aws_session_token']
        )
    return botocore_session


def setup_kms_master_key_provider():
    """Reads the test_values config file and builds the requested KMS Master Key Provider."""
    config = read_test_config()
    cmk_arn = get_cmk_arn(config)
    botocore_session = setup_botocore_session(config)
    kms_master_key_provider = KMSMasterKeyProvider(botocore_session=botocore_session)
    kms_master_key_provider.add_master_key(cmk_arn)
    return kms_master_key_provider
