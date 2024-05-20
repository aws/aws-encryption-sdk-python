# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Base class interface for crypto material managers."""
import abc

import six


@six.add_metaclass(abc.ABCMeta)
class CryptoMaterialsManager(object):
    """Parent interface for crypto material manager classes.

    .. versionadded:: 1.3.0
    """

    @abc.abstractmethod
    def get_encryption_materials(self, request):
        """Provides encryption materials appropriate for the request.

        .. note::
            Must be implemented by specific CryptoMaterialsManager implementations.

        :param request: encryption materials request
        :type request: aws_encryption_sdk.materials_managers.EncryptionMaterialsRequest
        :returns: encryption materials
        :rtype: aws_encryption_sdk.materials_managers.EncryptionMaterials
        """

    @abc.abstractmethod
    def decrypt_materials(self, request):
        """Provides decryption materials appropriate for the request.

        .. note::
            Must be implemented by specific CryptoMaterialsManager implementations.

        :param request: decrypt materials request
        :type request: aws_encryption_sdk.materials_managers.DecryptionMaterialsRequest
        :returns: decryption materials
        :rtype: aws_encryption_sdk.materials_managers.DecryptionMaterials
        """
