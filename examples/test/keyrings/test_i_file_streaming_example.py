# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Test suite for the file streaming keyring example."""
import os

import pytest

from ...src.keyrings.file_streaming_example import encrypt_and_decrypt_with_keyring

pytestmark = [pytest.mark.examples]


def test_encrypt_and_decrypt_with_keyring():
    """Test function for encrypt and decrypt for file streaming example using Raw AES keyring."""
    test_keyrings_directory = 'test_keyrings'
    if not os.path.exists(test_keyrings_directory):
        os.makedirs(test_keyrings_directory)

    # Define the filename of the plaintext data.
    plaintext_filename = test_keyrings_directory + '/my-secret-data.dat'

    # Define the plaintext data to be encrypted and decrypted.
    plaintext_data = '''Lorem ipsum dolor sit amet, consectetur adipiscing elit.
Praesent non feugiat leo. Aenean iaculis tellus ut velit consectetur,
quis convallis orci eleifend. Sed eu dictum sapien. Nulla facilisi. Suspendisse potenti.
Proin vehicula vehicula maximus. Donec varius et elit vel rutrum. Nulla lacinia neque turpis
quis consequat orci pharetra et. Etiam consequat ullamcorper mauris. Vivamus molestie mollis
mauris a gravida. Curabitur sed bibendum nisl. Cras varius tortor non erat sodales, quis congu
tellus laoreet. Etiam fermentum purus eu diam sagittis, vitae commodo est vehicula.
Nulla feugiat viverra orci vel interdum. Quisque pulvinar elit eget nulla facilisis varius.
Mauris at suscipit sem. Aliquam in purus ut velit fringilla volutpat id non mi.
Curabitur quis nunc eleifend, ornare lectus non, fringilla quam. Nam maximus volutpat placerat.
Nulla ullamcorper lorem velit, nec sagittis ex tristique posuere. Aliquam fringilla magna commod
libero faucibus tempor. Vestibulum non ligula tincidunt, finibus sapien in, sollicitudin
ex. Pellentesque congue laoreet mi in condimentum. Cras convallis nisi ac nunc tincidunt
venenatis. Suspendisse urna elit, cursus eu lacus a, aliquet porttitor mi.
Nulla vel congue nibh, sed condimentum dui. Ut ante ligula, blandit eu finibus nec,
scelerisque quis eros. Maecenas gravida odio eget nibh dictum, dictum varius lacus interdum.
Integer quis nulla vulputate, rhoncus diam vitae, mollis mauris. Sed ut porttitor dolor.
Fusce ut justo a ex bibendum imperdiet nec sit amet magna. Sed ullamcorper luctus augue,
tempor viverra elit interdum sed. Cras sit amet arcu eu turpis molestie sollicitudin.
Curabitur fermentum varius nibh, ut aliquet nisi. Aliquam id tempus tellus.
Nulla porttitor nulla at nibh interdum, quis sollicitudin erat egestas.
Ut blandit mauris quis efficitur efficitur. Morbi neque sapien, posuere ut aliquam eget,
aliquam at velit. Morbi sit amet rhoncus felis, et hendrerit sem. Nulla porta dictum ligula
eget iaculis. Cras lacinia ligula quis risus ultrices, sed consectetur metus imperdiet.
Nullam id enim vestibulum nibh ultricies auctor. Morbi neque lacus, faucibus vitae commodo quis,
malesuada sed velit.'''

    # Write plaintext data to file
    with open(plaintext_filename, "w", encoding="utf-8") as f:
        f.write(plaintext_data)

    # Define the filename of the encrypted data.
    ciphertext_filename = test_keyrings_directory + '/my-encrypted-data.ct'

    # Define the filename of the decrypted data.
    decrypted_filename = test_keyrings_directory + '/my-decrypted-data.dat'

    encrypt_and_decrypt_with_keyring(plaintext_filename,
                                     ciphertext_filename,
                                     decrypted_filename)
