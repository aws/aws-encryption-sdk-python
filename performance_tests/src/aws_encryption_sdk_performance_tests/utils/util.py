# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Utility functions for AWS Encryption SDK performance tests."""


class PerfTestUtils:
    """Utility functions for AWS Encryption SDK performance tests."""
    DEFAULT_N_ITERS = 100
    DEFAULT_FILE_SIZE = 'small'
    DEFAULT_AES_256_STATIC_KEY = \
        b'_\xcf"\x82\x03\x12\x9d\x00\x8a\xed\xaf\xe4\x80\x1d\x00t\xa6P\xac\xb6\xfe\xc5\xf6/{\xe7\xaaO\x01\x13W\x85'
    DEFAULT_RSA_PUBLIC_KEY = bytes("-----BEGIN PUBLIC KEY-----\n"
                                   + "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAwEkp2yRpTAgZa4MDNxq8"
                                   + "eQ7rkaVw9QTdJr9NFAtjUpM/6UQARJ2aAq8SjzkGk94EqfH6XqMWum/XQDIb5IWy"
                                   + "E2nm4MCHED62mEEbjbDwtLmiWK0giZV3qe1PJ1LRLmeqRvjVHWc0b7QxnkjPCCnf"
                                   + "Mpode5IQY3AZM3unIVFA043oD3ZPRsEch/hl2my2sxBa4PNod2cxw1PLbQVQWvKh"
                                   + "f7ivmhVAKxwacXTb2yIynGljEgZZfkV1hATS9TGgHG2wpeZ9o0M4/JaN+TLgjruv"
                                   + "gaE6vArdndBQcUV/NAOBeDegsfAsic7OC9FD/3MFgLo2g72WYY3BuCNMDj8L3lWK"
                                   + "+vyC/S66cIvp1P2GzsccHSfcK0MC09ojnCbKF6D7tv5pIKhtvZRC7xcNv1ctS/fb"
                                   + "UbMy4tH+8iwvJlTRGZuuEYDwoBFowNS1oHxeO1PI1im93inAYt5GhkMuaZKLaY64"
                                   + "xe51LJNcP1ovAhHaMG8UGfeCiNBRjGEP3pMG8sgLyw9k3gqMVzX4MUfPlXQh503k"
                                   + "3bVE/eymdsdZ1kAlMLR26IoQ6muAHtn0cy00RjRPy0hIQ2Z+ACog0ge91AyWgXjn"
                                   + "0WYI3AUOzVRZAoqS7ymf2zQfyb3WVYBMfyYT9IhUZlAWq8uzEkoFs47r0LKrv6DA"
                                   + "LX8MCeTVUP6ELg4Inaz8UDECAwEAAQ=="
                                   + "\n-----END PUBLIC KEY-----", 'utf-8')

    DEFAULT_RSA_PRIVATE_KEY = bytes("-----BEGIN RSA PRIVATE KEY-----\n"
                                    + "MIIJJwIBAAKCAgEAwEkp2yRpTAgZa4MDNxq8eQ7rkaVw9QTdJr9NFAtjUpM/6UQA"
                                    + "RJ2aAq8SjzkGk94EqfH6XqMWum/XQDIb5IWyE2nm4MCHED62mEEbjbDwtLmiWK0g"
                                    + "iZV3qe1PJ1LRLmeqRvjVHWc0b7QxnkjPCCnfMpode5IQY3AZM3unIVFA043oD3ZP"
                                    + "RsEch/hl2my2sxBa4PNod2cxw1PLbQVQWvKhf7ivmhVAKxwacXTb2yIynGljEgZZ"
                                    + "fkV1hATS9TGgHG2wpeZ9o0M4/JaN+TLgjruvgaE6vArdndBQcUV/NAOBeDegsfAs"
                                    + "ic7OC9FD/3MFgLo2g72WYY3BuCNMDj8L3lWK+vyC/S66cIvp1P2GzsccHSfcK0MC"
                                    + "09ojnCbKF6D7tv5pIKhtvZRC7xcNv1ctS/fbUbMy4tH+8iwvJlTRGZuuEYDwoBFo"
                                    + "wNS1oHxeO1PI1im93inAYt5GhkMuaZKLaY64xe51LJNcP1ovAhHaMG8UGfeCiNBR"
                                    + "jGEP3pMG8sgLyw9k3gqMVzX4MUfPlXQh503k3bVE/eymdsdZ1kAlMLR26IoQ6muA"
                                    + "Htn0cy00RjRPy0hIQ2Z+ACog0ge91AyWgXjn0WYI3AUOzVRZAoqS7ymf2zQfyb3W"
                                    + "VYBMfyYT9IhUZlAWq8uzEkoFs47r0LKrv6DALX8MCeTVUP6ELg4Inaz8UDECAwEA"
                                    + "AQKCAgBYJXH9lox6oT/d7DoeGbCKok9U/g1xFOC4cXvJE4tdgEkNCvJAgirmzhDo"
                                    + "/RBJ2r4ylc3bclHp93kqYY4tzSgcBDElmLyRst4Ln9UcuB8wCeUlV4AR8iXgDPx7"
                                    + "H1jrN/R0An/Xscb06hrQ37mgmWlLDiEz03qVyv6Sfj3YZSIdmPDnnamr2rzUjAdN"
                                    + "AQcjwPyYIJ0kF3dVfmVDverfNljYbvZ44QMAgCqTFinvI5cl4p3a1nRSEU9UzM1U"
                                    + "P4KRZatT8fxoSlmmWPIOacdNRzamax28tBJx1Nv7gQtV8cF5Na8BwwL3zYjhG/Za"
                                    + "9QRxxWtWKyPz5oMGgY/M/BPZwUcrCXs9fiHKzFtGQK0C1AffIhUnmlLf90OKLkhW"
                                    + "O6CSIAyRZl6aKhDRrtmM+n4tn9tjKOyrJ9WWFU/BV57v+MNo97tIWsPu0G7TSAIv"
                                    + "JQAQlTKtpH1Nf4Kt3gCNILJcvBVOQPZ2TObJRqFD89/0daRr8ewmOeDYF0Q0h1n5"
                                    + "9oWqnoseodYD2EnvttC50IpfSF3XMfugbDQ90t96uSlTAkFuPw+HI3ikhP4RxveB"
                                    + "keBp+VUCKOdwfBCSWLLPGcU4dQlsmiEoIvkLr/z3rrsJKI/64/lqgfU3A7GqAgQz"
                                    + "2dfrnf0UPVSjJjuCs/TKBXSDxghzhFAQ5rjH4laazzQdqrQUPQKCAQEA7uhWcnxM"
                                    + "B62vjJDQ4cVhKGrTooE8PehrOGKKR2i1BrddvwwbXy8wlbHDgEjvSTc0yOr38vdk"
                                    + "Miwul/gR2/EG3qGuI6OnnPp8tYWLYMkDjjYC5mcQXBnHT5BAmAIDEgC7Fi0O9+hM"
                                    + "5fCy7/8admovUJZcOX8q+urs1LNakcLuusA0CGB9KJvNvIwOuMnhaVvaFXTf2oZ8"
                                    + "55itKyoG6Ca/AR5aNuUO6YnL+rEQaYsKsreYwB1B8B0UTxgVl12YtJWZkG3SHAKR"
                                    + "RQeqrZQPtIUgN5hk6dX0vzv4fvooGT162PrWckriqSKag4lxJnOp6DO0NyEGwf+4"
                                    + "FaEItex7PFUMuwKCAQEAzgrvL+56sqhKho0Z3J/PYj4f4LNElE1hQ7sHd2QtfyYS"
                                    + "Ig4qKiUJIKjfC9LrFjtyqRiH5OTs63eorO+757DTFWjXCSVUwppPcLyOyr5mrULL"
                                    + "T2PE8LE0GBw2PnIkfMCuDlvxKp/Arb1Co5uRCWrSPHEcY+hSlp5SJYwNhs3HyNBZ"
                                    + "soKmjnUtP+HX5KlBoMQEo8kKnlfBTSVl2WAeu5UaM4Z0Q8ZxgCMnhDx2lVmMohUw"
                                    + "/qBDw+uA51vgSCSRQLamrlEZQ6jqUzD/9kNbqioMKuPCOZWIKBZvBJNe2hmF+JKb"
                                    + "epSrtKIor229l98UbfYhhiAw0//qon+pGXANNyneAwKCAQAd5VMUBnvZJiHmnCSX"
                                    + "bASpcxzCpBtuv8vTBXm6T97/VSjVBGXUdmpFATausfHHnrHrRoP6knymTqMR/0f0"
                                    + "1ud+KotJCGysFyhN6sUzOlRIknewb0s7yzoGuc1reCz8Lr06nC7YVOhyiblKkQi1"
                                    + "srnzAq3NwB0XwxgZ0cvOm68WDYE1XyWqVDzdkEUzWIftkEHtF2//v36X2KIq2Zp9"
                                    + "qIOUV0EAx48jKEwvNcMRAgY3sQPbXo3mxyzIbQIeq+a1CldqHGQDf0rAcaIpEHMa"
                                    + "quIKMvbF0DFNUOrasOEdr3TU/CajrL1KXvso5KUVI7oqRXYSw/49fouBoWIeqdYO"
                                    + "CbKLAoIBAC9lzIgWMBuRIzO4mc5q5OYQrHygQJJtCobuK1WHsf+h3mH/KCvxwRvG"
                                    + "PSkXKAVBP6sufXRmRSoVqLO/olY2ExjFuVHdSJZLsSKZ/a8eBbituN9WcCN+YCF7"
                                    + "u+65izM3j9K1y9CmV0igVQgV7VNhQ2OsEX/aHcWQPg1tHl94TxEe/MNX0sDKq9Ia"
                                    + "PfPYC8TT0s1qngq23TzF8ZwDxI4aSqC3uV8t80Yq0BhXYGAS7YsLnO22KGCVeF3A"
                                    + "gOOXpeJhIg7PkSRDY0Qn7XnVHO0UJyBmrHNatquiHX/L9vHtFSiNcT7NnII9G2bf"
                                    + "s9GP+78f865LEXBzWqJvA5Nad2/NLckCggEANWMjb5QcJqTSXn0f2UqJ7AicWoqQ"
                                    + "dMjpY79N+2iz2tlNFD9/BC/l6QGhM4YMVLNDwM2Aak37P8ZnQ9frEjMCEoD2bIlO"
                                    + "cWxVaXMP39rnLUPzg8D2TcjiQ2NBL4FDYXudZCUh4b1x70Gp2GiP7GxZwv2/SQhD"
                                    + "j7cc4oNwaE1hkiMhAYbPgWUU06JQwWPcD8UmKUgdp2ET+eUEwfV0GVtNOSfGoenf"
                                    + "ZqdaYcE8c3ft37JM5AsKo5h+G3qHOBRMEYHtQDybuvvFsg+hJ0BuxYt4mFubWZYL"
                                    + "V/tu4K1kmEZXgTvNZWSsZaIY2xBus2Ol2rKTahA0d9ffGeUhRj+UQrWpxg=="
                                    + "\n-----END RSA PRIVATE KEY-----", "utf-8")

    @staticmethod
    def read_file(filename):
        """Returns the contents of the file."""
        with open(filename, 'rb') as file:
            return file.read()

    @staticmethod
    def get_rsa_key_from_file(filename):
        """Returns the RSA key"""
        with open(filename, "r", encoding='utf-8') as f:
            key = f.read()

        # Convert the key from a string to bytes
        key = bytes(key, 'utf-8')

        return key

    @staticmethod
    def write_time_list_to_csv(time_list, filename):
        """Writes the time list to a CSV file."""
        with open('results/' + filename + '.csv', 'w', encoding='utf-8') as myfile:
            for time in time_list:
                myfile.write(str(time) + '\n')
