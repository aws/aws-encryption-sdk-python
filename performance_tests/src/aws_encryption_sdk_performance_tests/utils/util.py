# Copyright Amazon.com Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0
"""Utility functions for AWS Encryption SDK performance tests."""


class PerfTestUtils:
    """Utility functions for AWS Encryption SDK performance tests."""
    DEFAULT_N_ITERS = 100
    DEFAULT_FILE_SIZE = 'medium'
    DEFAULT_AES_256_STATIC_KEY = \
        b'_\xcf"\x82\x03\x12\x9d\x00\x8a\xed\xaf\xe4\x80\x1d\x00t\xa6P\xac\xb6\xfe\xc5\xf6/{\xe7\xaaO\x01\x13W\x85'
    DEFAULT_RSA_PUBLIC_KEY = bytes("-----BEGIN PUBLIC KEY-----\n"
                                   + "MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEAxwWEEtEofjwaoo3WO79D\n"
                                   + "hntoPf2APlY5yzlqm6ZvMyaazlwetkAzLSn5GB4hjKZaf043BfADJEdwXMHn8/UN\n"
                                   + "up0BfUj8PfGn/b8cL78CTnvFZd/7WxQh6tUnfLX7BMiccHMb9OHhRy5PrTSuj6Um\n"
                                   + "wwhBadL+Lc23DGl2cyN9SjGuYWWQ1IHGFA4/2EQr+Ez4LpebZqwXgv0iLuApte1q\n"
                                   + "vGl6zOhByxi1N/ORVEscLT82+L+F3STgeTYA1CaoLFQ0y9ybx+7UUfEfKxhGoGEO\n"
                                   + "XEOTuRBdLE2Jm8xaBODLqfiXr0z62VhTpRs4CYYTGHTLFCJHqeH7R2fwvwoG1nIg\n"
                                   + "QzWSyyapK7d5MLn3rF3ManjZhvlyHK1wqa7nWVpo+jq1Py+HWLAtU8FY0br6wnOR\n"
                                   + "3jjPGk0N4//iDnxNN+kpDxFnHEvxe3eJKWnbw0GR9+BGj32O+wRMtGyfRTzkoD/E\n"
                                   + "EqIRlDzdtYCAtFW0HUsdQwL+ssDjEQ0+lqvEQrwTU1WBZiBQhEmzksAowHAcNIT+\n"
                                   + "Fz7mvIlpEETNOQbsJkoXdEkhJXljh5UYmH1cB5al1MJf/5ea5Xb2HfH5WkMy4+eS\n"
                                   + "V68V+tXv3ZthTe2bCk9rQTH9FWKLIYJyZfv8WAIxSWEEsyk5b+7WUGmvtm/nPJ4Z\n"
                                   + "RfzkXoBJqJiSiPYCM0+jG4sCAwEAAQ==\n"
                                   + "-----END PUBLIC KEY-----\n", 'utf-8')

    DEFAULT_RSA_PRIVATE_KEY = bytes("-----BEGIN PRIVATE KEY-----\n"
                                    + "MIIJQwIBADANBgkqhkiG9w0BAQEFAASCCS0wggkpAgEAAoICAQDHBYQS0Sh+PBqi\n"
                                    + "jdY7v0OGe2g9/YA+VjnLOWqbpm8zJprOXB62QDMtKfkYHiGMplp/TjcF8AMkR3Bc\n"
                                    + "wefz9Q26nQF9SPw98af9vxwvvwJOe8Vl3/tbFCHq1Sd8tfsEyJxwcxv04eFHLk+t\n"
                                    + "NK6PpSbDCEFp0v4tzbcMaXZzI31KMa5hZZDUgcYUDj/YRCv4TPgul5tmrBeC/SIu\n"
                                    + "4Cm17Wq8aXrM6EHLGLU385FUSxwtPzb4v4XdJOB5NgDUJqgsVDTL3JvH7tRR8R8r\n"
                                    + "GEagYQ5cQ5O5EF0sTYmbzFoE4Mup+JevTPrZWFOlGzgJhhMYdMsUIkep4ftHZ/C/\n"
                                    + "CgbWciBDNZLLJqkrt3kwufesXcxqeNmG+XIcrXCprudZWmj6OrU/L4dYsC1TwVjR\n"
                                    + "uvrCc5HeOM8aTQ3j/+IOfE036SkPEWccS/F7d4kpadvDQZH34EaPfY77BEy0bJ9F\n"
                                    + "POSgP8QSohGUPN21gIC0VbQdSx1DAv6ywOMRDT6Wq8RCvBNTVYFmIFCESbOSwCjA\n"
                                    + "cBw0hP4XPua8iWkQRM05BuwmShd0SSEleWOHlRiYfVwHlqXUwl//l5rldvYd8fla\n"
                                    + "QzLj55JXrxX61e/dm2FN7ZsKT2tBMf0VYoshgnJl+/xYAjFJYQSzKTlv7tZQaa+2\n"
                                    + "b+c8nhlF/ORegEmomJKI9gIzT6MbiwIDAQABAoICAAi9ysfCzQsCW88g+LRmGbKp\n"
                                    + "7/GtFTlnsyEkc/TDMiYmf20p6aVqm3TT3596D1IsqlPmHQ+TM6gfxSUl1SjHbiNw\n"
                                    + "qvSURJP57b186+GC+7hzwj9Pv6wH7ddxJktZeN2EbC6aN7OhSjJEq/Y5FqOzhsjR\n"
                                    + "L4JU5Joha3VNmojDGcks9nJLsjlLO+Z8m7xFfkLpKottWEOBsoSr1pkFen+FnocJ\n"
                                    + "AP5IAz/G5YrAFXWE2Qd5u9HgI6KLcJqSTyYCTqenySvdFDCLYmL4+rv7VHrN2IIf\n"
                                    + "67iYqeb8vtsLdja5ouhjxVHLSUdLlFzvnZ35eBQ+aP8I5GnnRZCk1ZOmfpdjqtwE\n"
                                    + "4mQRJU44DtGH/aySgQEAjn5BAxjrflSBpgAJs8HxTIoGXEEtGgJQeJcvSxv/1fTy\n"
                                    + "EJSmwzepxDT1kAK0BPEllSHNLlHTEeJ8FMCGaEofDXPvJsJP/UvWxGmyRQXtG68m\n"
                                    + "WAy27OsAQ2z6Iqn2829lUnJERjtFUHJDu5ZlJHRPz6d7FTbmI5jFOGGTDWKtHqFI\n"
                                    + "88JZTwby55KyYLwDyxbqcDrRSOtzZ4N0rV2tLIMRoMDpjhJ8CopuxuQyxeuP3/7V\n"
                                    + "tcW4IbNTqEDKL4TFZkZhb+govAvFAkRFjBWu7kZpSEGNVvR+O1pTgXxWsfaAb+3K\n"
                                    + "EZ0lXelzaGCMCbwysAhxAoIBAQD+AfzgIva7GelSKujRO8rlhtPxoVNTMDbRo9QX\n"
                                    + "NtztLHvrxyaZqM5nqf4rMjrbU7vPdT5Fn/3/iupaBkZk8IqqdKpdmgi+Pr+aFvOB\n"
                                    + "LU2blEY8zWZCOwYerrwEPbQKblLdkIhDvOGpx1g4JuAlqIqJWW/RvMODf9Makwyq\n"
                                    + "fxkG+y2Cr8TIsM3jKXprOkgeE7sB97r2OvkSuL/xP2cedCt0dI1vnk2QvUWw6af4\n"
                                    + "Fs4xzqntS3KG3PHM9Jhljadm6da3cFnQxTIYpS0qT+Dv07NnTn1Ysjb2iCXEjvW2\n"
                                    + "vZEjrcLO4dWfZXVIXAjKhG+e/MbCcjEmbhd480SvDjImzk47AoIBAQDIlR+afYw+\n"
                                    + "UHaaQJiqnkY8E/ju4emgwVDZN3QJGEQS1q+HrCM0QAD410cwEBiyhuciYN27lEfU\n"
                                    + "3NXNb4TKYLN9u/Alj0Em+UFN/cPdUEvgrqQXS5E5GWOX3ehG3LYI/a4n6nlo/zdu\n"
                                    + "GSqHU93i8PoKweQFS23oCqnCkH5xBRcyvC3J/T4G/fl8FrnoVn9HLs3vM0gYMZSl\n"
                                    + "Ej2XZJXbitpqS3QyK51ULePVwaC3Zjot3YxsAzpdcSG1/6VNj1QWr9KAr8YdXTu7\n"
                                    + "VcStCElDksVbfMgYahpBYlU4xipPA101ll1KPom1ECI/F6ku5b2H2vnewy2TNzsY\n"
                                    + "QX0R4NFofQLxAoIBAG2af/pbO+naMXKSL2nxighmmFfATAsuV8k4DxGBS+1Pb516\n"
                                    + "jq5pR781fAY5o2n2hKjtJ1S1x80XrS3xXTi7Dqqkssq256TnwJeF5cbMvJswbOpZ\n"
                                    + "mxFjFK3yqhCOa3zAxCL09cd83kb7TJbWN4woYLcJj5WKBTdd1cK2xxVeyHbZtXaZ\n"
                                    + "z6jlmcG2qStRt8K6sswTkGolYkpwy+oWeLGMYR/cFxed0ExvT34aJK+Jb6nQSkSp\n"
                                    + "dJ67Ad91f7j6WcyvhEYdRbQvEwHNbGLAmwgBan1eQfoe1Famwt1A7sfOnq0tkkzg\n"
                                    + "5+PizKvPgr+YS+3nlwBac9joUlqPZgi/cGaMSPcCggEBALbTLZ4sJyM5RhFtJXoG\n"
                                    + "j6/86F4cbk1HRwDmSY5snsepBQ8duGzMldY6qrlFQq2expgQQKrUCfEcZIg+yIOK\n"
                                    + "RrApGEez3ke+02ZaEifsI20k4Y4WI8UuvhdTfX7xd76UMyRQ1N7+GTDyIVB+AfXz\n"
                                    + "fYVGmya0TPY+meMsvwMXB8EHwpikid/nqHoRYNxD0vk30R7g2CqtLnaTPK58URdt\n"
                                    + "5Y0TP1LnbBypQ0y3k1z3AbqCgJaHDrDTCE4SOUKLjLKtCaqgDG0BaQtkrsKkldrQ\n"
                                    + "sbCk+OE//LRyA4mfHjssrs3EQz4D6JKvpPdrApsrbmihEDWaIzVXFzcRogUkrNqX\n"
                                    + "b5ECggEBAKGW7doJEm0MjyvrJj/Tj4Zx3S8UjMgheBEIUZtMjewtNL0pn70O2AxN\n"
                                    + "aEa4zHaNS0yTgMdbObImzYgat+asJbmFcv0UJy/e4CN+rrZlCHW2D9v9U+O0wKLB\n"
                                    + "e5AmmFwaT/vVIy4gmBTcKGxV90ZF799gmKSoHAlrgjPFSRB/WcJsMwsGEyXl/C4Z\n"
                                    + "4/xCqJgr0VJvuwrCiWf1QKn9AHuytit27E2R52n4FjU5nJ+CJEQqU1XDgF0x+txw\n"
                                    + "PXUuRjOxKO6MzldzqJSUrTir8uqCwBIR9x9GOrGDp//ZbRw2TK4EbkyjNYO7KtOF\n"
                                    + "A/DHJmMI5bKETJyj1GhBE9LqypAI1Bo=\n"
                                    + "-----END PRIVATE KEY-----\n", "utf-8")

    DEFAULT_ENCRYPTION_CONTEXT = {
        "tenant": "TenantA",
        "encryption": "context",
        "is not": "secret",
        "but adds": "useful metadata",
        "that can help you": "be confident that",
        "the data you are handling": "is what you think it is",
    }

    DEFAULT_BRANCH_KEY_ID_A = 'a52dfaad-7dbd-4430-a1fd-abaa5299da07'

    DEFAULT_BRANCH_KEY_ID_B = '8ba79cef-581c-4125-9292-b057a29d42d7'

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
        with open(filename + '.csv', 'w', encoding='utf-8') as myfile:
            for time in time_list:
                myfile.write(str(time) + '\n')
