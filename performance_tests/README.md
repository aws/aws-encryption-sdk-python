# Performance Tests for ESDK Python

## License

This project is licensed under the Apache-2.0 License.

## Overview

Here are the keyrings / master key-providers that we are testing:

1. KMS Keyring / KMS Master Key Provider
2. Raw AES Keyring / AES Master Key Provider
3. HKeyring / caching CMM example ("old" caching solution vs the (current) "new" caching solution)
4. Raw RSA Keyring / RSA Master Key Provider

For each test on the above keyrings / master key-providers, we measure the execution time and memory consumption in each test.

For each keyring / master key-provider, we test the execution time and memory consumption time for three operations:
1. Create keyring / master key-provider
2. Encrypt
3. Decrypt

We demonstrate the usage of the performance tests through an [AWS KMS Keyring](https://docs.aws.amazon.com/encryption-sdk/latest/developer-guide/use-kms-keyring.html). However, the procedure is the same for any keyring / master key-provider, with slight change in the input arguments.

The results for the performance test will be available in the results folder in the performance_tests directory.

## Usage: Execution Time

### Create Keyring
To run the performance test for execution time, please use the following commands in the performance_tests directory
```
python test/keyrings/test_aws_kms_keyring.py create
```

#### Optional Arguments
* kms_key_id: The KMS key ID you want to use
* n_iters: Number of iterations you want to run the test for. For instance, if n_iters = 100, this performance test script will run the create_keyring method 100 times and report the execution time of each of the calls.
* output_file: The output file for execution times for each function call, default='kms_keyring_create' in the results folder

#### Consolidate Results

In order to find the minimum, maximum and average times from the n_iters runs, please use the following script from the performance_tests directory:
```
python consolidate_results.py results/kms_keyring_create.csv
```

### Encrypt
To run the performance test for execution time, please use the following commands in the performance_tests directory
```
python test/keyrings/test_aws_kms_keyring.py encrypt
```

Here, you will receive a prompt on the terminal to specify the plaintext file you want to encrypt. Some example plaintext data files are present in the 'test/resources' directory.

Alternatively, if you want to provide the arguments as flags without using the interactive CLI, you can run the command in the following manner:

```
python test/keyrings/test_aws_kms_keyring.py encrypt --plaintext_data_filename test/resources/plaintext-data-medium.dat
```

You can choose to use any other plaintext file as well.

#### Arguments
* plaintext_data_filename: Filename containing plaintext data you want to encrypt

#### Optional Arguments
* kms_key_id: The KMS key ID you want to use to encrypt the data
* n_iters: Number of iterations you want to run the test for. For instance, if n_iters = 100, this performance test script will run the encrypt method 100 times and report the execution time of each of the calls.
* output_file: The output file for execution times for each function call, default='kms_keyring_encrypt'

#### Consolidate Results

In order to find the minimum, maximum and average times from the n_iters runs, please use the following script from the performance_tests directory:
```
python consolidate_results.py results/kms_keyring_encrypt.csv
```

### Decrypt
To run the performance test for execution time, please use the following commands in the performance_tests directory
```
python test/keyrings/test_aws_kms_keyring.py decrypt
```

Here, you will receive a prompt on the terminal to specify the ciphertext file you want to decrypt. Some example ciphertext data files are present in the 'test/resources' directory.

Alternatively, if you want to provide the arguments as flags without using the interactive CLI, you can run the command in the following manner:

```
python test/keyrings/test_aws_kms_keyring.py decrypt --ciphertext_data_filename test/resources/ciphertext-data-medium.ct
```

You can choose to use any other ciphertext file as well.

#### Arguments
* ciphertext_data_filename: Filename containing ciphertext data you want to decrypt

#### Optional Arguments
* kms_key_id: The KMS key ID you want to use to decrypt the data
* n_iters: Number of iterations you want to run the test for. For instance, if n_iters = 100, this performance test script will run the decrypt method 100 times and report the execution time of each of the calls.
* output_file: The output file for execution times for each function call, default='kms_keyring_decrypt'

#### Consolidate Results

In order to find the minimum, maximum and average times from the n_iters runs, please use the following script from the performance_tests directory:
```
python consolidate_results.py results/kms_keyring_decrypt.csv
```

## Usage: Memory Consumption
To get the memory consumption, simply use 'mprof run' instead of 'python' in the previously mentioned commands.

For example, if you want to calculate the memory consumption of the encrypt function of a AWS KMS Keyring, simply write:
```
mprof run test/keyrings/test_aws_kms_keyring.py encrypt --plaintext_data_filename test/resources/plaintext-data-medium.dat
```

This should generate an mprofile log file in your current directory. To plot the memory consumption with time, please use the following command from the same directory
```
mprof plot
```

This 'mprof plot' command will plot the most recent mprofile log file.

## Usage: Performance Graph
To generate a performance graph, please use the following command to generate the pstats log file by specifying the output pstats file path. Here, we use 'results/kms_keyring_create.pstats' as the output file.

```
python -m cProfile -o results/kms_keyring_create.pstats test/keyrings/test_aws_kms_keyring.py create
```

After generating the pstats file, please run the following command to generate the performance graph. The output performance graph will be a .png file that you specify. Here, we use 'results/kms_keyring_create.png' as the output file.
```
gprof2dot -f pstats results/kms_keyring_create.pstats | dot -Tpng -o results/kms_keyring_create.png && eog results/kms_keyring_create.png 
```
