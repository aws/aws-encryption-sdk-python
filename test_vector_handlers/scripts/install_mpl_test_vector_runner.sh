# Builds the Python MPL TestVector runner from source.
# This package is used by the ESDK-Python test vectors for testing with the MPL.

# This script is intended to be used by ESDK-Python's integration tests.
# You may need or want to make local changes to get this work on your machine.

# Change to the directory of the script
cd "$(dirname "$0")"

# Get highest MPL version specified in requirements.txt
export mplVersion=$(grep 'aws-cryptographic-material-providers' ../requirements_mpl.txt | tr ',' '\n' | grep '<=' | sed -E 's/[^0-9]*//')

# Clone MPL repo to get test vectors runner source code and the Dafny version to use
git clone --branch v$mplVersion --recurse-submodules https://github.com/aws/aws-cryptographic-material-providers-library.git

# Download Dafny to build the test vector runner; get Dafny version from ESDK's project.properties file
export dafnyVersion=$(grep '^dafnyVersion=' aws-cryptographic-material-providers-library/project.properties | cut -d '=' -f 2)
curl https://github.com/dafny-lang/dafny/releases/download/v$dafnyVersion/dafny-$dafnyVersion-x64-ubuntu-20.04.zip  -L -o dafny.zip
unzip -qq dafny.zip && rm dafny.zip
export PATH="$PWD/dafny:$PATH"

# Build MPL test vector runner from source
cd aws-cryptographic-material-providers-library/
make -C StandardLibrary setup_net # Without this the if-dafny-at-least command includes "Downloading ..." output
cd TestVectorsAwsCryptographicMaterialProviders/
make transpile_python
