# Build Python MPL TestVector runner from source      
# Clone MPL repo to get test vectors runner source code and the Dafny version to use
git clone --recurse-submodules https://github.com/aws/aws-cryptographic-material-providers-library.git
# Download Dafny to build the test vector runner; get Dafny version from ESDK's project.properties file
export dafnyVersion=$(grep '^dafnyVersion=' aws-cryptographic-material-providers-library/project.properties | cut -d '=' -f 2)
curl https://github.com/dafny-lang/dafny/releases/download/v$dafnyVersion/dafny-$dafnyVersion-x64-ubuntu-20.04.zip  -L -o dafny.zip
unzip -qq dafny.zip && rm dafny.zip
export PATH="$PWD/dafny:$PATH"

# Build MPL test vector runner from source
cd aws-cryptographic-material-providers-library/TestVectorsAwsCryptographicMaterialProviders/
make transpile_python
# Install built runner.
# (no-deps skips installing its local MPL dependency in favor of the one from PyPI.)
pip install runtimes/python --no-deps
cd ../../
