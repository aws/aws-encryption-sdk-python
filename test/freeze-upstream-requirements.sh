#!/bin/bash
# Minimal wrapper script for upstream requirements install and freeze.
# We do this here rather than as tox commands because tox does not support output redirection.
if [ -z ${1} ]; then
    exit 1
fi

pip install -r requirements.txt
pip install -r dev_requirements/test-requirements.txt
pip freeze > ${1}
