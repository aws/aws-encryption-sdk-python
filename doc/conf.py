# -*- coding: utf-8 -*-
import os
import re
from datetime import datetime

VERSION_RE = re.compile(r'''__version__ = ['"]([0-9.]+)['"]''')
HERE = os.path.abspath(os.path.dirname(__file__))


def read(*args):
    """Reads complete file contents."""
    return open(os.path.join(HERE, *args)).read()


def get_release():
    """Reads the release (full three-part version number) from this module."""
    init = read('..', 'src', 'aws_encryption_sdk', 'identifiers.py')
    return VERSION_RE.search(init).group(1)


def get_version():
    """Reads the version (MAJOR.MINOR) from this module."""
    release = get_release()
    split_version = release.split('.')
    if len(split_version) == 3:
        return '.'.join(split_version[:2])
    return release


project = u'aws-encryption-sdk-python'
version = get_version()
release = get_release()

# Add any Sphinx extension module names here, as strings. They can be extensions
# coming with Sphinx (named 'sphinx.ext.*') or your custom ones.
extensions = ['sphinx.ext.autodoc', 'sphinx.ext.doctest',
              'sphinx.ext.intersphinx', 'sphinx.ext.todo',
              'sphinx.ext.coverage', 'sphinx.ext.autosummary',
              'sphinx.ext.napoleon']
napoleon_include_special_with_doc = False

# Add any paths that contain templates here, relative to this directory.
templates_path = ['_templates']

source_suffix = '.rst'  # The suffix of source filenames.
master_doc = 'index'  # The master toctree document.

copyright = u'%s, Amazon' % datetime.now().year

# List of directories, relative to source directory, that shouldn't be searched
# for source files.
exclude_trees = ['_build']

pygments_style = 'sphinx'

autoclass_content = "both"
autodoc_default_flags = ['show-inheritance', 'members']
autodoc_member_order = 'bysource'

html_theme = 'sphinx_rtd_theme'
html_static_path = ['_static']
htmlhelp_basename = '%sdoc' % project

# Example configuration for intersphinx: refer to the Python standard library.
intersphinx_mapping = {'http://docs.python.org/': None}

# autosummary
autosummary_generate = True
