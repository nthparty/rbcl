====
rbcl
====

Python library that bundles `libsodium <https://github.com/jedisct1/libsodium>`__ and provides wrappers for its Ristretto group functions.

|pypi| |readthedocs| |actions| |coveralls|

.. |pypi| image:: https://badge.fury.io/py/rbcl.svg
   :target: https://badge.fury.io/py/rbcl
   :alt: PyPI version and link.

.. |readthedocs| image:: https://readthedocs.org/projects/rbcl/badge/?version=latest
   :target: https://rbcl.readthedocs.io/en/latest/?badge=latest
   :alt: Read the Docs documentation status.

.. |actions| image:: https://github.com/nthparty/rbcl/workflows/lint-test-cover-docs-build-upload/badge.svg
   :target: https://github.com/nthparty/rbcl/actions
   :alt: GitHub Actions status.

.. |coveralls| image:: https://coveralls.io/repos/github/nthparty/rbcl/badge.svg?branch=main
   :target: https://coveralls.io/github/nthparty/rbcl?branch=main
   :alt: Coveralls test coverage summary.

Installation and Usage
----------------------
This library is available as a `package on PyPI <https://pypi.org/project/rbcl>`__:

.. code-block:: bash

    python -m pip install rbcl

The library can be imported in the usual ways:

.. code-block:: python

    import rbcl
    from rbcl import *

Examples
^^^^^^^^

A few usage examples are presented below:

.. code-block:: python

    >>> from rbcl import *
    >>> x = crypto_core_ristretto255_random()
    >>> assert crypto_core_ristretto255_is_valid_point(x)
    >>> y = crypto_core_ristretto255_from_hash(b'\xF0' * 64)
    >>> assert crypto_core_ristretto255_is_valid_point(y)
    >>> z1 = crypto_core_ristretto255_add(x, y)
    >>> z2 = crypto_core_ristretto255_add(y, x)
    >>> assert z1 == z2 # Point addition commutes.
    >>> s1 = crypto_core_ristretto255_scalar_random()
    >>> s2 = crypto_core_ristretto255_scalar_random()
    >>> w1 = crypto_scalarmult_ristretto255(s1, crypto_scalarmult_ristretto255(s2, x))
    >>> w2 = crypto_scalarmult_ristretto255(s2, crypto_scalarmult_ristretto255(s1, x))
    >>> assert w1 == w2 # Multiplication of a point by a scalar is repeated addition.

This library exports Python wrappers for `constructors <https://libsodium.gitbook.io/doc/advanced/point-arithmetic/ristretto#encoded-element-validation>`__, `point arithmetic functions <https://libsodium.gitbook.io/doc/advanced/point-arithmetic/ristretto#scalar-multiplication>`__, and `scalar arithmetic functions <https://libsodium.gitbook.io/doc/advanced/point-arithmetic/ristretto#scalar-arithmetic-over-l>`__.

Development, Build, and Manual Installation Instructions
--------------------------------------------------------
All development and installation dependencies are managed using `setuptools <https://pypi.org/project/setuptools>`__ and are fully specified in ``setup.cfg``. The ``extras_require`` option is used to `specify optional requirements <https://setuptools.pypa.io/en/latest/userguide/dependency_management.html#optional-dependencies>`__ for various development tasks. This makes it possible to specify additional options (such as ``docs``, ``lint``, and so on) when performing installation using `pip <https://pypi.org/project/pip>`__ (assuming that the library has already been built successfully):

.. code-block:: bash

    python -m pip install .[docs,lint]

Building from Source
^^^^^^^^^^^^^^^^^^^^
The library can be built manually from source **within Linux and macOS** using the sequence of commands below:

.. code-block:: bash

    python -m pip install .[build]
    python -m build --sdist --wheel .

Developing the library further in a local environment and/or building the library from source requires `libsodium <https://doc.libsodium.org>`__. The step ``python -m build --sdist --wheel .`` in the above attempts to automatically locate a copy of the libsodium source archive ``src/rbcl/libsodium.tar.gz``. If the archive corresponding to the operating system is not found, the build process attempts to download it. To support building offline, it is necessary to first download the appropriate libsodium archive to its designated location:

.. code-block:: bash

    wget -O src/rbcl/libsodium.tar.gz https://github.com/jedisct1/libsodium/releases/download/1.0.18-RELEASE/libsodium-1.0.18.tar.gz

The process for building manually from source within a Windows environment is not currently documented, but an example of one sequence of steps can be found in the Windows job entry within the GitHub Actions workflow defined in the file ``.github/workflows/lint-test-cover-docs-build-upload.yml``.

Preparation for Local Development
^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^
Before `documentation can be generated <#documentation>`_ or `tests can be executed <#testing-and-conventions>`_, it is necessary to `run the build process <#building-from-source>`_ and then to use the command below to move the compiled libsodium shared/dynamic library file into its designated location (so that the module file ``src/rbcl/rbcl.py`` is able to import it):

.. code-block:: bash

    cp build/lib*/rbcl/_sodium.py src/rbcl

Manual Installation
^^^^^^^^^^^^^^^^^^^
Once the package is `built <#building-from-source>`_, it can be installed manually using the command below:

.. code-block:: bash

    python -m pip install -f dist . --upgrade

Documentation
^^^^^^^^^^^^^
Once the libsodium shared library file is compiled and moved into its designated location (as described in `the relevant subsection above <#preparation-for-local-development>`_), the documentation can be generated automatically from the source files using `Sphinx <https://www.sphinx-doc.org>`__:

.. code-block:: bash

    python -m pip install .[docs]
    cd docs
    sphinx-apidoc -f -E --templatedir=_templates -o _source .. ../src/rbcl/_sodium_build.py && make html

Testing and Conventions
^^^^^^^^^^^^^^^^^^^^^^^
Before unit tests can be executed, it is first necessary to prepare for local development by compiling and moving into its designated location the libsodium shared library file (as described in `the relevant subsection above <#preparation-for-local-development>`__).

All unit tests are executed and their coverage is measured when using `pytest <https://docs.pytest.org>`__ (see ``pyproject.toml`` for configuration details):

.. code-block:: bash

    python -m pip install .[test]
    python -m pytest

Alternatively, all unit tests are included in the module itself and can be executed using `doctest <https://docs.python.org/3/library/doctest.html>`__:

.. code-block:: bash

    python src/rbcl/rbcl.py -v

Style conventions are enforced using `Pylint <https://pylint.readthedocs.io>`__:

.. code-block:: bash

    python -m pip install .[lint]
    python -m pylint src/rbcl src/rbcl/_sodium.tmpl src/rbcl/_sodium_build.py --disable=duplicate-code

Contributions
^^^^^^^^^^^^^
In order to contribute to the source code, open an issue or submit a pull request on the `GitHub page <https://github.com/nthparty/rbcl>`__ for this library.

Versioning
^^^^^^^^^^
The version number format for this library and the changes to the library associated with version number increments conform with `Semantic Versioning 2.0.0 <https://semver.org/#semantic-versioning-200>`__.

Publishing
^^^^^^^^^^
This library can be published as a `package on PyPI <https://pypi.org/project/rbcl>`__ by a package maintainer. First, install the dependencies required for packaging and publishing:

.. code-block:: bash

    python -m pip install .[publish]

Ensure that the correct version number appears in ``setup.cfg``, and that any links in this README document to the Read the Docs documentation of this package (or its dependencies) have appropriate version numbers. Also ensure that the Read the Docs project for this library has an `automation rule <https://docs.readthedocs.io/en/stable/automation-rules.html>`__ that activates and sets as the default all tagged versions. Create and push a tag for this version (replacing ``?.?.?`` with the version number):

.. code-block:: bash

    git tag ?.?.?
    git push origin ?.?.?

Remove any old build/distribution files. Then, package the source into a distribution archive:

.. code-block:: bash

    rm -rf build dist src/*.egg-info
    python -m build --sdist .

Next, navigate to the appropriate GitHub Actions run of the workflow defined in ``lint-test-cover-docs-build-upload.yml``. Click on the workflow and scroll down to the **Artifacts** panel. Download the archive files to the ``dist`` directory. Unzip all the archive files so that only the ``*.whl`` files remain:

.. code-block:: bash

    cd dist && for i in `ls *.zip`; do unzip $i; done && rm *.zip && cd ..

Finally, upload the package distribution archive to `PyPI <https://pypi.org>`__:

.. code-block:: bash

    python -m twine upload dist/*
