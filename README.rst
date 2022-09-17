====
rbcl
====

Ristretto group Python binding to `libsodium <https://github.com/jedisct1/libsodium>`__

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

rbcl supports Python 3.7, 3.8 and 3.9.

.. code:: python

    from rbcl import *

    x = crypto_core_ristretto255_random()
    assert crypto_core_ristretto255_is_valid_point(x)

    y = crypto_core_ristretto255_from_hash(b'\xF0'*64)
    assert crypto_core_ristretto255_is_valid_point(y)

    z1 = crypto_core_ristretto255_add(x, y)
    z2 = crypto_core_ristretto255_add(y, x)
    assert z1 == z2  # Assert that point addition commutes (in L)

    s1 = crypto_core_ristretto255_scalar_random()
    s2 = crypto_core_ristretto255_scalar_random()
    w1 = crypto_scalarmult_ristretto255(s1, crypto_scalarmult_ristretto255(s2, x))
    w2 = crypto_scalarmult_ristretto255(s2, crypto_scalarmult_ristretto255(s1, x))
    assert w1 == w2  # Assert that point multiplication (by a scalar) is repeated addition (in L)

The following bindings are made available:

`Constructors <https://libsodium.gitbook.io/doc/advanced/point-arithmetic/ristretto#encoded-element-validation>`__
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: python

    crypto_core_ristretto255_random()
    crypto_core_ristretto255_from_hash(h)
    crypto_core_ristretto255_is_valid_point(p)

`Scalar arithmetic <https://libsodium.gitbook.io/doc/advanced/point-arithmetic/ristretto#scalar-arithmetic-over-l>`__
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: python

    crypto_core_ristretto255_scalar_add(s1, s2)
    crypto_core_ristretto255_scalar_sub(s1, s2)
    crypto_core_ristretto255_scalar_mul(s1, s2)  # NOT scalar multiplication of a point!
    crypto_core_ristretto255_scalar_complement(s)
    crypto_core_ristretto255_scalar_invert(s)
    crypto_core_ristretto255_scalar_negate(s)
    crypto_core_ristretto255_scalar_reduce(s)
    crypto_core_ristretto255_scalar_random()

`Point arithmetic <https://libsodium.gitbook.io/doc/advanced/point-arithmetic/ristretto#scalar-multiplication>`__
~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~

.. code:: python

    crypto_core_ristretto255_add(p, q)
    crypto_core_ristretto255_sub(p, q)
    crypto_scalarmult_ristretto255(s, p)
    crypto_scalarmult_ristretto255_allow_scalar_zero(s, p)
    crypto_scalarmult_ristretto255_base(s)
	crypto_scalarmult_ristretto255_base_allow_scalar_zero(s)

Constants
~~~~~~~~~

::

    crypto_scalarmult_ristretto255_bytes
    crypto_scalarmult_ristretto255_scalarbytes
    crypto_core_ristretto255_bytes
    crypto_core_ristretto255_scalarbytes
    crypto_core_ristretto255_hashbytes
    crypto_core_ristretto255_nonreducedscalarbytes

Helpers
~~~~~~~

::

    randombytes
    randombytes_buf_deterministic

===================================
Manual installation
===================================

.. code:: shell

    # Build as a wheel and install
    python setup.py bdist_wheel
    python -m pip install -f wheelhouse --no-index rbcl
    python -m nose

===================================
Publishing (for Maintainers Only)
===================================

.. code:: shell
    
    # Package source distribution
    python setup.py sdist
    
    # Run wheel-builder.yml and save/download artifacts locally, e.g. in ./dist
    # Then, upload to PyPi
    twine upload dist/rbcl-0.2.0*

===================================
Documentation
===================================
.. include:: toc.rst

The documentation can be generated automatically from the source files using `Sphinx <https://www.sphinx-doc.org/>`_::

    cd docs
    python -m pip install -r requirements.txt
    sphinx-apidoc -f -E --templatedir=_templates -o _source .. ../setup.py ../rbcl/sodium_ffi.py && make html
