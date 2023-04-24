"""
Python library that bundles `libsodium <https://github.com/jedisct1/libsodium>`__
and provides wrappers for its Ristretto group functions.

This library exports wrappers for all libsodium functions related to the Ristretto
group and random element generation, including all functions with names of the form
``crypto_scalarmult_*`` and relevant functions with names of the form
``randombytes*``.
"""
from __future__ import annotations
from typing import Callable
import doctest
import ctypes
import os
import pathlib
from barriers import barriers

try:
    VALIDATION_ENABLED = 'site-packages' not in str(pathlib.Path(__file__).resolve())
except NameError: # pragma: no cover
    VALIDATION_ENABLED = False
safe = barriers(VALIDATION_ENABLED) @ globals()

try:
    # Support for direct invocation in order to execute doctests.
    from _sodium import _sodium # pylint: disable=cyclic-import
except: # pylint: disable=bare-except # pragma: no cover
    from rbcl._sodium import _sodium # pylint: disable=cyclic-import

# Public and private globals (defined within ``_sodium_init`` after libsodium is ready).
randombytes_SEEDBYTES: int = None
"""Length of seed for a pseudorandom byte sequence.

:meta hide-value:
"""

crypto_core_ristretto255_BYTES: int = None
"""Length of a byte sequence that represents a point.

:meta hide-value:
"""

crypto_core_ristretto255_HASHBYTES: int = None
"""Length of hash digest to use for creating a point.

:meta hide-value:
"""

crypto_core_ristretto255_NONREDUCEDSCALARBYTES: int = None
"""
Length of a byte sequence that represents a scalar (possibly using a
non-reduced representation).

:meta hide-value:
"""

crypto_core_ristretto255_SCALARBYTES: int = None
"""Length of a byte sequence that represents a scalar.

:meta hide-value:
"""

crypto_scalarmult_ristretto255_BYTES: int = None
"""
Length of a byte sequence that represents a point (provided to -- or
returned by -- a scalar-point multiplication function).

:meta hide-value:
"""

crypto_scalarmult_ristretto255_SCALARBYTES: int = None
"""
Length of a byte sequence that represents a scalar (to be used as
an input to a scalar-point multiplication function).

:meta hide-value:
"""

_crypto_core_ristretto255_point_new: Callable[[], bytes] = (
    lambda: None # pylint: disable=unnecessary-lambda-assignment
)
_crypto_core_ristretto255_scalar_new: Callable[[], bytes] = (
    lambda: None # pylint: disable=unnecessary-lambda-assignment
)
_crypto_scalarmult_ristretto255_point_new: Callable[[], bytes] = (
    lambda: None # pylint: disable=unnecessary-lambda-assignment
)
_buffer_create: Callable[[int], bytes] = (
    lambda size: (ctypes.c_char * size)() # pylint: disable=unnecessary-lambda-assignment
)

def randombytes(length: int) -> bytes:
    """
    Return a bytes-like object of length ``length`` containing random bytes
    from a cryptographically suitable source of randomness.

    :param length: Length of bytes-like object to return.

    >>> len(randombytes(14)) == 14
    True
    >>> r1 = randombytes(14)
    >>> r2 = randombytes(14)
    >>> r1 == r2 # Chances of equality succeeding are 1/(2^42).
    False

    An exception is raised if the input is not valid:

    >>> randombytes('abc')
    Traceback (most recent call last):
      ...
    TypeError: length must be an integer
    >>> randombytes(-1)
    Traceback (most recent call last):
      ...
    ValueError: length must be a non-negative integer
    """
    if not isinstance(length, int):
        raise TypeError('length must be an integer')

    if length < 0:
        raise ValueError('length must be a non-negative integer')

    buf = _buffer_create(length)
    _sodium.randombytes(buf, length)
    return buf.raw

def randombytes_buf_deterministic(length: int, seed: bytes) -> bytes:
    """
    Return a bytes-like object of length ``length`` containing pseudorandom
    bytes that have been deterministically generated from the supplied seed
    (a byte vector of length :obj:`randombytes_SEEDBYTES`).

    :param length: Length of bytes-like object to return.
    :param seed: Seed to use for generating pseudorandom bytes.

    The example below shows that the first ``32`` bytes from the stream of
    pseudorandom bytes seeded by ``b'\x70' * 32`` are consistent across
    invocations:

    >>> r1 = randombytes_buf_deterministic(32, b'\x70' * 32)
    >>> r2 = randombytes_buf_deterministic(40, b'\x70' * 32)
    >>> len(r1) == 32
    True
    >>> r1 == r2[:32]
    True

    An exception is raised if an input is not valid:

    >>> randombytes_buf_deterministic('abc', b'\x70' * 32)
    Traceback (most recent call last):
      ...
    TypeError: length must be an integer
    >>> randombytes_buf_deterministic(-1, b'\x70' * 32)
    Traceback (most recent call last):
      ...
    ValueError: length must be a non-negative integer
    >>> try:
    ...     randombytes_buf_deterministic(32, 123)
    ... except TypeError as e:
    ...     str(e) == 'seed must be a bytes object of length ' + str(randombytes_SEEDBYTES)
    True
    >>> try:
    ...     randombytes_buf_deterministic(32, b'\x70'*16)
    ... except ValueError as e:
    ...     str(e) == 'seed must be a bytes object of length ' + str(randombytes_SEEDBYTES)
    True
    """
    if not isinstance(length, int):
        raise TypeError('length must be an integer')

    if length < 0:
        raise ValueError('length must be a non-negative integer')

    well_typed = isinstance(seed, bytes)
    if not well_typed or len(seed) != randombytes_SEEDBYTES:
        raise (ValueError if well_typed else TypeError)(
            'seed must be a bytes object of length ' +
            str(randombytes_SEEDBYTES)
        )

    buf = _buffer_create(length)
    _sodium.randombytes_buf_deterministic(buf, length, seed)
    return buf.raw

def crypto_core_ristretto255_is_valid_point(p: bytes) -> bool:
    """
    Return a boolean indiciating whether ``p`` is a representation of a valid
    point on the main subgroup (in canonical form) and that the point does not
    have a small order.

    :param p: Byte vector of length :obj:`crypto_core_ristretto255_BYTES`.

    >>> p = crypto_core_ristretto255_random()
    >>> crypto_core_ristretto255_is_valid_point(p)
    True

    For this and other functions that operate on points, a descriptive exception
    is raised if an input is not valid:

    >>> try:
    ...     crypto_core_ristretto255_is_valid_point(123)
    ... except TypeError as e:
    ...     str(e) == (
    ...         'point must be a bytes object of length ' +
    ...         str(crypto_core_ristretto255_BYTES)
    ...     )
    True
    >>> try:
    ...     crypto_core_ristretto255_is_valid_point(bytes([0, 0 ,0]))
    ... except ValueError as e:
    ...     str(e) == (
    ...         'point must be a bytes object of length ' +
    ...         str(crypto_core_ristretto255_BYTES)
    ...     )
    True
    """
    well_typed = isinstance(p, bytes)
    if not well_typed or len(p) != crypto_core_ristretto255_BYTES:
        raise (ValueError if well_typed else TypeError)(
            'point must be a bytes object of length ' +
            str(crypto_core_ristretto255_BYTES)
        )

    rc = _sodium.crypto_core_ristretto255_is_valid_point(p)
    return rc == 1

def crypto_core_ristretto255_random() -> bytes:
    """
    Return a valid random point (represented as a byte vector of length
    :obj:`crypto_core_ristretto255_BYTES`).

    >>> p = crypto_core_ristretto255_random()
    >>> crypto_core_ristretto255_is_valid_point(p)
    True
    """
    r = _crypto_core_ristretto255_scalar_new()
    _sodium.crypto_core_ristretto255_random(r)
    return r.raw

def crypto_core_ristretto255_from_hash(h: bytes) -> bytes:
    """
    Map a 64-byte vector ``h`` (usually the output of a hash function) to a
    a point (represented as a byte vector of length
    :obj:`crypto_core_ristretto255_BYTES`).

    :param h: Byte vector of length :obj:`crypto_core_ristretto255_HASHBYTES`
        (usually representing a hash digest).

    >>> p = crypto_core_ristretto255_from_hash(b'\x70'*64)
    >>> crypto_core_ristretto255_is_valid_point(p)
    True
    """
    well_typed = isinstance(h, bytes)
    if not well_typed or len(h) != crypto_core_ristretto255_HASHBYTES:
        raise (ValueError if well_typed else TypeError)(
            'input must be a bytes object of length ' +
            str(crypto_core_ristretto255_HASHBYTES)
        ) # pragma: no cover

    r = _crypto_core_ristretto255_point_new()
    _sodium.crypto_core_ristretto255_from_hash(r, h)
    return r.raw

def crypto_core_ristretto255_add(p: bytes, q: bytes) -> bytes:
    """
    Add two points ``p`` and ``q`` and return their sum (represented as
    a byte vector of length :obj:`crypto_core_ristretto255_BYTES`).

    :param p: Byte vector of length :obj:`crypto_core_ristretto255_BYTES`
        representing a point.
    :param q: Byte vector of length :obj:`crypto_core_ristretto255_BYTES`
        representing a point.

    Addition of points is commutative:

    >>> p = crypto_core_ristretto255_random()
    >>> q = crypto_core_ristretto255_from_hash(b'\x70'*64)
    >>> pq = crypto_core_ristretto255_add(p, q)
    >>> qp = crypto_core_ristretto255_add(q, p)
    >>> pq == qp
    True
    """
    well_typed = isinstance(p, bytes)
    if not well_typed or len(p) != crypto_core_ristretto255_BYTES:
        raise (ValueError if well_typed else TypeError)(
            'each point must be a bytes object of length ' +
            str(crypto_core_ristretto255_BYTES)
        ) # pragma: no cover

    well_typed = isinstance(q, bytes)
    if not well_typed or len(q) != crypto_core_ristretto255_BYTES:
        raise (ValueError if well_typed else TypeError)(
            'each point must be a bytes object of length ' +
            str(crypto_core_ristretto255_BYTES)
        ) # pragma: no cover

    r = _crypto_core_ristretto255_point_new()
    _sodium.crypto_core_ristretto255_add(r, p, q)
    return r.raw

def crypto_core_ristretto255_sub(p: bytes, q: bytes) -> bytes:
    """
    Subtract a point ``q`` from a point ``p`` and return their difference
    (represented as a byte vector of length :obj:`crypto_core_ristretto255_BYTES`).

    :param p: Byte vector of length :obj:`crypto_core_ristretto255_BYTES`
        representing a point.
    :param q: Byte vector of length :obj:`crypto_core_ristretto255_BYTES`
        representing a point.

    Subtraction between points is the inverse of point addition:

    >>> p = crypto_core_ristretto255_from_hash(b'\x70'*64)
    >>> q = crypto_core_ristretto255_random()
    >>> masked = crypto_core_ristretto255_add(p, q)
    >>> unmasked = crypto_core_ristretto255_sub(masked, q)
    >>> p == unmasked
    True
    """
    well_typed = isinstance(p, bytes)
    if not well_typed or len(p) != crypto_core_ristretto255_BYTES:
        raise (ValueError if well_typed else TypeError)(
            'each point must be a bytes object of length ' +
            str(crypto_core_ristretto255_BYTES)
        ) # pragma: no cover

    well_typed = isinstance(q, bytes)
    if not well_typed or len(q) != crypto_core_ristretto255_BYTES:
        raise (ValueError if well_typed else TypeError)(
            'each point must be a bytes object of length ' +
            str(crypto_core_ristretto255_BYTES)
        ) # pragma: no cover

    r = _crypto_core_ristretto255_point_new()
    _sodium.crypto_core_ristretto255_sub(r, p, q)
    return r.raw

def crypto_core_ristretto255_scalar_random() -> bytes:
    """
    Return a random scalar, represented as a byte vector of length
    :obj:`crypto_core_ristretto255_SCALARBYTES`.

    >>> s = crypto_core_ristretto255_scalar_random()
    >>> len(s) == crypto_core_ristretto255_SCALARBYTES
    True

    When interpreted as an integer, the scalar is guaranteed to be
    less than the order of the group (*i.e.*,
    ``2^252 + 27742317777372353535851937790883648493``).
    """
    r = _crypto_core_ristretto255_scalar_new()
    _sodium.crypto_core_ristretto255_scalar_random(r)
    return r.raw

def crypto_core_ristretto255_scalar_reduce(s: bytes) -> bytes:
    """
    Given a byte vector of length :obj:`crypto_core_ristretto255_NONREDUCEDSCALARBYTES`
    representing a scalar, return its reduced representation ``s`` modulo ``L``
    (where ``L`` is the order of the main subgroup) as a byte vector of length
    :obj:`crypto_core_ristretto255_SCALARBYTES` .

    :param s: Byte vector of length :obj:`crypto_core_ristretto255_NONREDUCEDSCALARBYTES`
        representing a scalar.

    In the example below, a large integer representing a scalar is reduced to
    a valid scalar:

    >>> x = bytes.fromhex('FF' * 32)
    >>> s = crypto_core_ristretto255_scalar_reduce(x)
    >>> p = crypto_core_ristretto255_random()
    >>> masked = crypto_scalarmult_ristretto255(s, p)
    >>> s_inv = crypto_core_ristretto255_scalar_invert(s)
    >>> unmasked = crypto_scalarmult_ristretto255(s_inv, masked)
    >>> unmasked == p
    True

    For this and other functions that operate on points, a descriptive exception
    is raised if an input is not valid:

    >>> try:
    ...     crypto_core_ristretto255_scalar_reduce(123)
    ... except TypeError as e:
    ...     str(e) == (
    ...         'scalar must be a bytes object of length ' +
    ...         str(crypto_core_ristretto255_SCALARBYTES)
    ...     )
    True
    >>> try:
    ...     crypto_core_ristretto255_scalar_reduce(bytes([0, 0 ,0]))
    ... except ValueError as e:
    ...     str(e) == (
    ...         'scalar must be a bytes object of length ' +
    ...         str(crypto_core_ristretto255_SCALARBYTES)
    ...     )
    True
    """
    well_typed = isinstance(s, bytes)
    if not well_typed or len(s) != crypto_core_ristretto255_SCALARBYTES:
        raise (ValueError if well_typed else TypeError)(
            'scalar must be a bytes object of length ' +
            str(crypto_core_ristretto255_SCALARBYTES)
        )

    r = _crypto_core_ristretto255_scalar_new()
    _sodium.crypto_core_ristretto255_scalar_reduce(r, s)
    return r.raw

def crypto_core_ristretto255_scalar_negate(s: bytes) -> bytes:
    """
    Return the additive inverse of the scalar ``s`` modulo ``L`` (*i.e.*,
    a scalar ``t`` such that ``s + t == 0`` modulo ``L``, where ``L`` is the
    order of the main subgroup). The input and output are each represented as
    a byte vector of length :obj:`crypto_core_ristretto255_SCALARBYTES`.

    :param s: Byte vector of length :obj:`crypto_core_ristretto255_SCALARBYTES`
        representing a scalar.

    All scalars have an additive inverse:

    >>> s = crypto_core_ristretto255_scalar_random()
    >>> t = crypto_core_ristretto255_scalar_negate(s)
    >>> zero = crypto_core_ristretto255_scalar_add(s, t)
    >>> s == crypto_core_ristretto255_scalar_add(s, zero)
    True
    """
    well_typed = isinstance(s, bytes)
    if not well_typed or len(s) != crypto_core_ristretto255_SCALARBYTES:
        raise (ValueError if well_typed else TypeError)(
            'scalar must be a bytes object of length ' +
            str(crypto_core_ristretto255_SCALARBYTES)
        ) # pragma: no cover

    r = _crypto_core_ristretto255_scalar_new()
    _sodium.crypto_core_ristretto255_scalar_negate(r, s)
    return r.raw

def crypto_core_ristretto255_scalar_complement(s: bytes) -> bytes:
    """
    Return the additive complement of the scalar ``s`` modulo ``L`` (*i.e.*,
    a scalar ``t`` such that ``s + t == 1`` modulo ``L``, where ``L`` is the
    order of the main subgroup). The input and output are each represented as
    a byte vector of length :obj:`crypto_core_ristretto255_SCALARBYTES`.

    :param s: Byte vector of length :obj:`crypto_core_ristretto255_SCALARBYTES`
        representing a scalar.

    All scalars have an additive complement:

    >>> s = crypto_core_ristretto255_scalar_random()
    >>> t = crypto_core_ristretto255_scalar_complement(s)
    >>> one = crypto_core_ristretto255_scalar_add(s, t)
    >>> p = crypto_core_ristretto255_random()
    >>> p == crypto_scalarmult_ristretto255(one, p)
    True
    """
    well_typed = isinstance(s, bytes)
    if not well_typed or len(s) != crypto_core_ristretto255_SCALARBYTES:
        raise (ValueError if well_typed else TypeError)(
            'scalar must be a bytes object of length ' +
            str(crypto_core_ristretto255_SCALARBYTES)
        ) # pragma: no cover

    r = _crypto_core_ristretto255_scalar_new()
    _sodium.crypto_core_ristretto255_scalar_complement(r, s)
    return r.raw

def crypto_core_ristretto255_scalar_invert(s: bytes) -> bytes:
    """
    Return the multiplicative inverse of the scalar ``s`` modulo ``L``
    (*i.e.*, an integer ``t`` such that ``s * t == 1`` modulo ``L``, where
    ``L`` is the order of the main subgroup). The input and output are each
    represented as a byte vector of length :obj:`crypto_core_ristretto255_SCALARBYTES`.

    :param s: Byte vector of length :obj:`crypto_core_ristretto255_SCALARBYTES`
        representing a scalar.

    All scalars have a multiplicative inverse:

    >>> s = crypto_core_ristretto255_scalar_random()
    >>> p = crypto_core_ristretto255_random()
    >>> masked = crypto_scalarmult_ristretto255(s, p)
    >>> s_inv = crypto_core_ristretto255_scalar_invert(s)
    >>> unmasked = crypto_scalarmult_ristretto255(s_inv, masked)
    >>> unmasked == p
    True

    If ``s`` is the zero scalar, an exception is raised.

    >>> crypto_core_ristretto255_scalar_invert(bytes([0] * 32))
    Traceback (most recent call last):
      ...
    ValueError: scalar must not be zero
    """
    well_typed = isinstance(s, bytes)
    if not well_typed or len(s) != crypto_core_ristretto255_SCALARBYTES:
        raise (ValueError if well_typed else TypeError)(
            'scalar must be a bytes object of length ' +
            str(crypto_core_ristretto255_SCALARBYTES)
        ) # pragma: no cover

    if sum(s) == 0:
        raise ValueError('scalar must not be zero')

    r = _crypto_core_ristretto255_scalar_new()
    _sodium.crypto_core_ristretto255_scalar_invert(r, s)
    return r.raw

def crypto_core_ristretto255_scalar_add(s: bytes, t: bytes) -> bytes:
    """
    Add two scalars ``s`` and ``t`` modulo ``L`` (where ``L`` is the order
    of the main subgroup) and return their scalar product (represented as
    a byte vector of length :obj:`crypto_core_ristretto255_SCALARBYTES`).

    :param s: Byte vector of length :obj:`crypto_core_ristretto255_SCALARBYTES`
        representing a scalar.
    :param t: Byte vector of length :obj:`crypto_core_ristretto255_SCALARBYTES`
        representing a scalar.

    Addition of scalars is commutative:

    >>> s1 = crypto_core_ristretto255_scalar_random()
    >>> s2 = crypto_core_ristretto255_scalar_random()
    >>> s12 = crypto_core_ristretto255_scalar_add(s1, s2)
    >>> s21 = crypto_core_ristretto255_scalar_add(s2, s1)
    >>> s12 == s21
    True
    """
    well_typed = isinstance(s, bytes)
    if not well_typed or len(s) != crypto_core_ristretto255_SCALARBYTES:
        raise (ValueError if well_typed else TypeError)(
            'each scalar must be a bytes object of length ' +
            str(crypto_core_ristretto255_SCALARBYTES)
        ) # pragma: no cover

    well_typed = isinstance(t, bytes)
    if not well_typed or len(t) != crypto_core_ristretto255_SCALARBYTES:
        raise (ValueError if well_typed else TypeError)(
            'each scalar must be a bytes object of length ' +
            str(crypto_core_ristretto255_SCALARBYTES)
        ) # pragma: no cover

    r = _crypto_core_ristretto255_scalar_new()
    _sodium.crypto_core_ristretto255_scalar_add(r, s, t)
    return r.raw

def crypto_core_ristretto255_scalar_sub(s: bytes, t: bytes) -> bytes:
    """
    Subtract a scalar ``t`` from a scalar ``s`` modulo ``L`` (where ``L`` is
    the order of the main subgroup) and return their difference (represented
    as a byte vector of length :obj:`crypto_core_ristretto255_SCALARBYTES`).

    :param s: Byte vector of length :obj:`crypto_core_ristretto255_SCALARBYTES`
        representing a scalar.
    :param t: Byte vector of length :obj:`crypto_core_ristretto255_SCALARBYTES`
        representing a scalar.

    Subtraction between scalars is the inverse of scalar addition:

    >>> s1 = crypto_core_ristretto255_scalar_random()
    >>> s2 = crypto_core_ristretto255_scalar_random()
    >>> s1_plus_s2 = crypto_core_ristretto255_scalar_add(s1, s2)
    >>> s1 == crypto_core_ristretto255_scalar_sub(s1_plus_s2, s2)
    True
    """
    well_typed = isinstance(s, bytes)
    if not isinstance(s, bytes) or len(s) != crypto_core_ristretto255_SCALARBYTES:
        raise (ValueError if well_typed else TypeError)(
            'each scalar must be a bytes object of length ' +
            str(crypto_core_ristretto255_SCALARBYTES)
        ) # pragma: no cover

    well_typed = isinstance(t, bytes)
    if not isinstance(t, bytes) or len(t) != crypto_core_ristretto255_SCALARBYTES:
        raise (ValueError if well_typed else TypeError)(
            'each scalar must be a bytes object of length ' +
            str(crypto_core_ristretto255_SCALARBYTES)
        ) # pragma: no cover

    r = _crypto_core_ristretto255_scalar_new()
    _sodium.crypto_core_ristretto255_scalar_sub(r, s, t)
    return r.raw

def crypto_core_ristretto255_scalar_mul(s: bytes, t: bytes) -> bytes:
    """
    Multiply two scalars ``s`` and ``t`` modulo ``L`` (where ``L`` is the
    order of the main subgroup) and return their scalar product (represented
    as a byte vector of length :obj:`crypto_core_ristretto255_SCALARBYTES`).

    :param s: Byte vector of length :obj:`crypto_core_ristretto255_SCALARBYTES`
        representing a scalar.
    :param t: Byte vector of length :obj:`crypto_core_ristretto255_SCALARBYTES`
        representing a scalar.

    Multiplication of two scalars is commutative:

    >>> s1 = crypto_core_ristretto255_scalar_random()
    >>> s2 = crypto_core_ristretto255_scalar_random()
    >>> s1s2 = crypto_core_ristretto255_scalar_mul(s1, s2)
    >>> s2s1 = crypto_core_ristretto255_scalar_mul(s2, s1)
    >>> s1s2 == s2s1
    True
    """
    well_typed = isinstance(s, bytes)
    if not isinstance(s, bytes) or len(s) != crypto_core_ristretto255_SCALARBYTES:
        raise (ValueError if well_typed else TypeError)(
            'each scalar must be a bytes object of length ' +
            str(crypto_core_ristretto255_SCALARBYTES)
        ) # pragma: no cover

    well_typed = isinstance(t, bytes)
    if not isinstance(t, bytes) or len(t) != crypto_core_ristretto255_SCALARBYTES:
        raise (ValueError if well_typed else TypeError)(
            'each scalar must be a bytes object of length ' +
            str(crypto_core_ristretto255_SCALARBYTES)
        ) # pragma: no cover

    r = _crypto_core_ristretto255_scalar_new()
    _sodium.crypto_core_ristretto255_scalar_mul(r, s, t)
    return r.raw

def crypto_scalarmult_ristretto255_base(s: bytes) -> bytes:
    """
    Compute and return the product (represented as a byte vector of length
    :obj:`crypto_scalarmult_ristretto255_BYTES`) of a standard group element
    and a scalar ``s``. 

    :param s: Byte vector of length :obj:`crypto_scalarmult_ristretto255_SCALARBYTES`
        representing a scalar.

    >>> s = crypto_core_ristretto255_scalar_random()
    >>> gs = crypto_scalarmult_ristretto255_base(s)
    >>> crypto_core_ristretto255_is_valid_point(gs)
    True
    """
    well_typed = isinstance(s, bytes)
    if not well_typed or len(s) != crypto_scalarmult_ristretto255_SCALARBYTES:
        raise (ValueError if well_typed else TypeError)(
            'scalar must be a bytes object of length ' +
            str(crypto_scalarmult_ristretto255_SCALARBYTES)
        ) # pragma: no cover

    q = _crypto_scalarmult_ristretto255_point_new()
    if _sodium.crypto_scalarmult_ristretto255_base(q, s) == -1:
        raise RuntimeError(
            'input cannot be larger than the size of the group and ' +
            'cannot yield the identity element when applied as an exponent'
        ) # pragma: no cover

    return q.raw

def crypto_scalarmult_ristretto255_base_allow_scalar_zero(s: bytes) -> bytes:
    """
    Compute and return the product (represented as a byte vector of length
    :obj:`crypto_scalarmult_ristretto255_BYTES`) of a standard group element
    and a scalar ``s``. Zero-valued scalars are permitted.

    :param s: Byte vector of length :obj:`crypto_scalarmult_ristretto255_SCALARBYTES`
        representing a scalar.

    >>> s = crypto_core_ristretto255_scalar_random()
    >>> gs = crypto_scalarmult_ristretto255_base_allow_scalar_zero(s)
    >>> crypto_core_ristretto255_is_valid_point(gs)
    True
    >>> crypto_scalarmult_ristretto255_base_allow_scalar_zero(
    ...     crypto_core_ristretto255_scalar_sub(s, s)
    ... ) == crypto_core_ristretto255_sub(gs, gs)
    True
    """
    well_typed = isinstance(s, bytes)
    if not well_typed or len(s) != crypto_scalarmult_ristretto255_SCALARBYTES:
        raise (ValueError if well_typed else TypeError)(
            'scalar must be a bytes object of length ' +
            str(crypto_scalarmult_ristretto255_SCALARBYTES)
        ) # pragma: no cover

    q = _crypto_scalarmult_ristretto255_point_new()

    # If the below returns ``-1``, then ``q`` remains cleared (``b'\0' * 32``).
    _sodium.crypto_scalarmult_ristretto255_base(q, s)
    return q.raw

def crypto_scalarmult_ristretto255(s: bytes, p: bytes) -> bytes:
    """
    Compute and return the product (represented as a byte vector of length
    :obj:`crypto_scalarmult_ristretto255_BYTES`) of a *clamped* integer ``s``
    and the provided point (*i.e.*, group element).

    :param s: Byte vector of length :obj:`crypto_scalarmult_ristretto255_SCALARBYTES`
        representing a scalar.
    :param p: Byte vector of length :obj:`crypto_scalarmult_ristretto255_BYTES`
        representing a valid point.

    The scalar is clamped, as done in the public key generation case,
    by setting to zero the bits in position ``[0, 1, 2, 255]`` and by
    setting to ``1`` the bit in position ``254``.

    Scalar multiplication is an invertible operation:

    >>> s = crypto_core_ristretto255_scalar_random()
    >>> p = crypto_core_ristretto255_random()
    >>> masked = crypto_scalarmult_ristretto255(s, p)
    >>> s_inv = crypto_core_ristretto255_scalar_invert(s)
    >>> unmasked = crypto_scalarmult_ristretto255(s_inv, masked)
    >>> unmasked == p
    True

    Multiplication by the zero scalar is not defined in the subgroup consisting
    of products of valid points and scalars:

    >>> p = crypto_core_ristretto255_random()
    >>> s = crypto_core_ristretto255_scalar_random()
    >>> t = crypto_core_ristretto255_scalar_negate(s)
    >>> zero = crypto_core_ristretto255_scalar_add(s, t)
    >>> try:
    ...     crypto_scalarmult_ristretto255(zero, p)
    ... except RuntimeError as e:
    ...     str(e) == (
    ...         'input cannot be larger than the size of the group and ' +
    ...         'cannot yield the identity element when applied as an exponent'
    ...     )
    True
    """
    well_typed = isinstance(s, bytes)
    if not well_typed or len(s) != crypto_scalarmult_ristretto255_SCALARBYTES:
        raise (ValueError if well_typed else TypeError)(
            'scalar must be a bytes object of length ' +
            str(crypto_scalarmult_ristretto255_SCALARBYTES)
        ) # pragma: no cover

    well_typed = isinstance(p, bytes)
    if not well_typed or len(p) != crypto_scalarmult_ristretto255_BYTES:
        raise (ValueError if well_typed else TypeError)(
            'point must be a bytes object of length ' +
            str(crypto_scalarmult_ristretto255_BYTES)
        ) # pragma: no cover

    q = _crypto_scalarmult_ristretto255_point_new()
    if _sodium.crypto_scalarmult_ristretto255(q, s, p) == -1:
        raise RuntimeError(
            'input cannot be larger than the size of the group and ' +
            'cannot yield the identity element when applied as an exponent'
        )

    return q.raw

@safe
def crypto_scalarmult_ristretto255_allow_scalar_zero(
        s: bytes, p: bytes
    ) -> bytes: # pragma: no cover # The decorator recompiles this function body.
    """
    Compute and return the product (represented as a byte vector of length
    :obj:`crypto_scalarmult_ristretto255_BYTES`) of a *clamped* integer
    ``s`` and the provided point (*i.e.*, group element).

    :param s: Byte vector of length :obj:`crypto_scalarmult_ristretto255_SCALARBYTES`
        representing a scalar.
    :param p: Byte vector of length :obj:`crypto_scalarmult_ristretto255_BYTES`
        representing a valid point.

    The scalar is clamped, as done in the public key generation case,
    by setting to zero the bits in position ``[0, 1, 2, 255]`` and by
    setting to ``1`` the bit in position ``254``. Zero-valued scalars
    are permitted.

    Scalar multiplication is an invertible operation:

    >>> s = crypto_core_ristretto255_scalar_random()
    >>> p = crypto_core_ristretto255_random()
    >>> masked = crypto_scalarmult_ristretto255_allow_scalar_zero(s, p)
    >>> s_inv = crypto_core_ristretto255_scalar_invert(s)
    >>> unmasked = crypto_scalarmult_ristretto255_allow_scalar_zero(s_inv, masked)
    >>> unmasked == p
    True

    Multiplication by the zero scalar is permitted:

    >>> zero_scalar, zero_point = bytes(32), bytes(32)
    >>> crypto_scalarmult_ristretto255_allow_scalar_zero(zero_scalar, p) == zero_point
    True

    While the scalar input can be zero, the provided point must be valid:

    >>> invalid_point = b'\1' * 32
    >>> crypto_scalarmult_ristretto255_allow_scalar_zero(zero_scalar, invalid_point)
    Traceback (most recent call last):
      ...
    TypeError: second input must represent a valid point
    """
    well_typed = isinstance(s, bytes)
    if not well_typed or len(s) != crypto_scalarmult_ristretto255_SCALARBYTES:
        raise (ValueError if well_typed else TypeError)(
            'scalar must be a bytes object of length ' +
            str(crypto_scalarmult_ristretto255_SCALARBYTES)
        ) # pragma: no cover

    well_typed = isinstance(p, bytes)
    if not well_typed or len(p) != crypto_scalarmult_ristretto255_BYTES:
        raise (ValueError if well_typed else TypeError)(
            'point must be a bytes object of length ' +
            str(crypto_scalarmult_ristretto255_BYTES)
        ) # pragma: no cover

    safe # pylint: disable=pointless-statement # Marker for ``barriers`` decorator ``safe``.
    if not crypto_core_ristretto255_is_valid_point(p):
        raise TypeError('second input must represent a valid point')

    q = _crypto_scalarmult_ristretto255_point_new()

    # If ``-1``, then ``q`` remains cleared (``b'\0' * 32``).
    _sodium.crypto_scalarmult_ristretto255(q, s, p)
    return q.raw

def _sodium_init() -> None:
    """
    Checks that libsodium is not already initialized, initializes it,
    and defines globals whose definitions depend on functions exported
    by libsodium.
    """
    if _sodium.sodium_init() == 1:
        raise RuntimeError('libsodium is already initialized') # pragma: no cover

    if not _sodium.sodium_init() == 1:
        raise RuntimeError('libsodium error during initialization') # pragma: no cover

    _sodium.ready = True

    # Define values of public and private globals.
    context = globals()
    context['crypto_scalarmult_ristretto255_BYTES'] = \
        _sodium.crypto_scalarmult_ristretto255_bytes()
    context['crypto_scalarmult_ristretto255_SCALARBYTES'] = \
        _sodium.crypto_scalarmult_ristretto255_scalarbytes()
    context['crypto_core_ristretto255_BYTES'] = \
        _sodium.crypto_core_ristretto255_bytes()
    context['crypto_core_ristretto255_HASHBYTES'] = \
        _sodium.crypto_core_ristretto255_hashbytes()
    context['crypto_core_ristretto255_NONREDUCEDSCALARBYTES'] = \
        _sodium.crypto_core_ristretto255_nonreducedscalarbytes()
    context['crypto_core_ristretto255_SCALARBYTES'] = \
        _sodium.crypto_core_ristretto255_scalarbytes()
    context['randombytes_SEEDBYTES'] = \
        _sodium.randombytes_seedbytes()

    context['_crypto_core_ristretto255_point_new'] = \
        ctypes.c_char * crypto_core_ristretto255_BYTES
    context['_crypto_core_ristretto255_scalar_new'] = \
        ctypes.c_char * crypto_core_ristretto255_SCALARBYTES
    context['_crypto_scalarmult_ristretto255_point_new'] = \
        ctypes.c_char * crypto_scalarmult_ristretto255_BYTES

# Check that libsodium is not already initialized and initialize it
# (unless documentation is being automatically generated).
if not os.environ.get('RBCL_SPHINX_AUTODOC_BUILD', None) == '1':
    _sodium_init()

if __name__ == '__main__':
    doctest.testmod() # pragma: no cover
