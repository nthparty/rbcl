"""
Python library that bundles `libsodium <https://github.com/jedisct1/libsodium>`__
and provides wrappers for its Ristretto group functions.

This library exports wrappers for all libsodium methods related to the Ristretto
group and random number generation, including all ``crypto_scalarmult_*`` methods
and ``randombytes*`` methods.
"""
from __future__ import annotations
from ctypes import c_char
import doctest
import pathlib
from barriers import barriers

try:
    VALIDATION_ENABLED = 'site-packages' not in str(pathlib.Path(__file__).resolve())
except NameError:
    VALIDATION_ENABLED = False
safe = barriers(VALIDATION_ENABLED) @ globals()

try:
    # Support for direct invocation in order to execute doctests.
    from _sodium import _sodium # pylint: disable=cyclic-import
except: # pylint: disable=bare-except # pragma: no cover
    from rbcl._sodium import _sodium # pylint: disable=cyclic-import

doctests_not_ready = not ((_sodium.ready is True) and (type(_sodium.ready) is type(True))) # pylint: disable=unidiomatic-typecheck
crypto_scalarmult_ristretto255_BYTES: int = \
    (32 if doctests_not_ready else None) or _sodium.crypto_scalarmult_ristretto255_bytes()
crypto_scalarmult_ristretto255_SCALARBYTES: int = \
    (32 if doctests_not_ready else None) or _sodium.crypto_scalarmult_ristretto255_scalarbytes()
crypto_core_ristretto255_BYTES: int = \
    (32 if doctests_not_ready else None) or _sodium.crypto_core_ristretto255_bytes()
crypto_core_ristretto255_HASHBYTES: int = \
    (64 if doctests_not_ready else None) or _sodium.crypto_core_ristretto255_hashbytes()
crypto_core_ristretto255_NONREDUCEDSCALARBYTES: int = \
    (64 if doctests_not_ready else None) or _sodium.crypto_core_ristretto255_nonreducedscalarbytes()
crypto_core_ristretto255_SCALARBYTES: int = \
    (32 if doctests_not_ready else None) or _sodium.crypto_core_ristretto255_scalarbytes()
randombytes_SEEDBYTES: int = \
    (32 if doctests_not_ready else None) or _sodium.randombytes_seedbytes()

crypto_core_ristretto255_point_new = c_char * crypto_core_ristretto255_BYTES
crypto_core_ristretto255_scalar_new = c_char * crypto_core_ristretto255_SCALARBYTES
crypto_scalarmult_ristretto255_point_new = c_char * crypto_scalarmult_ristretto255_BYTES
buf_new = lambda size : (c_char * size)() # pylint: disable=unnecessary-lambda-assignment

def crypto_core_ristretto255_is_valid_point(p):  # (const unsigned char *p);
    """
    Check if ``p`` represents a point on the ristretto255 curve, in canonical
    form, on the main subgroup, and that the point doesn't have a small order.

    >>> p = crypto_core_ristretto255_random()
    >>> crypto_core_ristretto255_is_valid_point(p)
    True

    :param p: a :py:data:`.crypto_core_ristretto255_BYTES` long bytes sequence
              representing a point on the ristretto255 curve
    :type p: bytes
    :return: point validity
    :rtype: bool
    """
    well_typed = isinstance(p, bytes)
    if not well_typed or len(p) != crypto_core_ristretto255_BYTES:
        raise (ValueError if well_typed else TypeError)(
            'point must be a bytes object of length ' +
            str(crypto_core_ristretto255_BYTES)
        ) # pragma: no cover

    rc = _sodium.crypto_core_ristretto255_is_valid_point(p)
    return rc == 1

def crypto_core_ristretto255_add(p, q):
    """
    Add two points on the ristretto255 curve.

    Example - Point addition commutes in L:

    >>> x = crypto_core_ristretto255_random()
    >>> y = crypto_core_ristretto255_from_hash(b'\x70'*64)
    >>> z1 = crypto_core_ristretto255_add(x, y)
    >>> z2 = crypto_core_ristretto255_add(y, x)
    >>> z1 == z2
    True

    :param p: a :py:data:`.crypto_core_ristretto255_BYTES` long bytes sequence
              representing a point on the ristretto255 curve
    :type p: bytes
    :param q: a :py:data:`.crypto_core_ristretto255_BYTES` long bytes sequence
              representing a point on the ristretto255 curve
    :type q: bytes
    :return: a point on the ristretto255 curve represented as
             a :py:data:`.crypto_core_ristretto255_BYTES` long bytes sequence
    :rtype: bytes
    """
    well_typed = isinstance(p, bytes)
    if not well_typed or len(p) != crypto_core_ristretto255_BYTES:
        raise (ValueError if well_typed else TypeError)(
            'first argument must be a bytes object of length ' +
            str(crypto_core_ristretto255_BYTES)
        ) # pragma: no cover

    well_typed = isinstance(q, bytes)
    if not well_typed or len(q) != crypto_core_ristretto255_BYTES:
        raise (ValueError if well_typed else TypeError)(
            'second argument must be a bytes object of length ' +
            str(crypto_core_ristretto255_BYTES)
        ) # pragma: no cover

    r = crypto_core_ristretto255_point_new()
    _sodium.crypto_core_ristretto255_add(r, p, q)
    return r.raw

def crypto_core_ristretto255_sub(p, q):
    """
    Subtract a point from another on the ristretto255 curve.

    Example - Point subtraction is the inverse of addition:

    >>> p = crypto_core_ristretto255_from_hash(b'\x70'*64)
    >>> mask = crypto_core_ristretto255_random()
    >>> masked = crypto_core_ristretto255_add(p, mask)
    >>> unmasked = crypto_core_ristretto255_sub(masked, mask)
    >>> p == unmasked
    True

    :param p: a :py:data:`.crypto_core_ristretto255_BYTES` long bytes sequence
              representing a point on the ristretto255 curve
    :type p: bytes
    :param q: a :py:data:`.crypto_core_ristretto255_BYTES` long bytes sequence
              representing a point on the ristretto255 curve
    :type q: bytes
    :return: a point on the ristretto255 curve represented as
             a :py:data:`.crypto_core_ristretto255_BYTES` long bytes sequence
    :rtype: bytes
    """
    well_typed = isinstance(p, bytes)
    if not well_typed or len(p) != crypto_core_ristretto255_BYTES:
        raise (ValueError if well_typed else TypeError)(
            'first argument must be a bytes object of length ' +
            str(crypto_core_ristretto255_BYTES)
        ) # pragma: no cover

    well_typed = isinstance(q, bytes)
    if not well_typed or len(q) != crypto_core_ristretto255_BYTES:
        raise (ValueError if well_typed else TypeError)(
            'second argument must be a bytes object of length ' +
            str(crypto_core_ristretto255_BYTES)
        ) # pragma: no cover

    r = crypto_core_ristretto255_point_new()
    _sodium.crypto_core_ristretto255_sub(r, p, q)
    return r.raw

def crypto_core_ristretto255_from_hash(h):
    """
    Map a 64-byte vector ``h`` (usually the output of a hash function) to a ristretto255
    group element (a point), and output its representation in bytes.

    >>> p = crypto_core_ristretto255_from_hash(b'\x70'*64)
    >>> crypto_core_ristretto255_is_valid_point(p)
    True

    :param h: a :py:data:`.crypto_core_ristretto255_HASHBYTES`
              long bytes sequence ideally representing a hash digest
    :type h: bytes

    :return: an integer represented as a
              :py:data:`.crypto_core_ristretto255_BYTES` long bytes sequence
    :rtype: bytes
    """
    well_typed = isinstance(h, bytes)
    if not well_typed or len(h) != crypto_core_ristretto255_HASHBYTES:
        raise (ValueError if well_typed else TypeError)(
            'each integer must be a bytes object of length ' +
            str(crypto_core_ristretto255_HASHBYTES)
        ) # pragma: no cover

    r = crypto_core_ristretto255_point_new()
    _sodium.crypto_core_ristretto255_from_hash(r, h)
    return r.raw

def crypto_core_ristretto255_random():
    """
    Returns a ristretto255 group element (point).

    >>> p = crypto_core_ristretto255_random()
    >>> crypto_core_ristretto255_is_valid_point(p)
    True

    :return: an integer represented as a
              :py:data:`.crypto_core_ristretto255_BYTES` long bytes sequence
    :rtype: bytes
    """
    r = crypto_core_ristretto255_scalar_new()
    _sodium.crypto_core_ristretto255_random(r)
    return r.raw

def crypto_core_ristretto255_scalar_random():  # (unsigned char *r);
    """
    Returns a :py:data:`.crypto_core_ristretto255_SCALARBYTES` byte long
    representation of the scalar in the ``[0..L]`` interval, ``L`` being the
    order of the group ``(2^252 + 27742317777372353535851937790883648493)``.

    Example - All valid scalars have an inverse:

    >>> s = crypto_core_ristretto255_scalar_random()
    >>> p = crypto_core_ristretto255_random()
    >>> masked = crypto_scalarmult_ristretto255(s, p)
    >>> s_inv = crypto_core_ristretto255_scalar_invert(s)
    >>> unmasked = crypto_scalarmult_ristretto255(s_inv, masked)
    >>> unmasked == p
    True

    :return: an integer represented as a
              :py:data:`.crypto_core_ristretto255_SCALARBYTES` long bytes sequence
    :rtype: bytes
    """
    r = crypto_core_ristretto255_scalar_new()
    _sodium.crypto_core_ristretto255_scalar_random(r)
    return r.raw

def crypto_core_ristretto255_scalar_invert(p):
    """
    Return the multiplicative inverse of integer ``s`` modulo ``L``,
    i.e an integer ``i`` such that ``s * i = 1 (mod L)``, where ``L``
    is the order of the main subgroup.

    Example - All scalars have a multiplicative inverse:

    >>> s = crypto_core_ristretto255_scalar_random()
    >>> p = crypto_core_ristretto255_random()
    >>> masked = crypto_scalarmult_ristretto255(s, p)
    >>> s_inv = crypto_core_ristretto255_scalar_invert(s)
    >>> unmasked = crypto_scalarmult_ristretto255(s_inv, masked)
    >>> unmasked == p
    True

    Raises a ``RuntimeError`` if ``s`` is the integer zero.

    :param s: a :py:data:`.crypto_core_ristretto255_SCALARBYTES`
              long bytes sequence representing an integer
    :type s: bytes
    :return: an integer represented as a
              :py:data:`.crypto_core_ristretto255_SCALARBYTES` long bytes sequence
    :rtype: bytes
    """
    well_typed = isinstance(p, bytes)
    if not well_typed or len(p) != crypto_core_ristretto255_SCALARBYTES:
        raise (ValueError if well_typed else TypeError)(
            'each integer must be a bytes object of length ' +
            str(crypto_core_ristretto255_SCALARBYTES)
        ) # pragma: no cover

    r = crypto_core_ristretto255_scalar_new()
    _sodium.crypto_core_ristretto255_scalar_invert(r, p)
    return r.raw

def crypto_core_ristretto255_scalar_negate(p):
    """
    Return the integer ``n`` such that ``s + n = 0 (mod L)``, where ``L``
    is the order of the main subgroup.

    Example - All scalars have an additive inverse:

    >>> s = crypto_core_ristretto255_scalar_random()
    >>> s_inv = crypto_core_ristretto255_scalar_negate(s)
    >>> zero = crypto_core_ristretto255_scalar_add(s, s_inv)
    >>> s == crypto_core_ristretto255_scalar_add(s, zero)
    True

    Example - Multiplication by zero is not defined in the subgroup {point * s | scalars s}:

    >>> p = crypto_core_ristretto255_random()
    >>> try:
    ...     zero_p = crypto_scalarmult_ristretto255(zero, p)
    ... except RuntimeError as e:
    ...     str(e) == 'input cannot be larger than the size of the group and ' + \
                      'cannot yield the identity element when applied as an exponent'
    True

    :param s: a :py:data:`.crypto_core_ristretto255_SCALARBYTES`
              long bytes sequence representing an integer
    :type s: bytes
    :return: an integer represented as a
              :py:data:`.crypto_core_ristretto255_SCALARBYTES` long bytes sequence
    :rtype: bytes
    """
    well_typed = isinstance(p, bytes)
    if not well_typed or len(p) != crypto_core_ristretto255_SCALARBYTES:
        raise (ValueError if well_typed else TypeError)(
            'each integer must be a bytes object of length ' +
            str(crypto_core_ristretto255_SCALARBYTES)
        ) # pragma: no cover

    r = crypto_core_ristretto255_scalar_new()
    _sodium.crypto_core_ristretto255_scalar_negate(r, p)
    return r.raw

def crypto_core_ristretto255_scalar_complement(p):
    """
    Return the complement of integer ``s`` modulo ``L``, i.e. an integer
    ``c`` such that ``s + c = 1 (mod L)``, where ``L`` is the order of
    the main subgroup.

    Example - All scalars have an additive complement:

    >>> s = crypto_core_ristretto255_scalar_random()
    >>> s_comp = crypto_core_ristretto255_scalar_complement(s)
    >>> one = crypto_core_ristretto255_scalar_add(s, s_comp)
    >>> p = crypto_core_ristretto255_random()
    >>> p == crypto_scalarmult_ristretto255(one, p)
    True

    :param s: a :py:data:`.crypto_core_ristretto255_SCALARBYTES`
              long bytes sequence representing an integer
    :type s: bytes
    :return: an integer represented as a
              :py:data:`.crypto_core_ristretto255_SCALARBYTES` long bytes sequence
    :rtype: bytes
    """
    well_typed = isinstance(p, bytes)
    if not well_typed or len(p) != crypto_core_ristretto255_SCALARBYTES:
        raise (ValueError if well_typed else TypeError)(
            'each integer must be a bytes object of length ' +
            str(crypto_core_ristretto255_SCALARBYTES)
        ) # pragma: no cover

    r = crypto_core_ristretto255_scalar_new()
    _sodium.crypto_core_ristretto255_scalar_complement(r, p)
    return r.raw

def crypto_core_ristretto255_scalar_add(p, q):
    """
    Add integers ``p`` and ``q`` modulo ``L``, where ``L`` is the order of
    the main subgroup.

    Example - Addition of two scalars is commutative:

    >>> s1 = crypto_core_ristretto255_scalar_random()
    >>> s2 = crypto_core_ristretto255_scalar_random()
    >>> s12 = crypto_core_ristretto255_scalar_add(s1, s2)
    >>> s21 = crypto_core_ristretto255_scalar_add(s2, s1)
    >>> s12 == s21
    True

    :param p: a :py:data:`.crypto_core_ristretto255_SCALARBYTES`
              long bytes sequence representing an integer
    :type p: bytes
    :param q: a :py:data:`.crypto_core_ristretto255_SCALARBYTES`
              long bytes sequence representing an integer
    :type q: bytes
    :return: an integer represented as a
              :py:data:`.crypto_core_ristretto255_SCALARBYTES` long bytes sequence
    :rtype: bytes
    """
    well_typed = isinstance(p, bytes)
    if not well_typed or len(p) != crypto_core_ristretto255_SCALARBYTES:
        raise (ValueError if well_typed else TypeError)(
            'first argument must be a bytes object of length ' +
            str(crypto_core_ristretto255_SCALARBYTES)
        ) # pragma: no cover

    well_typed = isinstance(q, bytes)
    if not well_typed or len(q) != crypto_core_ristretto255_SCALARBYTES:
        raise (ValueError if well_typed else TypeError)(
            'second argument must be a bytes object of length ' +
            str(crypto_core_ristretto255_SCALARBYTES)
        ) # pragma: no cover

    r = crypto_core_ristretto255_scalar_new()
    _sodium.crypto_core_ristretto255_scalar_add(r, p, q)
    return r.raw

def crypto_core_ristretto255_scalar_sub(p, q):
    """
    Subtract integers ``p`` and ``q`` modulo ``L``, where ``L`` is the
    order of the main subgroup.

    Example - Subtraction is the inverse of addition:

    >>> s1 = crypto_core_ristretto255_scalar_random()
    >>> s2 = crypto_core_ristretto255_scalar_random()
    >>> s1_plus_s2 = crypto_core_ristretto255_scalar_add(s1, s2)
    >>> s1 == crypto_core_ristretto255_scalar_sub(s1_plus_s2, s2)
    True

    :param p: a :py:data:`.crypto_core_ristretto255_SCALARBYTES`
              long bytes sequence representing an integer
    :type p: bytes
    :param q: a :py:data:`.crypto_core_ristretto255_SCALARBYTES`
              long bytes sequence representing an integer
    :type q: bytes
    :return: an integer represented as a
              :py:data:`.crypto_core_ristretto255_SCALARBYTES` long bytes sequence
    :rtype: bytes
    """
    well_typed = isinstance(p, bytes)
    if not isinstance(p, bytes) or len(p) != crypto_core_ristretto255_SCALARBYTES:
        raise (ValueError if well_typed else TypeError)(
            'first argument must be a bytes object of length ' +
            str(crypto_core_ristretto255_SCALARBYTES)
        ) # pragma: no cover

    well_typed = isinstance(q, bytes)
    if not isinstance(q, bytes) or len(q) != crypto_core_ristretto255_SCALARBYTES:
        raise (ValueError if well_typed else TypeError)(
            'second argument must be a bytes object of length ' +
            str(crypto_core_ristretto255_SCALARBYTES)
        ) # pragma: no cover

    r = crypto_core_ristretto255_scalar_new()
    _sodium.crypto_core_ristretto255_scalar_sub(r, p, q)
    return r.raw

def crypto_core_ristretto255_scalar_mul(p, q):
    """
    Multiply integers ``p`` and ``q`` modulo ``L``, where ``L`` is the
    order of the main subgroup.

    Example - Multiplication of two scalars is commutative:

    >>> s1 = crypto_core_ristretto255_scalar_random()
    >>> s2 = crypto_core_ristretto255_scalar_random()
    >>> s1s2 = crypto_core_ristretto255_scalar_mul(s1, s2)
    >>> s2s1 = crypto_core_ristretto255_scalar_mul(s2, s1)
    >>> s1s2 == s2s1
    True

    :param p: a :py:data:`.crypto_core_ristretto255_SCALARBYTES`
              long bytes sequence representing an integer
    :type p: bytes
    :param q: a :py:data:`.crypto_core_ristretto255_SCALARBYTES`
              long bytes sequence representing an integer
    :type q: bytes
    :return: an integer represented as a
              :py:data:`.crypto_core_ristretto255_SCALARBYTES` long bytes sequence
    :rtype: bytes
    """
    well_typed = isinstance(p, bytes)
    if not isinstance(p, bytes) or len(p) != crypto_core_ristretto255_SCALARBYTES:
        raise (ValueError if well_typed else TypeError)(
            'each integer must be a bytes object of length ' +
            str(crypto_core_ristretto255_SCALARBYTES)
        ) # pragma: no cover

    well_typed = isinstance(q, bytes)
    if not isinstance(q, bytes) or len(q) != crypto_core_ristretto255_SCALARBYTES:
        raise (ValueError if well_typed else TypeError)(
            'each integer must be a bytes object of length ' +
            str(crypto_core_ristretto255_SCALARBYTES)
        ) # pragma: no cover

    r = crypto_core_ristretto255_scalar_new()
    _sodium.crypto_core_ristretto255_scalar_mul(r, p, q)
    return r.raw

def crypto_core_ristretto255_scalar_reduce(p):
    """
    Reduce integer ``s`` to ``s`` modulo ``L``, where ``L`` is the order
    of the main subgroup.

    Example - Reduce a large value to a valid scalar:

    >>> x = bytes.fromhex('FF'*32)
    >>> s = crypto_core_ristretto255_scalar_reduce(x)
    >>> p = crypto_core_ristretto255_random()
    >>> masked = crypto_scalarmult_ristretto255(s, p)
    >>> s_inv = crypto_core_ristretto255_scalar_invert(s)
    >>> unmasked = crypto_scalarmult_ristretto255(s_inv, masked)
    >>> unmasked == p
    True

    :param s: a :py:data:`.crypto_core_ristretto255_NONREDUCEDSCALARBYTES`
              long bytes sequence representing an integer
    :type s: bytes
    :return: an integer represented as a
              :py:data:`.crypto_core_ristretto255_SCALARBYTES` long bytes sequence
    :rtype: bytes
    """
    well_typed = isinstance(p, bytes)
    if not well_typed or len(p) != crypto_core_ristretto255_SCALARBYTES:
        raise (ValueError if well_typed else TypeError)(
            'each integer must be a bytes object of length ' +
            str(crypto_core_ristretto255_SCALARBYTES)
        ) # pragma: no cover

    r = crypto_core_ristretto255_scalar_new()
    _sodium.crypto_core_ristretto255_scalar_reduce(r, p)
    return r.raw

def crypto_scalarmult_ristretto255_base(n):
    """
    Computes and returns the scalar product of a standard group element and an
    integer ``n`` on the ristretto255 curve.

    >>> s = crypto_core_ristretto255_scalar_random()
    >>> gs = crypto_scalarmult_ristretto255_base(s)
    >>> crypto_core_ristretto255_is_valid_point(gs)
    True

    :param n: a :py:data:`.crypto_scalarmult_ristretto255_SCALARBYTES` long bytes
              sequence representing a scalar
    :type n: bytes
    :return: a point on the ristretto255 curve, represented as a
             :py:data:`.crypto_scalarmult_ristretto255_BYTES` long bytes sequence
    :rtype: bytes
    """
    well_typed = isinstance(n, bytes)
    if not well_typed or len(n) != crypto_scalarmult_ristretto255_SCALARBYTES:
        raise (ValueError if well_typed else TypeError)(
            'input must be a bytes object of length ' +
            str(crypto_scalarmult_ristretto255_SCALARBYTES)
        ) # pragma: no cover

    q = crypto_scalarmult_ristretto255_point_new()
    if _sodium.crypto_scalarmult_ristretto255_base(q, n) == -1:
        raise RuntimeError(
            'input cannot be larger than the size of the group and ' +
            'cannot yield the identity element when applied as an exponent'
        ) # pragma: no cover

    return q.raw

def crypto_scalarmult_ristretto255_base_allow_scalar_zero(n):
    """
    Computes and returns the scalar product of a standard group element and an
    integer ``n`` on the ristretto255 curve.  Zero-valued scalars are allowed.

    >>> s = crypto_core_ristretto255_scalar_random()
    >>> gs = crypto_scalarmult_ristretto255_base_allow_scalar_zero(s)
    >>> crypto_core_ristretto255_is_valid_point(gs)
    True
    >>> crypto_scalarmult_ristretto255_base_allow_scalar_zero(
    ...   crypto_core_ristretto255_scalar_sub(s, s)
    ... ) == crypto_core_ristretto255_sub(gs, gs)
    True

    :param n: a :py:data:`.crypto_scalarmult_ristretto255_SCALARBYTES` long bytes
              sequence representing a scalar
    :type n: bytes
    :return: a point on the ristretto255 curve, represented as a
             :py:data:`.crypto_scalarmult_ristretto255_BYTES` long bytes sequence
    :rtype: bytes
    """
    well_typed = isinstance(n, bytes)
    if not well_typed or len(n) != crypto_scalarmult_ristretto255_SCALARBYTES:
        raise (ValueError if well_typed else TypeError)(
            'input must be a bytes object of length ' +
            str(crypto_scalarmult_ristretto255_SCALARBYTES)
        ) # pragma: no cover

    q = crypto_scalarmult_ristretto255_point_new()

    # If ``-1``, then ``q`` remains cleared (``b'\0'*32``).
    _sodium.crypto_scalarmult_ristretto255_base(q, n)
    return q.raw

def crypto_scalarmult_ristretto255(n, p):
    """
    Computes and returns the scalar product of a *clamped* integer ``n``
    and the given group element on the ristretto255 curve.
    The scalar is clamped, as done in the public key generation case,
    by setting to zero the bits in position [0, 1, 2, 255] and setting
    to one the bit in position 254.

    Example - Scalar multiplication is an invertible operation:

    >>> s = crypto_core_ristretto255_scalar_random()
    >>> p = crypto_core_ristretto255_random()
    >>> masked = crypto_scalarmult_ristretto255(s, p)
    >>> s_inv = crypto_core_ristretto255_scalar_invert(s)
    >>> unmasked = crypto_scalarmult_ristretto255(s_inv, masked)
    >>> unmasked == p
    True

    :param n: a :py:data:`.crypto_scalarmult_ristretto255_SCALARBYTES` long bytes
              sequence representing a scalar
    :type n: bytes
    :param p: a :py:data:`.crypto_scalarmult_ristretto255_BYTES` long bytes sequence
              representing a point on the ristretto255 curve
    :type p: bytes
    :return: a point on the ristretto255 curve, represented as a
             :py:data:`.crypto_scalarmult_ristretto255_BYTES` long bytes sequence
    :rtype: bytes
    """
    well_typed = isinstance(n, bytes)
    if not well_typed or len(n) != crypto_scalarmult_ristretto255_SCALARBYTES:
        raise (ValueError if well_typed else TypeError)(
            'input must be a bytes object of length ' +
            str(crypto_scalarmult_ristretto255_SCALARBYTES)
        ) # pragma: no cover

    well_typed = isinstance(p, bytes)
    if not well_typed or len(p) != crypto_scalarmult_ristretto255_BYTES:
        raise (ValueError if well_typed else TypeError)(
            'input must be a bytes object of length ' +
            str(crypto_scalarmult_ristretto255_BYTES)
        ) # pragma: no cover

    q = crypto_scalarmult_ristretto255_point_new()
    if _sodium.crypto_scalarmult_ristretto255(q, n, p) == -1:
        raise RuntimeError(
            'input cannot be larger than the size of the group and ' +
            'cannot yield the identity element when applied as an exponent'
        )
    return q.raw

@safe
def crypto_scalarmult_ristretto255_allow_scalar_zero(
        n, p
    ): # pragma: no cover # The decorator recompiles this function body.
    """
    Computes and returns the scalar product of a *clamped* integer ``n``
    and the given group element on the ristretto255 curve.
    The scalar is clamped, as done in the public key generation case,
    by setting to zero the bits in position [0, 1, 2, 255] and setting
    to one the bit in position 254.  Zero-valued scalars are allowed.

    Example - Scalar multiplication is an invertible operation:

    >>> s = crypto_core_ristretto255_scalar_random()
    >>> p = crypto_core_ristretto255_random()
    >>> masked = crypto_scalarmult_ristretto255_allow_scalar_zero(s, p)
    >>> s_inv = crypto_core_ristretto255_scalar_invert(s)
    >>> unmasked = crypto_scalarmult_ristretto255_allow_scalar_zero(s_inv, masked)
    >>> unmasked == p
    True

    Example - Multiplication by zero is allowed:

    >>> zero_scalar, zero_point = bytes(32), bytes(32)
    >>> crypto_scalarmult_ristretto255_allow_scalar_zero(zero_scalar, p) == zero_point
    True

    Example - The scalar being zero does not raise an error, but the point being invalid does:

    >>> invalid_point = b'\1'*32
    >>> crypto_scalarmult_ristretto255_allow_scalar_zero(zero_scalar, invalid_point)
    Traceback (most recent call last):
      ...
    TypeError: second input must represent a valid point

    :param n: a :py:data:`.crypto_scalarmult_ristretto255_SCALARBYTES` long bytes
              sequence representing a scalar
    :type n: bytes
    :param p: a :py:data:`.crypto_scalarmult_ristretto255_BYTES` long bytes sequence
              representing a point on the ristretto255 curve
    :type p: bytes
    :return: a point on the ristretto255 curve, represented as a
             :py:data:`.crypto_scalarmult_ristretto255_BYTES` long bytes sequence
    :rtype: bytes
    """
    well_typed = isinstance(n, bytes)
    if not well_typed or len(n) != crypto_scalarmult_ristretto255_SCALARBYTES:
        raise (ValueError if well_typed else TypeError)(
            'input must be a bytes object of length ' +
            str(crypto_scalarmult_ristretto255_SCALARBYTES)
        ) # pragma: no cover

    well_typed = isinstance(p, bytes)
    if not well_typed or len(p) != crypto_scalarmult_ristretto255_BYTES:
        raise (ValueError if well_typed else TypeError)(
            'input must be a bytes object of length ' +
            str(crypto_scalarmult_ristretto255_BYTES)
        ) # pragma: no cover

    safe # pylint: disable=pointless-statement # Marker for ``barriers`` decorator ``safe``.
    if not crypto_core_ristretto255_is_valid_point(p):
        raise TypeError('second input must represent a valid point')

    q = crypto_scalarmult_ristretto255_point_new()

    # If ``-1``, then ``q`` remains cleared (``b'\0'*32``).
    _sodium.crypto_scalarmult_ristretto255(q, n, p)
    return q.raw

def randombytes(size):
    """
    Returns ``size`` number of random bytes from a cryptographically secure
    random source.

    >>> r1 = randombytes(14)
    >>> r2 = randombytes(14)
    >>> r1 == r2  # 2^42 chance of one-off event (i.e. equality)
    False

    :param size: int
    :rtype: bytes
    """
    buf = buf_new(size)
    _sodium.randombytes(buf, size)
    return buf.raw

def randombytes_buf_deterministic(size, seed):
    """
    Returns ``size`` number of deterministically generated pseudorandom bytes
    from a seed

    Example - Get the first 32 bytes from a stream seeded by 0x7070...70:

    >>> r1 = randombytes_buf_deterministic(32, b'\x70'*32)
    >>> r2 = randombytes_buf_deterministic(40, b'\x70'*32)
    >>> r1 == r2[:32]
    True

    :param size: int
    :param seed: bytes
    :rtype: bytes
    """
    if len(seed) != randombytes_SEEDBYTES:
        raise ValueError('seed must be of length 32')

    buf = buf_new(size)
    _sodium.randombytes_buf_deterministic(buf, size, seed)
    return buf.raw

# Initializes sodium, picking the best implementations available for this
# machine.

def _sodium_init():
    if _sodium.sodium_init() == 1:
        raise RuntimeError('libsodium is already initialized') # pragma: no cover

    if not _sodium.sodium_init() == 1 and not doctests_not_ready:
        raise RuntimeError('libsodium error during initialization') # pragma: no cover

    _sodium.ready = True

_sodium_init()

if __name__ == '__main__':
    doctest.testmod() # pragma: no cover
