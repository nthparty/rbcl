"""
Python library that provides wrappers around the Ristretto group operations in libsodium.

This library exports all libsodium methods related to the Ristretto group or RNG, including
all `crypto_scalarmult*` methods and the `randombytes*` methods.
"""
from __future__ import annotations
import doctest

try:
    from rbcl import _sodium
except: # pylint: disable=W0702 # pragma: no cover
    # Support for direct invocation in order to execute doctests.
    import _sodium

crypto_scalarmult_ristretto255_BYTES: int = \
    _sodium.lib.crypto_scalarmult_ristretto255_bytes()
crypto_scalarmult_ristretto255_SCALARBYTES: int = \
    _sodium.lib.crypto_scalarmult_ristretto255_scalarbytes()
crypto_core_ristretto255_BYTES: int = \
    _sodium.lib.crypto_core_ristretto255_bytes()
crypto_core_ristretto255_HASHBYTES: int = \
    _sodium.lib.crypto_core_ristretto255_hashbytes()
crypto_core_ristretto255_NONREDUCEDSCALARBYTES: int = \
    _sodium.lib.crypto_core_ristretto255_nonreducedscalarbytes()
crypto_core_ristretto255_SCALARBYTES: int = \
    _sodium.lib.crypto_core_ristretto255_scalarbytes()
randombytes_SEEDBYTES: int = \
    _sodium.lib.randombytes_seedbytes()


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
    if not isinstance(p, bytes) or len(p) != crypto_core_ristretto255_BYTES:
        raise TypeError(
            "Point must be a " + str(crypto_core_ristretto255_BYTES) +
            "long bytes sequence"
        )  # pragma: no cover

    rc = _sodium.lib.crypto_core_ristretto255_is_valid_point(p)
    return rc == 1


# (unsigned char *r, const unsigned char *p, const unsigned char *q);
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
    if not isinstance(p, bytes) or len(p) != crypto_core_ristretto255_BYTES\
       or not isinstance(q, bytes) or len(q) != crypto_core_ristretto255_BYTES:
        raise TypeError(
            f"Each integer must be a {crypto_core_ristretto255_BYTES} long bytes sequence"
        )  # pragma: no cover

    r = _sodium.ffi.new("unsigned char[]", crypto_core_ristretto255_BYTES)

    _sodium.lib.crypto_core_ristretto255_add(r, p, q)

    return _sodium.ffi.buffer(r, crypto_core_ristretto255_BYTES)[:]


# (unsigned char *r, const unsigned char *p, const unsigned char *q);
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
    if not isinstance(p, bytes) or len(p) != crypto_core_ristretto255_BYTES\
       or not isinstance(q, bytes) or len(q) != crypto_core_ristretto255_BYTES:
        raise TypeError(
            f"Each integer must be a {crypto_core_ristretto255_BYTES} long bytes sequence"
        )  # pragma: no cover

    r = _sodium.ffi.new("unsigned char[]", crypto_core_ristretto255_BYTES)

    _sodium.lib.crypto_core_ristretto255_sub(r, p, q)

    return _sodium.ffi.buffer(r, crypto_core_ristretto255_BYTES)[:]


# (unsigned char *p, const unsigned char *r);
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
    if not isinstance(h, bytes) or len(
            h) != crypto_core_ristretto255_HASHBYTES:
        raise TypeError(
            f"Each integer must be a {crypto_core_ristretto255_HASHBYTES} long bytes sequence"
        )  # pragma: no cover

    r = _sodium.ffi.new("unsigned char[]", crypto_core_ristretto255_BYTES)

    _sodium.lib.crypto_core_ristretto255_from_hash(r, h)

    return _sodium.ffi.buffer(r, crypto_core_ristretto255_BYTES)[:]


def crypto_core_ristretto255_random():  # (unsigned char *p);
    """
    Returns a ristretto255 group element (point).

    >>> p = crypto_core_ristretto255_random()
    >>> crypto_core_ristretto255_is_valid_point(p)
    True

    :return: an integer represented as a
              :py:data:`.crypto_core_ristretto255_BYTES` long bytes sequence
    :rtype: bytes
    """

    r = _sodium.ffi.new(
        "unsigned char[]",
        crypto_core_ristretto255_SCALARBYTES)

    _sodium.lib.crypto_core_ristretto255_random(r)

    return _sodium.ffi.buffer(r, crypto_core_ristretto255_SCALARBYTES)[:]


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

    r = _sodium.ffi.new(
        "unsigned char[]",
        crypto_core_ristretto255_SCALARBYTES)

    _sodium.lib.crypto_core_ristretto255_scalar_random(r)

    return _sodium.ffi.buffer(r, crypto_core_ristretto255_SCALARBYTES)[:]


# (unsigned char *recip, const unsigned char *s);
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
    if not isinstance(p, bytes) or len(
            p) != crypto_core_ristretto255_SCALARBYTES:
        raise TypeError(
            f"Each integer must be a {crypto_core_ristretto255_SCALARBYTES} long bytes sequence"
        )  # pragma: no cover

    r = _sodium.ffi.new(
        "unsigned char[]",
        crypto_core_ristretto255_SCALARBYTES)

    _sodium.lib.crypto_core_ristretto255_scalar_invert(r, p)

    return _sodium.ffi.buffer(r, crypto_core_ristretto255_SCALARBYTES)[:]


# (unsigned char *neg, const unsigned char *s);
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
    ...     str(e) == "`n` cannot be larger than the size of "\
                    + "the group or p^n is the identity element"
    True

    :param s: a :py:data:`.crypto_core_ristretto255_SCALARBYTES`
              long bytes sequence representing an integer
    :type s: bytes
    :return: an integer represented as a
              :py:data:`.crypto_core_ristretto255_SCALARBYTES` long bytes sequence
    :rtype: bytes
    """
    if not isinstance(p, bytes) or len(
            p) != crypto_core_ristretto255_SCALARBYTES:
        raise TypeError(
            f"Each integer must be a {crypto_core_ristretto255_SCALARBYTES} long bytes sequence"
        )  # pragma: no cover

    r = _sodium.ffi.new(
        "unsigned char[]",
        crypto_core_ristretto255_SCALARBYTES)

    _sodium.lib.crypto_core_ristretto255_scalar_negate(r, p)

    return _sodium.ffi.buffer(r, crypto_core_ristretto255_SCALARBYTES)[:]


# (unsigned char *comp, const unsigned char *s);
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
    if not isinstance(p, bytes) or len(
            p) != crypto_core_ristretto255_SCALARBYTES:
        raise TypeError(
            f"Each integer must be a {crypto_core_ristretto255_SCALARBYTES} long bytes sequence"
        )  # pragma: no cover

    r = _sodium.ffi.new(
        "unsigned char[]",
        crypto_core_ristretto255_SCALARBYTES)

    _sodium.lib.crypto_core_ristretto255_scalar_complement(r, p)

    return _sodium.ffi.buffer(r, crypto_core_ristretto255_SCALARBYTES)[:]


# (unsigned char *z, const unsigned char *x, const unsigned char *y);
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
    if not isinstance(
            p, bytes) or len(p) != crypto_core_ristretto255_SCALARBYTES or not isinstance(
            q, bytes) or len(q) != crypto_core_ristretto255_SCALARBYTES:
        raise TypeError(
            f"Each integer must be a {crypto_core_ristretto255_SCALARBYTES} long bytes sequence"
        )  # pragma: no cover

    r = _sodium.ffi.new(
        "unsigned char[]",
        crypto_core_ristretto255_SCALARBYTES)

    _sodium.lib.crypto_core_ristretto255_scalar_add(r, p, q)

    return _sodium.ffi.buffer(r, crypto_core_ristretto255_SCALARBYTES)[:]


# (unsigned char *z, const unsigned char *x, const unsigned char *y);
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
    if not isinstance(
            p, bytes) or len(p) != crypto_core_ristretto255_SCALARBYTES or not isinstance(
            q, bytes) or len(q) != crypto_core_ristretto255_SCALARBYTES:
        raise TypeError(
            f"Each integer must be a {crypto_core_ristretto255_SCALARBYTES} long bytes sequence"
        )  # pragma: no cover

    r = _sodium.ffi.new(
        "unsigned char[]",
        crypto_core_ristretto255_SCALARBYTES)

    _sodium.lib.crypto_core_ristretto255_scalar_sub(r, p, q)

    return _sodium.ffi.buffer(r, crypto_core_ristretto255_SCALARBYTES)[:]


# (unsigned char *z, const unsigned char *x, const unsigned char *y);
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
    if not isinstance(
            p, bytes) or len(p) != crypto_core_ristretto255_SCALARBYTES or not isinstance(
            q, bytes) or len(q) != crypto_core_ristretto255_SCALARBYTES:
        raise TypeError(
            f"Each integer must be a {crypto_core_ristretto255_SCALARBYTES} long bytes sequence"
        )  # pragma: no cover

    r = _sodium.ffi.new(
        "unsigned char[]",
        crypto_core_ristretto255_SCALARBYTES)

    _sodium.lib.crypto_core_ristretto255_scalar_mul(r, p, q)

    return _sodium.ffi.buffer(r, crypto_core_ristretto255_SCALARBYTES)[:]


# (unsigned char *r, const unsigned char *s);
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
    if not isinstance(p, bytes) or len(
            p) != crypto_core_ristretto255_SCALARBYTES:
        raise TypeError(
            f"Each integer must be a {crypto_core_ristretto255_SCALARBYTES} long bytes sequence"
        )  # pragma: no cover

    r = _sodium.ffi.new(
        "unsigned char[]",
        crypto_core_ristretto255_SCALARBYTES)

    _sodium.lib.crypto_core_ristretto255_scalar_reduce(r, p)

    return _sodium.ffi.buffer(r, crypto_core_ristretto255_SCALARBYTES)[:]


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
    if not isinstance(n, bytes) or len(
            n) != crypto_scalarmult_ristretto255_SCALARBYTES:
        raise TypeError(
            f"Input must be a {crypto_scalarmult_ristretto255_SCALARBYTES} long bytes sequence"
        )  # pragma: no cover

    q = _sodium.ffi.new(
        "unsigned char[]",
        crypto_scalarmult_ristretto255_BYTES)

    if _sodium.lib.crypto_scalarmult_ristretto255_base(q, n) == -1:
        raise RuntimeError(
            "`n` cannot be larger than the size of the group or g^n is the identity element"
        )  # pragma: no cover

    return _sodium.ffi.buffer(q, crypto_scalarmult_ristretto255_BYTES)[:]


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
    if not isinstance(n, bytes) or len(
            n) != crypto_scalarmult_ristretto255_SCALARBYTES:
        raise TypeError(
            f"Input must be a {crypto_scalarmult_ristretto255_SCALARBYTES} long bytes sequence"
        )  # pragma: no cover

    if not isinstance(p, bytes) or len(
            p) != crypto_scalarmult_ristretto255_BYTES:
        raise TypeError(
            f"Input must be a {crypto_scalarmult_ristretto255_BYTES} long bytes sequence"
        )  # pragma: no cover

    q = _sodium.ffi.new(
        "unsigned char[]",
        crypto_scalarmult_ristretto255_BYTES)

    if _sodium.lib.crypto_scalarmult_ristretto255(q, n, p) == -1:
        raise RuntimeError(
            "`n` cannot be larger than the size of the group or p^n is the identity element")

    return _sodium.ffi.buffer(q, crypto_scalarmult_ristretto255_BYTES)[:]


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
    buf = _sodium.ffi.new("unsigned char[]", size)
    _sodium.lib.randombytes(buf, size)
    return _sodium.ffi.buffer(buf, size)[:]


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
        raise TypeError(
            "Deterministic random bytes must be generated from 32 bytes"
        )  # pragma: no cover

    buf = _sodium.ffi.new("unsigned char[]", size)
    _sodium.lib.randombytes_buf_deterministic(buf, size, seed)
    return _sodium.ffi.buffer(buf, size)[:]

# Initializes sodium, picking the best implementations available for this
# machine.


def _sodium_init():
    if _sodium.lib.sodium_init() == -1:
        raise RuntimeError(
            "libsodium error during initialization")  # pragma: no cover


_sodium.ffi.init_once(_sodium_init, "libsodium")

if __name__ == "__main__":
    doctest.testmod()  # pragma: no cover
