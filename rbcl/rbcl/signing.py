# Copyright 2013 Donald Stufft and individual contributors
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import, division, print_function

import rbcl.bindings
from rbcl import encoding
from rbcl import exceptions as exc
from rbcl.public import (
    PrivateKey as _Curve25519_PrivateKey,
    PublicKey as _Curve25519_PublicKey,
)
from rbcl.utils import StringFixer, random


class SignedMessage(bytes):
    """
    A bytes subclass that holds a messaged that has been signed by a
    :class:`SigningKey`.
    """

    @classmethod
    def _from_parts(cls, signature, message, combined):
        obj = cls(combined)
        obj._signature = signature
        obj._message = message
        return obj

    @property
    def signature(self):
        """
        The signature contained within the :class:`SignedMessage`.
        """
        return self._signature

    @property
    def message(self):
        """
        The message contained within the :class:`SignedMessage`.
        """
        return self._message


class VerifyKey(encoding.Encodable, StringFixer, object):
    """
    The public key counterpart to an Ed25519 SigningKey for producing digital
    signatures.

    :param key: [:class:`bytes`] Serialized Ed25519 public key
    :param encoder: A class that is able to decode the `key`
    """

    def __init__(self, key, encoder=encoding.RawEncoder):
        # Decode the key
        key = encoder.decode(key)
        if not isinstance(key, bytes):
            raise exc.TypeError("VerifyKey must be created from 32 bytes")

        if len(key) != rbcl.bindings.crypto_sign_PUBLICKEYBYTES:
            raise exc.ValueError(
                "The key must be exactly %s bytes long"
                % rbcl.bindings.crypto_sign_PUBLICKEYBYTES,
            )

        self._key = key

    def __bytes__(self):
        return self._key

    def __hash__(self):
        return hash(bytes(self))

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        return rbcl.bindings.sodium_memcmp(bytes(self), bytes(other))

    def __ne__(self, other):
        return not (self == other)

    def verify(self, smessage, signature=None, encoder=encoding.RawEncoder):
        """
        Verifies the signature of a signed message, returning the message
        if it has not been tampered with else raising
        :class:`~rbcl.signing.BadSignatureError`.

        :param smessage: [:class:`bytes`] Either the original messaged or a
            signature and message concated together.
        :param signature: [:class:`bytes`] If an unsigned message is given for
            smessage then the detached signature must be provided.
        :param encoder: A class that is able to decode the secret message and
            signature.
        :rtype: :class:`bytes`
        """
        if signature is not None:
            # If we were given the message and signature separately, validate
            #   signature size and combine them.
            if not isinstance(signature, bytes):
                raise exc.TypeError(
                    "Verification signature must be created from %d bytes"
                    % rbcl.bindings.crypto_sign_BYTES,
                )

            if len(signature) != rbcl.bindings.crypto_sign_BYTES:
                raise exc.ValueError(
                    "The signature must be exactly %d bytes long"
                    % rbcl.bindings.crypto_sign_BYTES,
                )

            smessage = signature + encoder.decode(smessage)
        else:
            # Decode the signed message
            smessage = encoder.decode(smessage)

        return rbcl.bindings.crypto_sign_open(smessage, self._key)

    def to_curve25519_public_key(self):
        """
        Converts a :class:`~rbcl.signing.VerifyKey` to a
        :class:`~rbcl.public.PublicKey`

        :rtype: :class:`~rbcl.public.PublicKey`
        """
        raw_pk = rbcl.bindings.crypto_sign_ed25519_pk_to_curve25519(self._key)
        return _Curve25519_PublicKey(raw_pk)


class SigningKey(encoding.Encodable, StringFixer, object):
    """
    Private key for producing digital signatures using the Ed25519 algorithm.

    Signing keys are produced from a 32-byte (256-bit) random seed value. This
    value can be passed into the :class:`~rbcl.signing.SigningKey` as a
    :func:`bytes` whose length is 32.

    .. warning:: This **must** be protected and remain secret. Anyone who knows
        the value of your :class:`~rbcl.signing.SigningKey` or it's seed can
        masquerade as you.

    :param seed: [:class:`bytes`] Random 32-byte value (i.e. private key)
    :param encoder: A class that is able to decode the seed

    :ivar: verify_key: [:class:`~rbcl.signing.VerifyKey`] The verify
        (i.e. public) key that corresponds with this signing key.
    """

    def __init__(self, seed, encoder=encoding.RawEncoder):
        # Decode the seed
        seed = encoder.decode(seed)
        if not isinstance(seed, bytes):
            raise exc.TypeError(
                "SigningKey must be created from a 32 byte seed"
            )

        # Verify that our seed is the proper size
        if len(seed) != rbcl.bindings.crypto_sign_SEEDBYTES:
            raise exc.ValueError(
                "The seed must be exactly %d bytes long"
                % rbcl.bindings.crypto_sign_SEEDBYTES
            )

        public_key, secret_key = rbcl.bindings.crypto_sign_seed_keypair(seed)

        self._seed = seed
        self._signing_key = secret_key
        self.verify_key = VerifyKey(public_key)

    def __bytes__(self):
        return self._seed

    def __hash__(self):
        return hash(bytes(self))

    def __eq__(self, other):
        if not isinstance(other, self.__class__):
            return False
        return rbcl.bindings.sodium_memcmp(bytes(self), bytes(other))

    def __ne__(self, other):
        return not (self == other)

    @classmethod
    def generate(cls):
        """
        Generates a random :class:`~rbcl.signing.SigningKey` object.

        :rtype: :class:`~rbcl.signing.SigningKey`
        """
        return cls(
            random(rbcl.bindings.crypto_sign_SEEDBYTES),
            encoder=encoding.RawEncoder,
        )

    def sign(self, message, encoder=encoding.RawEncoder):
        """
        Sign a message using this key.

        :param message: [:class:`bytes`] The data to be signed.
        :param encoder: A class that is used to encode the signed message.
        :rtype: :class:`~rbcl.signing.SignedMessage`
        """
        raw_signed = rbcl.bindings.crypto_sign(message, self._signing_key)

        crypto_sign_BYTES = rbcl.bindings.crypto_sign_BYTES
        signature = encoder.encode(raw_signed[:crypto_sign_BYTES])
        message = encoder.encode(raw_signed[crypto_sign_BYTES:])
        signed = encoder.encode(raw_signed)

        return SignedMessage._from_parts(signature, message, signed)

    def to_curve25519_private_key(self):
        """
        Converts a :class:`~rbcl.signing.SigningKey` to a
        :class:`~rbcl.public.PrivateKey`

        :rtype: :class:`~rbcl.public.PrivateKey`
        """
        sk = self._signing_key
        raw_private = rbcl.bindings.crypto_sign_ed25519_sk_to_curve25519(sk)
        return _Curve25519_PrivateKey(raw_private)