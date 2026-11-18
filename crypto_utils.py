"""
This file contains cryptographic utilities for secure messaging.

This module generates RSA keys, protects local private keys, 
creates encrypted message envelopes, 
and decrypts them on the user's device.
"""

import base64
import binascii
import hashlib
import os
from pathlib import Path

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Cryptographic sizes and message limits.
RSA_KEY_SIZE = 2048
AES_KEY_SIZE = 256
AES_GCM_NONCE_SIZE = 12
MAX_PLAINTEXT_BYTES = 2000


# RSA key generation, loading, and public-key identification.
def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=RSA_KEY_SIZE,
    )

    return private_key, private_key.public_key()


def serialize_public_key(public_key):
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return public_bytes.decode("ascii")


def load_rsa_public_key(public_key_pem):
    if not isinstance(public_key_pem, str):
        raise ValueError(
            "public key must be PEM text"
        )

    try:
        loaded_key = serialization.load_pem_public_key(
            public_key_pem.encode("utf-8")
        )
    except (TypeError, ValueError) as error:
        raise ValueError(
            "invalid public key"
        ) from error

    if not isinstance(
        loaded_key,
        rsa.RSAPublicKey,
    ):
        raise ValueError(
            "public key must be an RSA key"
        )

    if loaded_key.key_size < RSA_KEY_SIZE:
        raise ValueError(
            "RSA public key must be at least 2048 bits"
        )

    return loaded_key


def public_key_fingerprint(public_key):
    public_der = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return hashlib.sha256(
        public_der
    ).hexdigest()


# RSA-OAEP helpers for the small anonymous source handle.
def encrypt_small_payload(
    plaintext,
    recipient_public_key_pem,
):
    if not isinstance(plaintext, bytes) or not plaintext:
        raise ValueError(
            "small payload must be nonempty bytes"
        )

    public_key = load_rsa_public_key(
        recipient_public_key_pem
    )

    return public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def decrypt_small_payload(
    ciphertext,
    private_key,
):
    if not isinstance(ciphertext, bytes) or not ciphertext:
        raise ValueError(
            "encrypted small payload must be nonempty bytes"
        )

    return private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


# Password-protected local private-key storage.
def save_private_key(
    private_key,
    path,
    password,
    *,
    overwrite=False,
):
    if not isinstance(password, str) or not password:
        raise ValueError(
            "private-key password must not be empty"
        )

    output_path = Path(path)

    if output_path.exists() and not overwrite:
        raise FileExistsError(
            f"Private-key file already exists: {output_path}"
        )

    output_path.parent.mkdir(
        parents=True,
        exist_ok=True,
    )

    private_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=(
            serialization.BestAvailableEncryption(
                password.encode("utf-8")
            )
        ),
    )

    output_path.write_bytes(private_bytes)

    # Restrict the file to its owner on Unix-like systems.
    output_path.chmod(0o600)

    return output_path


def load_private_key(
    path,
    password,
):
    key_path = Path(path)

    if not key_path.exists():
        raise FileNotFoundError(
            f"Private-key file does not exist: {key_path}"
        )

    try:
        loaded_key = serialization.load_pem_private_key(
            key_path.read_bytes(),
            password=password.encode("utf-8"),
        )
    except (TypeError, ValueError) as error:
        raise ValueError(
            "private key could not be loaded"
        ) from error

    if not isinstance(
        loaded_key,
        rsa.RSAPrivateKey,
    ):
        raise ValueError(
            "private key must be an RSA key"
        )

    return loaded_key


# Base64 conversion for binary values sent through JSON.
def encode_bytes(value):
    return base64.b64encode(value).decode("ascii")


def decode_bytes(value):
    if not isinstance(value, str):
        raise ValueError(
            "Base64 value must be text"
        )

    try:
        return base64.b64decode(
            value.encode("ascii"),
            validate=True,
        )
    except (
        UnicodeEncodeError,
        binascii.Error,
        ValueError,
    ) as error:
        raise ValueError(
            "invalid Base64 data"
        ) from error


# Hybrid message encryption with AES-GCM and RSA-OAEP.
def encrypt_message(
    plaintext,
    recipient_public_key_pem,
):
    if not isinstance(plaintext, str):
        raise ValueError(
            "message must be text"
        )

    plaintext_bytes = plaintext.encode("utf-8")

    if not plaintext.strip():
        raise ValueError(
            "message must not be empty"
        )

    if len(plaintext_bytes) > MAX_PLAINTEXT_BYTES:
        raise ValueError(
            "message is too long"
        )

    recipient_public_key = load_rsa_public_key(
        recipient_public_key_pem
    )

    aes_key = AESGCM.generate_key(
        bit_length=AES_KEY_SIZE
    )

    nonce = os.urandom(AES_GCM_NONCE_SIZE)

    ciphertext = AESGCM(aes_key).encrypt(
        nonce,
        plaintext_bytes,
        None,
    )

    encrypted_aes_key = recipient_public_key.encrypt(
        aes_key,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    return {
        "encrypted_aes_key": encode_bytes(
            encrypted_aes_key
        ),
        "ciphertext": encode_bytes(ciphertext),
        "nonce": encode_bytes(nonce),
    }


def decrypt_message(
    envelope,
    private_key,
):
    try:
        encrypted_aes_key = decode_bytes(
            envelope["encrypted_aes_key"]
        )
        ciphertext = decode_bytes(
            envelope["ciphertext"]
        )
        nonce = decode_bytes(
            envelope["nonce"]
        )
    except KeyError as error:
        raise ValueError(
            "encrypted envelope is incomplete"
        ) from error

    if len(nonce) != AES_GCM_NONCE_SIZE:
        raise ValueError(
            "AES-GCM nonce must be 12 bytes"
        )

    aes_key = private_key.decrypt(
        encrypted_aes_key,
        padding.OAEP(
            mgf=padding.MGF1(
                algorithm=hashes.SHA256()
            ),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )

    plaintext_bytes = AESGCM(aes_key).decrypt(
        nonce,
        ciphertext,
        None,
    )

    try:
        return plaintext_bytes.decode("utf-8")
    except UnicodeDecodeError as error:
        raise ValueError(
            "decrypted message is not valid UTF-8"
        ) from error
