"""Ed25519 signing key for evidence case bundles.

A SHA-256 over the bundle only detects accidental corruption: whoever edits a
bundle can recompute it. The server signs that digest with a private key that
never leaves it, so an offline verifier holding the public key can tell that
the bundle was produced by this CyberCore instance and not edited afterwards.
"""

from __future__ import annotations

import base64
import hashlib
from dataclasses import dataclass
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey


def key_id(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return hashlib.sha256(raw).hexdigest()[:16]


def public_key_pem(public_key: Ed25519PublicKey) -> str:
    return public_key.public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode("ascii")


def load_public_key(pem: bytes) -> Ed25519PublicKey:
    key = serialization.load_pem_public_key(pem)
    if not isinstance(key, Ed25519PublicKey):
        raise ValueError("La clave pública no es Ed25519")
    return key


def verify_signature(public_key: Ed25519PublicKey, message: str, signature: str) -> bool:
    try:
        public_key.verify(base64.b64decode(signature, validate=True), message.encode("ascii"))
    except (InvalidSignature, ValueError):
        return False
    return True


@dataclass(frozen=True)
class EvidenceSigner:
    private_key: Ed25519PrivateKey

    @classmethod
    def generate(cls) -> "EvidenceSigner":
        return cls(Ed25519PrivateKey.generate())

    @classmethod
    def from_file(cls, path: Path) -> "EvidenceSigner":
        key = serialization.load_pem_private_key(path.read_bytes(), password=None)
        if not isinstance(key, Ed25519PrivateKey):
            raise ValueError(f"{path} no contiene una clave privada Ed25519")
        return cls(key)

    @property
    def public_key(self) -> Ed25519PublicKey:
        return self.private_key.public_key()

    @property
    def key_id(self) -> str:
        return key_id(self.public_key)

    def sign(self, message: str) -> str:
        return base64.b64encode(self.private_key.sign(message.encode("ascii"))).decode("ascii")

    def private_pem(self) -> bytes:
        return self.private_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
