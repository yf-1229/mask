"""Encrypted mapping-table handoff between teammates (封筒 scheme).

The mapping table is the re-identification key, so it only ever leaves a
process as ciphertext. The receiving gateway completes the whole process:
unseal with the shared passphrase, merge into its session, done.

Envelope format (v1):
    {"v": 1,
     "kdf": {"name": "argon2id", "salt": <b64>, "opslimit": n, "memlimit": n},
     "boxed": <b64 of nonce || XSalsa20-Poly1305 ciphertext>}

- key derivation: argon2id (libsodium) from a team passphrase
- encryption: SecretBox (XSalsa20-Poly1305, authenticated) — a wrong
  passphrase or a tampered envelope raises nacl.exceptions.CryptoError
- the envelope carries its own KDF parameters, so future releases can
  raise the cost without invalidating old files
"""

from __future__ import annotations

import base64
import json

from nacl import pwhash, secret, utils as nacl_utils

ENVELOPE_VERSION = 1
# Interactive-grade argon2id (~64 MiB, ~0.1 s per seal/unseal).
KDF_OPSLIMIT = pwhash.argon2id.OPSLIMIT_INTERACTIVE
KDF_MEMLIMIT = pwhash.argon2id.MEMLIMIT_INTERACTIVE


def seal(payload: dict, passphrase: str) -> dict:
    """Encrypt a JSON-serializable payload under a passphrase."""
    if not passphrase:
        raise ValueError("passphrase must not be empty")
    salt = nacl_utils.random(pwhash.argon2id.SALTBYTES)
    key = pwhash.argon2id.kdf(
        secret.SecretBox.KEY_SIZE,
        passphrase.encode("utf-8"),
        salt,
        opslimit=KDF_OPSLIMIT,
        memlimit=KDF_MEMLIMIT,
    )
    box = secret.SecretBox(key)
    plaintext = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    boxed = box.encrypt(plaintext)
    return {
        "v": ENVELOPE_VERSION,
        "kdf": {
            "name": "argon2id",
            "salt": base64.b64encode(salt).decode("ascii"),
            "opslimit": KDF_OPSLIMIT,
            "memlimit": KDF_MEMLIMIT,
        },
        "boxed": base64.b64encode(bytes(boxed)).decode("ascii"),
    }


def unseal(envelope: dict, passphrase: str) -> dict:
    """Decrypt an envelope back to its payload.

    Raises nacl.exceptions.CryptoError on a wrong passphrase or tampered
    ciphertext, ValueError/KeyError/TypeError on a malformed envelope.
    """
    if not isinstance(envelope, dict) or envelope.get("v") != ENVELOPE_VERSION:
        raise ValueError("unsupported envelope version")
    kdf = envelope["kdf"]
    if not isinstance(kdf, dict) or kdf.get("name") != "argon2id":
        raise ValueError("unsupported kdf")
    salt = base64.b64decode(kdf["salt"])
    key = pwhash.argon2id.kdf(
        secret.SecretBox.KEY_SIZE,
        passphrase.encode("utf-8"),
        salt,
        opslimit=int(kdf["opslimit"]),
        memlimit=int(kdf["memlimit"]),
    )
    box = secret.SecretBox(key)
    plaintext = box.decrypt(base64.b64decode(envelope["boxed"]))
    return json.loads(plaintext.decode("utf-8"))
