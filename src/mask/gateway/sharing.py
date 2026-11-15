"""Encrypted mapping-table handoff between teammates (封筒 scheme).

The mapping table is the re-identification key, so it only ever leaves a
process as ciphertext. The receiving gateway completes the whole process:
unseal with the shared passphrase, merge into its session, done.

Envelope format (v1):
    {"v": 1,
     "exp": <unix ts>,          # informational clear copy of the expiry
     "kdf": {"name": "argon2id", "salt": <b64>, "opslimit": n, "memlimit": n},
     "boxed": <b64 of nonce || XSalsa20-Poly1305 ciphertext>}

- key derivation: argon2id (libsodium) from a team passphrase
- encryption: SecretBox (XSalsa20-Poly1305, authenticated) — a wrong
  passphrase or a tampered envelope raises nacl.exceptions.CryptoError
- the envelope carries its own KDF parameters, so future releases can
  raise the cost without invalidating old files

Two ways an envelope becomes permanently undecryptable:
- 時間切れ: the authoritative expiry is sealed inside the authenticated
  payload (the clear copy is only a fast-fail convenience). After it
  passes, unseal raises EnvelopeExpired — fail-closed, so envelopes
  without an expiry are refused too.
- 認証失敗: the gateway counts failed passphrase attempts per envelope
  (keyed by envelope_fingerprint) and locks an envelope for good after
  the configured limit. On top of that the gateway marks an envelope
  consumed after a successful import (single use). These bound online
  guessing through the gateway; offline guessing against a copied
  envelope is mitigated by the argon2id cost, the passphrase strength,
  and the short expiry window.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time

from nacl import pwhash, secret, utils as nacl_utils

ENVELOPE_VERSION = 1
# Moderate-grade argon2id (~256 MiB, ~0.3 s per seal/unseal). Handoffs are
# rare and re-export is cheap, so we spend real cost here: this is the
# only thing slowing offline passphrase guessing against a copied
# envelope. The envelope carries its own parameters, so future raises
# do not invalidate old files.
KDF_OPSLIMIT = pwhash.argon2id.OPSLIMIT_MODERATE
KDF_MEMLIMIT = pwhash.argon2id.MEMLIMIT_MODERATE

# Default envelope lifetime: 1 h. A handoff is a minutes-scale operation;
# if it expires, export again.
DEFAULT_TTL_SECONDS = 3600


class EnvelopeExpired(ValueError):
    """The envelope's sealed expiry has passed; decryption is refused."""


def seal(payload: dict, passphrase: str, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> dict:
    """Encrypt a JSON-serializable payload under a passphrase.

    The expiry (`exp`, unix time) is sealed into the authenticated payload;
    a clear copy on the envelope lets recipients see when it dies.
    """
    if not passphrase:
        raise ValueError("passphrase must not be empty")
    if not isinstance(ttl_seconds, int) or ttl_seconds <= 0:
        raise ValueError("ttl_seconds must be a positive integer")
    exp = int(time.time()) + ttl_seconds
    salt = nacl_utils.random(pwhash.argon2id.SALTBYTES)
    key = pwhash.argon2id.kdf(
        secret.SecretBox.KEY_SIZE,
        passphrase.encode("utf-8"),
        salt,
        opslimit=KDF_OPSLIMIT,
        memlimit=KDF_MEMLIMIT,
    )
    box = secret.SecretBox(key)
    plaintext = json.dumps({**payload, "exp": exp}, ensure_ascii=False).encode("utf-8")
    boxed = box.encrypt(plaintext)
    return {
        "v": ENVELOPE_VERSION,
        "exp": exp,
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

    Raises EnvelopeExpired once the sealed expiry has passed (checked
    against the clear copy first for a fast fail, then against the
    authoritative copy inside the ciphertext). Raises
    nacl.exceptions.CryptoError on a wrong passphrase or tampered
    ciphertext, ValueError/KeyError/TypeError on a malformed envelope.
    """
    if not isinstance(envelope, dict) or envelope.get("v") != ENVELOPE_VERSION:
        raise ValueError("unsupported envelope version")
    clear_exp = envelope.get("exp")
    if isinstance(clear_exp, (int, float)) and time.time() > clear_exp:
        raise EnvelopeExpired("envelope expired")
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
    payload = json.loads(plaintext.decode("utf-8"))
    exp = payload.get("exp") if isinstance(payload, dict) else None
    if not isinstance(exp, (int, float)) or time.time() > exp:
        # authoritative, tamper-evident check; missing exp fails closed
        raise EnvelopeExpired("envelope expired")
    return payload


def envelope_fingerprint(envelope: dict) -> str:
    """Stable identity of a decryptable envelope (salt + ciphertext).

    Used to key the failed-attempt lockout: a copied envelope has the same
    fingerprint, and a mutated one can never decrypt, so guessing through
    the gateway cannot be reset by re-copying or tweaking bytes.
    """
    kdf = envelope.get("kdf") if isinstance(envelope, dict) else None
    salt = kdf.get("salt", "") if isinstance(kdf, dict) else ""
    boxed = envelope.get("boxed", "") if isinstance(envelope, dict) else ""
    material = f"{salt}|{boxed}".encode("utf-8")
    return hashlib.sha256(material).hexdigest()
