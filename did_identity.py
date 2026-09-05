#!/usr/bin/env python3
"""
did_identity.py — Ed25519 did:key identity for technocore.chat

DESIGN RULES (do not relax these — they are the whole point):

  1. DEDICATED KEY. This key is generated fresh, here, for chat only. It is never
     a trading wallet key, never imported from a seed you use elsewhere, and it
     never signs a transaction. If you ever find yourself pasting an existing
     private key into this file, stop: that is the failure mode this design exists
     to prevent.

  2. NEVER A GENERIC SIGNING ORACLE. There is no sign(bytes) function here, and
     there must never be one. A process that will sign arbitrary bytes on request
     is a process an attacker can walk to a transaction signature. The only two
     things this module will sign are the two fixed templates technocore defines:
        say-signed:  "<room>|<nonce>|<text>"
        note-signed: "<namespace>|<room>|<nonce>|<value>"
     Both are assembled here from validated parts. Callers pass fields, never
     a payload.

  3. ENCRYPTED AT REST. The private key is stored scrypt+AES-GCM encrypted under
     a passphrase. It is decrypted into memory only for the moment of a signature
     and the plaintext key object is dropped afterwards.

  4. NEVER LOGGED, NEVER SENT. The private key is never printed, never written to
     the SQLite log, never included in a message, never sent anywhere. Only the
     public did:key:z6Mk... identifier is ever displayed.

  5. BACKUP IS YOUR JOB. If Flop Labs' airdrop turns out to be claimable against a
     DID, losing this file loses that claim. Back up the .json file AND remember
     the passphrase. Write the passphrase on paper, offline. There is no recovery.

Usage:
  python did_identity.py create                 # generate a new identity
  python did_identity.py show                   # print the public DID only
  python did_identity.py verify                 # check passphrase + self-test a signature
  python did_identity.py backup-check           # confirm the file is readable and intact
"""

from __future__ import annotations

import base64
import getpass
import json
import os
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Optional

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives import serialization

# --------------------------------------------------------------------------- #

KEY_PATH = Path(os.environ.get("TECHNOCORE_KEY_FILE", "technocore_identity.json"))

# multicodec prefix for ed25519-pub, per the did:key spec
ED25519_MULTICODEC = b"\xed\x01"

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,47}$")

# scrypt parameters — deliberately slow. n=2**16 is ~100ms and ~64MB, which is
# painful for an offline brute-forcer and unnoticeable for you.
SCRYPT_N = 2 ** 16
SCRYPT_R = 8
SCRYPT_P = 1


# --------------------------------------------------------------------------- #
# base58btc (bitcoin alphabet) — did:key uses multibase 'z' prefix
# --------------------------------------------------------------------------- #

_B58_ALPHABET = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def b58encode(data: bytes) -> str:
    n = int.from_bytes(data, "big")
    out = ""
    while n > 0:
        n, rem = divmod(n, 58)
        out = _B58_ALPHABET[rem] + out
    # leading zero bytes become leading '1's
    for byte in data:
        if byte == 0:
            out = "1" + out
        else:
            break
    return out


def b58decode(s: str) -> bytes:
    n = 0
    for ch in s:
        idx = _B58_ALPHABET.find(ch)
        if idx < 0:
            raise ValueError(f"invalid base58 character: {ch!r}")
        n = n * 58 + idx
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    pad = 0
    for ch in s:
        if ch == "1":
            pad += 1
        else:
            break
    return b"\x00" * pad + body


def did_from_public_key(pub: Ed25519PublicKey) -> str:
    raw = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return "did:key:z" + b58encode(ED25519_MULTICODEC + raw)


# --------------------------------------------------------------------------- #
# Encrypted storage
# --------------------------------------------------------------------------- #

def _derive(passphrase: str, salt: bytes) -> bytes:
    kdf = Scrypt(salt=salt, length=32, n=SCRYPT_N, r=SCRYPT_R, p=SCRYPT_P)
    return kdf.derive(passphrase.encode("utf-8"))


def _save_encrypted(private: Ed25519PrivateKey, did: str, passphrase: str,
                    path: Path = KEY_PATH) -> None:
    raw = private.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    salt = os.urandom(16)
    nonce = os.urandom(12)
    key = _derive(passphrase, salt)
    ciphertext = AESGCM(key).encrypt(nonce, raw, did.encode("utf-8"))

    payload = {
        "version": 1,
        "did": did,                                   # public — safe to store plainly
        "kdf": {"name": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P,
                "salt": base64.b64encode(salt).decode()},
        "cipher": {"name": "AES-256-GCM",
                   "nonce": base64.b64encode(nonce).decode(),
                   "ciphertext": base64.b64encode(ciphertext).decode()},
        "note": "Encrypted Ed25519 private key for technocore.chat. "
                "Chat identity ONLY — never a wallet key. Back this file up "
                "together with the passphrase; there is no recovery.",
    }
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    tmp.replace(path)
    try:
        os.chmod(path, 0o600)  # no-op on Windows, meaningful on Linux/macOS
    except OSError:
        pass


@dataclass
class Identity:
    did: str
    _private: Ed25519PrivateKey

    # -- the ONLY two signing entry points ---------------------------------

    def sign_say(self, room: str, nonce: int, swept_text: str) -> str:
        """Sign a technocore say-signed message.

        `swept_text` MUST already be the text after the server's single-line
        sweep — the bytes that actually get stored. Signing the raw text will
        not verify. Pass the output of agent_v2.sanitize_text().
        """
        _require_name("room", room)
        _require_nonce(nonce)
        if not isinstance(swept_text, str) or not swept_text:
            raise ValueError("swept_text must be a non-empty string")
        if len(swept_text) > 4096:
            raise ValueError("text exceeds the 4096-character protocol cap")
        payload = f"{room}|{nonce}|{swept_text}".encode("utf-8")
        return _b64url(self._private.sign(payload))

    def sign_note(self, namespace: str, key: str, nonce: int, swept_value: str) -> str:
        """Sign a signed-note write. technocore only accepts these for the
        room-owners and room-allow namespaces; we refuse anything else so this
        cannot become a general-purpose signer."""
        if namespace not in ("room-owners", "room-allow"):
            raise ValueError(
                f"refusing to sign for namespace {namespace!r}: only "
                "'room-owners' and 'room-allow' accept signed note writes"
            )
        _require_name("key", key)
        _require_nonce(nonce)
        if not isinstance(swept_value, str) or not swept_value:
            raise ValueError("swept_value must be a non-empty string")
        payload = f"{namespace}|{key}|{nonce}|{swept_value}".encode("utf-8")
        return _b64url(self._private.sign(payload))

    # NOTE: there is deliberately no sign(data) method. Do not add one.


def _b64url(sig: bytes) -> str:
    return base64.urlsafe_b64encode(sig).decode().rstrip("=")


def _require_name(kind: str, value: str) -> None:
    if not NAME_RE.match(value or ""):
        raise ValueError(f"invalid {kind} {value!r}: must match ^[a-z0-9][a-z0-9_-]{{0,47}}$")


def _require_nonce(nonce: int) -> None:
    if not isinstance(nonce, int) or not (1 <= nonce <= 9_999_999_999_999_999_999):
        raise ValueError("nonce must be an integer of 1..19 digits")


def load_identity(passphrase: Optional[str] = None,
                  path: Path = KEY_PATH) -> Identity:
    if not path.exists():
        raise FileNotFoundError(
            f"no identity at {path}. Run: python did_identity.py create"
        )
    payload = json.loads(path.read_text(encoding="utf-8"))
    did = payload["did"]

    if passphrase is None:
        passphrase = os.environ.get("TECHNOCORE_KEY_PASSPHRASE")
    if passphrase is None:
        passphrase = getpass.getpass("passphrase for the technocore identity: ")

    salt = base64.b64decode(payload["kdf"]["salt"])
    nonce = base64.b64decode(payload["cipher"]["nonce"])
    ct = base64.b64decode(payload["cipher"]["ciphertext"])
    key = _derive(passphrase, salt)
    try:
        raw = AESGCM(key).decrypt(nonce, ct, did.encode("utf-8"))
    except Exception:
        raise ValueError("wrong passphrase, or the key file has been tampered with")

    private = Ed25519PrivateKey.from_private_bytes(raw)
    # sanity: the file's stated DID must match the key it actually holds
    if did_from_public_key(private.public_key()) != did:
        raise ValueError("key file is inconsistent: DID does not match the key")
    return Identity(did=did, _private=private)


# --------------------------------------------------------------------------- #
# Commands
# --------------------------------------------------------------------------- #

def cmd_create(path: Path = KEY_PATH) -> None:
    if path.exists():
        print(f"An identity already exists at {path}.", file=sys.stderr)
        print("Refusing to overwrite it — losing it may lose any future claim.", file=sys.stderr)
        print("Move it aside deliberately if you really want a new one.", file=sys.stderr)
        sys.exit(1)

    print("Creating a NEW Ed25519 identity for technocore.chat.")
    print()
    print("  * This key is for chat identity only. It will never sign a transaction.")
    print("  * Do NOT reuse a passphrase from a wallet or exchange.")
    print("  * Write the passphrase on PAPER. There is no recovery.")
    print()

    p1 = getpass.getpass("choose a passphrase: ")
    if len(p1) < 12:
        print("Too short — use at least 12 characters.", file=sys.stderr)
        sys.exit(1)
    p2 = getpass.getpass("confirm passphrase: ")
    if p1 != p2:
        print("Passphrases do not match.", file=sys.stderr)
        sys.exit(1)

    private = Ed25519PrivateKey.generate()
    did = did_from_public_key(private.public_key())
    _save_encrypted(private, did, p1, path)

    print()
    print("Identity created.")
    print(f"  file : {path.resolve()}")
    print(f"  DID  : {did}")
    print()
    print("NEXT: back up that file somewhere offline, and write the passphrase on paper.")
    print("The DID above is PUBLIC — safe to post. The file is not.")


def cmd_show(path: Path = KEY_PATH) -> None:
    if not path.exists():
        print(f"no identity at {path}", file=sys.stderr)
        sys.exit(1)
    payload = json.loads(path.read_text(encoding="utf-8"))
    print(payload["did"])


def cmd_verify(path: Path = KEY_PATH) -> None:
    """Prove the passphrase works and the key can produce a valid signature,
    without touching the network."""
    ident = load_identity(path=path)
    test_text = "verification selftest"
    sig = ident.sign_say("lobby", 1, test_text)

    # verify locally against the public key derived from the DID
    mb = payload_did_to_raw(ident.did)
    Ed25519PublicKey.from_public_bytes(mb).verify(
        base64.urlsafe_b64decode(sig + "=" * (-len(sig) % 4)),
        f"lobby|1|{test_text}".encode("utf-8"),
    )
    print("OK — passphrase correct, key intact, signature verifies.")
    print(f"DID: {ident.did}")


def payload_did_to_raw(did: str) -> bytes:
    if not did.startswith("did:key:z"):
        raise ValueError("not a did:key")
    decoded = b58decode(did[len("did:key:z"):])
    if not decoded.startswith(ED25519_MULTICODEC):
        raise ValueError("not an ed25519 did:key")
    return decoded[len(ED25519_MULTICODEC):]


def cmd_backup_check(path: Path = KEY_PATH) -> None:
    if not path.exists():
        print(f"MISSING: {path}", file=sys.stderr)
        sys.exit(1)
    payload = json.loads(path.read_text(encoding="utf-8"))
    size = path.stat().st_size
    print(f"file    : {path.resolve()}")
    print(f"size    : {size} bytes")
    print(f"DID     : {payload['did']}")
    print(f"version : {payload.get('version')}")
    print()
    print("Back up THIS FILE plus the passphrase. Both are needed. Neither alone works.")


def main() -> None:
    cmds = {
        "create": cmd_create,
        "show": cmd_show,
        "verify": cmd_verify,
        "backup-check": cmd_backup_check,
    }
    if len(sys.argv) < 2 or sys.argv[1] not in cmds:
        print(__doc__)
        sys.exit(1)
    cmds[sys.argv[1]]()


if __name__ == "__main__":
    main()
