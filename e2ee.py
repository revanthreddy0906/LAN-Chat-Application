"""End-to-end encryption building blocks (needs the `cryptography` package).

Each person has an identity: an X25519 key pair for key agreement and an Ed25519 key pair
for signing. The server only ever sees the public halves. Everything here is a small,
explicit composition of audited primitives from `cryptography`: X25519, Ed25519, HKDF-SHA256,
ChaCha20-Poly1305 and scrypt. Nothing in this file invents a cipher.

Without the package the rest of the app still works over TLS; `AVAILABLE` says which it is.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from dataclasses import dataclass

try:
    from cryptography.exceptions import InvalidSignature, InvalidTag
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
    from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
    from cryptography.hazmat.primitives.serialization import Encoding, NoEncryption, PrivateFormat, PublicFormat

    AVAILABLE = True
except ImportError:  # the chat still works, over TLS only
    AVAILABLE = False

SCRYPT_N = 2**15  # about 100 ms and 32 MB; tests lower it to stay fast
SCRYPT_R = 8
SCRYPT_P = 1
RECOVERY_ALPHABET = "ABCDEFGHJKMNPQRSTUVWXYZ23456789"  # no 0/O, 1/I/L look-alikes
RECOVERY_LENGTH = 24  # 24 characters of a 31-letter alphabet is about 119 bits
KEYFILE_AAD = b"lanchat-keyfile-v1"
BACKUP_AAD = b"lanchat-backup-v1"


class CryptoError(Exception):
    """Anything that should make the caller refuse the data: bad key, tampering, wrong passphrase."""


class WrongPassphrase(CryptoError):
    pass


def require() -> None:
    if not AVAILABLE:
        raise CryptoError("end-to-end encryption needs the 'cryptography' package (pip install cryptography)")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def unb64(text: str) -> bytes:
    try:
        return base64.b64decode(text.encode("ascii"), validate=True)
    except (ValueError, UnicodeError, AttributeError, TypeError) as error:
        raise CryptoError("malformed key data") from error


# ----- identities -----

@dataclass(frozen=True)
class Bundle:
    """The public half of an identity: what the server stores and contacts pin."""

    dh: bytes  # X25519 public key
    sign: bytes  # Ed25519 public key
    sig: bytes  # the signing key's signature over both keys (they belong together)

    def to_dict(self) -> dict:
        return {"dh": b64(self.dh), "sign": b64(self.sign), "sig": b64(self.sig)}

    @classmethod
    def from_dict(cls, data: dict) -> "Bundle":
        try:
            bundle = cls(unb64(data["dh"]), unb64(data["sign"]), unb64(data["sig"]))
        except (KeyError, TypeError) as error:
            raise CryptoError("incomplete key bundle") from error
        if len(bundle.dh) != 32 or len(bundle.sign) != 32 or len(bundle.sig) != 64:
            raise CryptoError("key bundle has the wrong sizes")
        return bundle

    def verify(self) -> bool:
        """True if the two public keys were signed together by the signing key."""
        require()
        try:
            Ed25519PublicKey.from_public_bytes(self.sign).verify(self.sig, _bundle_message(self.dh, self.sign))
            return True
        except (InvalidSignature, ValueError):
            return False

    def fingerprint(self) -> str:
        return hashlib.sha256(self.dh + self.sign).hexdigest()


def _bundle_message(dh: bytes, sign: bytes) -> bytes:
    return b"lanchat-bundle-v1" + dh + sign


def _raw_public(key) -> bytes:
    return key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def _raw_private(key) -> bytes:
    return key.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())


class Identity:
    def __init__(self, dh_private, sign_private) -> None:
        require()
        self.dh, self.sign = dh_private, sign_private

    @classmethod
    def generate(cls) -> "Identity":
        require()
        return cls(X25519PrivateKey.generate(), Ed25519PrivateKey.generate())

    @classmethod
    def from_secret(cls, secret: bytes) -> "Identity":
        require()
        if len(secret) != 64:
            raise CryptoError("secret key data has the wrong size")
        return cls(X25519PrivateKey.from_private_bytes(secret[:32]), Ed25519PrivateKey.from_private_bytes(secret[32:]))

    def secret_bytes(self) -> bytes:
        return _raw_private(self.dh) + _raw_private(self.sign)

    def public(self) -> Bundle:
        dh, sign = _raw_public(self.dh), _raw_public(self.sign)
        return Bundle(dh, sign, self.sign.sign(_bundle_message(dh, sign)))


# ----- wrapping secrets with a passphrase or recovery code -----

def _derive(passphrase: str, salt: bytes, n: int, r: int, p: int) -> bytes:
    return Scrypt(salt=salt, length=32, n=n, r=r, p=p).derive(passphrase.encode("utf-8"))


def wrap(secret: bytes, passphrase: str, aad: bytes = KEYFILE_AAD) -> dict:
    """Encrypt `secret` under a key stretched from `passphrase` (scrypt) with ChaCha20-Poly1305."""
    require()
    salt, nonce = os.urandom(16), os.urandom(12)
    key = _derive(passphrase, salt, SCRYPT_N, SCRYPT_R, SCRYPT_P)
    return {"v": 1, "kdf": "scrypt", "n": SCRYPT_N, "r": SCRYPT_R, "p": SCRYPT_P, "salt": b64(salt),
            "nonce": b64(nonce), "ct": b64(ChaCha20Poly1305(key).encrypt(nonce, secret, aad))}


def unwrap(blob: dict, passphrase: str, aad: bytes = KEYFILE_AAD) -> bytes:
    require()
    try:
        n, r, p = int(blob["n"]), int(blob["r"]), int(blob["p"])
        if not (2**10 <= n <= 2**20 and 1 <= r <= 16 and 1 <= p <= 4):  # never let a file pick absurd costs
            raise CryptoError("unreasonable key-stretching settings in the key file")
        key = _derive(passphrase, unb64(blob["salt"]), n, r, p)
        return ChaCha20Poly1305(key).decrypt(unb64(blob["nonce"]), unb64(blob["ct"]), aad)
    except InvalidTag as error:
        raise WrongPassphrase("wrong passphrase (or the key file was changed)") from error
    except (KeyError, TypeError, ValueError) as error:
        raise CryptoError("the key file is damaged") from error


def new_recovery_code() -> str:
    """A random code to write down: six groups of four, about 119 bits."""
    letters = "".join(secrets.choice(RECOVERY_ALPHABET) for _ in range(RECOVERY_LENGTH))
    return "-".join(letters[i:i + 4] for i in range(0, RECOVERY_LENGTH, 4))


def normalize_recovery_code(code: str) -> str:
    return "".join(ch for ch in code.upper() if ch in RECOVERY_ALPHABET)


def valid_recovery_code(code: str) -> bool:
    return len(normalize_recovery_code(code)) == RECOVERY_LENGTH


# ----- the backup the server holds for you (opaque to it) -----

def make_backup(identities, recovery_code: str) -> dict:
    """Your secret keys wrapped with the recovery code, safe to hand to the server.

    `identities` is the current identity, or a list with the current one first followed by older
    ones kept so that messages sealed to them can still be opened."""
    identities = [identities] if isinstance(identities, Identity) else list(identities)
    secrets_ = b"".join(identity.secret_bytes() for identity in identities)
    return {"v": 2, "count": len(identities), "bundle": identities[0].public().to_dict(),
            "wrapped": wrap(secrets_, normalize_recovery_code(recovery_code), BACKUP_AAD)}


def open_backup_all(backup: dict, recovery_code: str) -> list[Identity]:
    """Every identity in a backup, current first."""
    if not valid_recovery_code(recovery_code):
        raise WrongPassphrase("a recovery code is 24 letters and digits, like ABCD-EFGH-...")
    try:
        data = unwrap(backup["wrapped"], normalize_recovery_code(recovery_code), BACKUP_AAD)
        if len(data) == 0 or len(data) % 64:
            raise CryptoError("the backup is damaged")
        identities = [Identity.from_secret(data[i:i + 64]) for i in range(0, len(data), 64)]
        if identities[0].public().dh != Bundle.from_dict(backup["bundle"]).dh:
            raise CryptoError("the backup does not match its public keys")
    except (KeyError, TypeError) as error:
        raise CryptoError("the backup is damaged") from error
    return identities


def open_backup(backup: dict, recovery_code: str) -> Identity:
    return open_backup_all(backup, recovery_code)[0]


# ----- safety numbers -----

def safety_number(name_a: str, bundle_a: Bundle, name_b: str, bundle_b: Bundle) -> str:
    """Sixty digits both people see identically, for comparing aloud or in person.

    It covers both names and both identity keys, so a server that swapped either key would
    produce a different number on the two screens.
    """
    parts = sorted((name_a.lower().encode() + b"\0" + bundle_a.dh + bundle_a.sign,
                    name_b.lower().encode() + b"\0" + bundle_b.dh + bundle_b.sign))
    digest = b"lanchat-safety-v1" + b"".join(parts)
    for _ in range(5200):  # a little stretching makes brute-forcing a look-alike key costly
        digest = hashlib.sha512(digest).digest()
    groups = [f"{int.from_bytes(digest[i * 5:(i + 1) * 5], 'big') % 100000:05d}" for i in range(12)]
    return " ".join(groups)


# ----- sealed messages for one recipient -----

def aad_for(kind: str, sender: str, recipient: str) -> bytes:
    """Context bound into every sealed message so it cannot be replayed somewhere else."""
    return f"lanchat-msg-v1|{kind}|{sender.lower()}|{recipient.lower()}".encode()


def seal(plaintext: bytes, me: Identity, recipient_dh: bytes, aad: bytes) -> dict:
    """Encrypt for one person: ephemeral and static Diffie-Hellman, HKDF, ChaCha20-Poly1305, signed."""
    require()
    try:
        recipient_key = X25519PublicKey.from_public_bytes(recipient_dh)
    except ValueError as error:
        raise CryptoError("the recipient's key is not valid") from error
    ephemeral = X25519PrivateKey.generate()
    epk = _raw_public(ephemeral)
    key = _message_key(ephemeral.exchange(recipient_key), me.dh.exchange(recipient_key),
                       epk, _raw_public(me.dh), recipient_dh)
    nonce = os.urandom(12)
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    signature = me.sign.sign(_envelope_message(epk, nonce, ciphertext, aad))
    return {"v": 1, "epk": b64(epk), "n": b64(nonce), "ct": b64(ciphertext), "sig": b64(signature)}


def open_sealed(envelope: dict, me: Identity, sender: Bundle, aad: bytes) -> bytes:
    """Decrypt a sealed message from `sender`. Raises CryptoError for anything not exactly as sent."""
    require()
    try:
        epk, nonce = unb64(envelope["epk"]), unb64(envelope["n"])
        ciphertext, signature = unb64(envelope["ct"]), unb64(envelope["sig"])
        if envelope.get("v") != 1 or len(epk) != 32 or len(nonce) != 12:
            raise CryptoError("unsupported or malformed message")
        try:
            Ed25519PublicKey.from_public_bytes(sender.sign).verify(
                signature, _envelope_message(epk, nonce, ciphertext, aad))
        except InvalidSignature as error:
            raise CryptoError("the message is not signed by the person it claims to be from") from error
        ephemeral_key = X25519PublicKey.from_public_bytes(epk)
        sender_key = X25519PublicKey.from_public_bytes(sender.dh)
        key = _message_key(me.dh.exchange(ephemeral_key), me.dh.exchange(sender_key),
                           epk, sender.dh, _raw_public(me.dh))
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as error:
        raise CryptoError("the message was altered or is not for you") from error
    except (KeyError, TypeError, ValueError) as error:
        raise CryptoError("malformed message") from error


def _message_key(dh_ephemeral: bytes, dh_static: bytes, epk: bytes, sender_dh: bytes, recipient_dh: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None,
                info=b"lanchat-seal-v1" + epk + sender_dh + recipient_dh).derive(dh_ephemeral + dh_static)


def _envelope_message(epk: bytes, nonce: bytes, ciphertext: bytes, aad: bytes) -> bytes:
    return b"lanchat-envelope-v1" + epk + nonce + ciphertext + aad


# ----- messages for one or more people (what the chat actually sends) -----

MAX_TEXT_BYTES = 1500  # longest message text that still fits one frame with its keys and signatures
MAX_ENVELOPE_CHARS = 3000  # what the server will accept for one encrypted message


def message_aad(kind: str, sender: str, names) -> bytes:
    """Who the message is from and who it is for, bound into every ciphertext and signature."""
    return f"lanchat-msg-v2|{kind}|{sender.lower()}|{','.join(sorted(n.lower() for n in names))}".encode()


def encode_payload(body: str, file: dict | None = None) -> bytes:
    """The plaintext that gets encrypted: the text, a random id (to spot replays), the time and,
    for a file message, what the file is and the key that opens it."""
    payload = {"b": body, "mid": secrets.token_hex(8), "ts": time.time()}
    if file is not None:
        payload["f"] = file
    return json.dumps(payload, ensure_ascii=False, separators=(",", ":")).encode("utf-8")


def decode_payload(data: bytes) -> dict:
    try:
        payload = json.loads(data.decode("utf-8"))
        if not isinstance(payload, dict) or not isinstance(payload.get("b"), str) or not isinstance(payload.get("mid"), str):
            raise ValueError
        if "f" in payload and file_info(payload["f"]) is None:
            raise ValueError
    except (ValueError, UnicodeError) as error:
        raise CryptoError("the decrypted message is malformed") from error
    return payload


# ----- files: encrypted in chunks, so a big file never has to fit in memory -----

FILE_CHUNK = 64 * 1024
FILE_TAG = 16
FILE_AAD = b"lanchat-file-v1"
FILE_KINDS = ("image", "video", "audio", "file")


def file_info(data) -> dict | None:
    """The file description inside an encrypted message, if it is well formed (else None)."""
    try:
        if (isinstance(data, dict) and isinstance(data["name"], str) and 0 < len(data["name"]) <= 255
                and isinstance(data["size"], int) and not isinstance(data["size"], bool) and data["size"] > 0
                and data["kind"] in FILE_KINDS and isinstance(data["mime"], str) and len(data["mime"]) <= 120
                and len(unb64(data["key"])) == 32):
            return data
    except (KeyError, CryptoError):
        pass
    return None


def new_file_key() -> bytes:
    return os.urandom(32)


def encrypted_size(plain_size: int) -> int:
    """How many bytes a file of this size occupies once encrypted."""
    return plain_size + FILE_TAG * max(1, -(-plain_size // FILE_CHUNK))


def _chunk_nonce(index: int, final: bool) -> bytes:
    """Chunk number plus a flag on the last chunk, so reordering, dropping or adding chunks is detected."""
    return index.to_bytes(8, "big") + (b"\x00\x00\x00\x01" if final else b"\x00\x00\x00\x00")


def encrypt_file(source: str, target: str, key: bytes, progress=None) -> tuple[int, str]:
    """Encrypt `source` into `target`. Returns (encrypted size, its SHA-256), which is what the server sees."""
    require()
    plain_size = os.path.getsize(source)
    if plain_size == 0:
        raise CryptoError("an empty file cannot be shared")
    aead, digest, index, done = ChaCha20Poly1305(key), hashlib.sha256(), 0, 0
    with open(source, "rb") as reader, open(target, "wb") as writer:
        chunk = reader.read(FILE_CHUNK)
        while True:
            following = reader.read(FILE_CHUNK)
            final = not following
            sealed = aead.encrypt(_chunk_nonce(index, final), chunk, FILE_AAD)
            writer.write(sealed)
            digest.update(sealed)
            done += len(chunk)
            index += 1
            if progress:
                progress(done, plain_size)
            if final:
                break
            chunk = following
    return os.path.getsize(target), digest.hexdigest()


def decrypt_file(source: str, target: str, key: bytes, plain_size: int, progress=None) -> None:
    """Decrypt `source` into `target`, writing the file only if every chunk checks out."""
    require()
    if os.path.getsize(source) != encrypted_size(plain_size):
        raise CryptoError("the file has the wrong size (it was cut short or extended)")
    aead, index, done = ChaCha20Poly1305(key), 0, 0
    partial = target + ".part"
    try:
        with open(source, "rb") as reader, open(partial, "wb") as writer:
            chunk = reader.read(FILE_CHUNK + FILE_TAG)
            while True:
                following = reader.read(FILE_CHUNK + FILE_TAG)
                final = not following
                try:
                    plain = aead.decrypt(_chunk_nonce(index, final), chunk, FILE_AAD)
                except InvalidTag as error:
                    raise CryptoError("the file was altered, reordered or is not for you") from error
                writer.write(plain)
                done += len(plain)
                index += 1
                if progress:
                    progress(done, plain_size)
                if final:
                    break
                chunk = following
        if done != plain_size:
            raise CryptoError("the file has the wrong size")
        os.replace(partial, target)
    finally:
        if os.path.exists(partial):
            os.unlink(partial)


def encrypt_message(plaintext: bytes, me: Identity, my_name: str, recipients: dict[str, Bundle],
                    kind: str = "text") -> dict:
    """Encrypt once with a random message key, then seal that key separately for each person.

    `recipients` is {name: public bundle} and should include the sender, so the sender can read
    their own history on another day. The text is encrypted a single time, so adding people
    costs a few hundred bytes each, not a copy of the message.
    """
    require()
    people = {name.lower(): bundle for name, bundle in recipients.items()}
    people[my_name.lower()] = me.public()
    aad = message_aad(kind, my_name, people)
    key, nonce = os.urandom(32), os.urandom(12)
    ciphertext = ChaCha20Poly1305(key).encrypt(nonce, plaintext, aad)
    sealed = {name: seal(key, me, bundle.dh, aad + b"|key|" + name.encode()) for name, bundle in sorted(people.items())}
    signature = me.sign.sign(b"lanchat-msg-v2" + nonce + ciphertext + aad)
    return {"v": 2, "n": b64(nonce), "ct": b64(ciphertext), "k": sealed, "sig": b64(signature)}


def envelope_size(envelope: dict) -> int:
    return len(json.dumps(envelope, separators=(",", ":")))


def envelope_people(envelope) -> list[str]:
    """The names an envelope is addressed to (lower case), or raises if it is malformed."""
    try:
        keys = envelope["k"]
        if envelope.get("v") != 2 or not isinstance(keys, dict) or not keys or not all(
                isinstance(name, str) and isinstance(entry, dict) for name, entry in keys.items()):
            raise CryptoError("malformed encrypted message")
        for field in ("n", "ct", "sig"):
            if not isinstance(envelope[field], str):
                raise CryptoError("malformed encrypted message")
        return sorted(keys)
    except (KeyError, TypeError, AttributeError) as error:
        raise CryptoError("malformed encrypted message") from error


def decrypt_message(envelope: dict, me: Identity, my_name: str, sender_name: str, sender: Bundle,
                    kind: str = "text") -> bytes:
    """Open a message addressed to me. Raises CryptoError unless it is exactly what `sender` sent."""
    require()
    names = envelope_people(envelope)
    aad = message_aad(kind, sender_name, names)
    nonce, ciphertext, signature = unb64(envelope["n"]), unb64(envelope["ct"]), unb64(envelope["sig"])
    try:
        Ed25519PublicKey.from_public_bytes(sender.sign).verify(signature, b"lanchat-msg-v2" + nonce + ciphertext + aad)
    except InvalidSignature as error:
        raise CryptoError("the message is not signed by the person it claims to be from") from error
    except ValueError as error:
        raise CryptoError("the sender's key is not valid") from error
    mine = envelope["k"].get(my_name.lower())
    if mine is None:
        raise CryptoError("this message was not encrypted for you")
    key = open_sealed(mine, me, sender, aad + b"|key|" + my_name.lower().encode())
    try:
        return ChaCha20Poly1305(key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as error:
        raise CryptoError("the message was altered") from error


# ----- the group room: one-way key chains per sender -----

MAX_CHAIN_STEPS = 20000  # how far a chain is walked forward to reach a message number


class NoKey(CryptoError):
    """The sender's key for this message has not been given to me (for example it was sent before I joined)."""


def chain_message_key(chain_key: bytes) -> bytes:
    return hmac.new(chain_key, b"lanchat-msgkey-v1", hashlib.sha256).digest()


def chain_next(chain_key: bytes) -> bytes:
    """The next link. It is one-way: holding link n does not reveal any earlier link."""
    return hmac.new(chain_key, b"lanchat-chain-v1", hashlib.sha256).digest()


def chain_advance(chain_key: bytes, steps: int) -> bytes:
    if steps < 0 or steps > MAX_CHAIN_STEPS:
        raise CryptoError("that message number is out of range")
    for _ in range(steps):
        chain_key = chain_next(chain_key)
    return chain_key


def group_aad(sender: str, epoch: int, number: int) -> bytes:
    return f"lanchat-group-v1|{sender.lower()}|{epoch}|{number}".encode()


def group_key_aad(sender: str, recipient: str, epoch: int) -> bytes:
    return f"lanchat-groupkey-v1|{sender.lower()}|{recipient.lower()}|{epoch}".encode()


def encrypt_group(plaintext: bytes, me: Identity, my_name: str, epoch: int, number: int, chain_key: bytes) -> dict:
    """One message to the whole room: encrypted under the sender's chain key for this number, and signed."""
    require()
    aad = group_aad(my_name, epoch, number)
    nonce = os.urandom(12)
    ciphertext = ChaCha20Poly1305(chain_message_key(chain_key)).encrypt(nonce, plaintext, aad)
    signature = me.sign.sign(b"lanchat-group-env-v1" + nonce + ciphertext + aad)
    return {"v": 3, "e": epoch, "n": number, "nn": b64(nonce), "ct": b64(ciphertext), "sig": b64(signature)}


def group_envelope_fields(envelope) -> tuple[int, int]:
    """(epoch, message number) of a group envelope, or raises if it is malformed."""
    try:
        if envelope.get("v") != 3:
            raise CryptoError("not a group message")
        epoch, number = envelope["e"], envelope["n"]
        for value in (epoch, number):
            if not isinstance(value, int) or isinstance(value, bool) or value < 0:
                raise CryptoError("malformed group message")
        for field in ("nn", "ct", "sig"):
            if not isinstance(envelope[field], str):
                raise CryptoError("malformed group message")
        return epoch, number
    except (KeyError, TypeError, AttributeError) as error:
        raise CryptoError("malformed group message") from error


def decrypt_group(envelope: dict, sender_name: str, sender: Bundle, chain_key: bytes) -> bytes:
    """Open a room message given the chain key for its number. Checks the sender's signature first."""
    require()
    epoch, number = group_envelope_fields(envelope)
    aad = group_aad(sender_name, epoch, number)
    nonce, ciphertext, signature = unb64(envelope["nn"]), unb64(envelope["ct"]), unb64(envelope["sig"])
    try:
        Ed25519PublicKey.from_public_bytes(sender.sign).verify(signature, b"lanchat-group-env-v1" + nonce + ciphertext + aad)
    except InvalidSignature as error:
        raise CryptoError("the message is not signed by the person it claims to be from") from error
    except ValueError as error:
        raise CryptoError("the sender's key is not valid") from error
    try:
        return ChaCha20Poly1305(chain_message_key(chain_key)).decrypt(nonce, ciphertext, aad)
    except InvalidTag as error:
        raise CryptoError("the message was altered") from error


def constant_time_equal(a: str, b: str) -> bool:
    return hmac.compare_digest(a.encode(), b.encode())
