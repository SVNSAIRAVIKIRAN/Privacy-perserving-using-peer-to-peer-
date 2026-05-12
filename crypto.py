import hashlib
import hmac
import secrets
import time

try:
    import bcrypt as _bcrypt
    _HAS_BCRYPT = True
except ImportError:
    _HAS_BCRYPT = False
    import warnings
    warnings.warn('bcrypt not installed — using SHA-256 fallback. Install bcrypt for production!')
bcrypt = None  # accessed via helpers only
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import serialization

from config import BCRYPT_ROUNDS


def generate_anonymous_id(real_id: str) -> str:
    salt = secrets.token_bytes(16)
    return hashlib.sha256(real_id.encode() + salt).hexdigest()


# ── Password hashing ──────────────────────────────────────────────────────────

def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    digest = hashlib.sha256((salt + password).encode()).hexdigest()
    return f"{salt}:{digest}"


def verify_password(password: str, stored_hash: str) -> bool:
    try:
        salt, digest = stored_hash.split(":", 1)
        expected = hashlib.sha256((salt + password).encode()).hexdigest()
        return secrets.compare_digest(expected, digest)
    except Exception:
        return False


def generate_ecc_keys():
    priv = ec.generate_private_key(ec.SECP256R1())
    return priv, priv.public_key()


def compute_shared_secret(private_key, peer_public_key) -> bytes:
    raw = private_key.exchange(ec.ECDH(), peer_public_key)
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"p2p cloud auth v2",
    ).derive(raw)


def authenticate_peers(p1_priv, p1_pub, p2_priv, p2_pub):
    t = time.time()
    s1 = compute_shared_secret(p1_priv, p2_pub)
    s2 = compute_shared_secret(p2_priv, p1_pub)
    elapsed = time.time() - t
    ok = secrets.compare_digest(s1, s2)
    return (s1 if ok else None, elapsed, ok)


def derive_session_key(shared: bytes) -> str:
    return hashlib.sha256(shared).hexdigest()   # 32 bytes → 64 hex chars


# ── Session token ─────────────────────────────────────────────────────────────

def generate_session_token(peer_a: str, peer_b: str, session_key: str) -> tuple[str, str]:
    nonce = secrets.token_hex(16)
    raw = f"{peer_a}:{peer_b}:{session_key}:{nonce}".encode()
    token = hashlib.sha256(raw).hexdigest()
    return token, nonce


def verify_session_token(
    token: str, peer_a: str, peer_b: str, session_key: str, nonce: str
) -> bool:
    raw = f"{peer_a}:{peer_b}:{session_key}:{nonce}".encode()
    expected = hashlib.sha256(raw).hexdigest()
    return secrets.compare_digest(token, expected)


# ── AES-256-GCM file encryption ───────────────────────────────────────────────

def encrypt_file(data: bytes, session_key_hex: str) -> bytes:
    """
    AES-256-GCM encrypt.
    Returns nonce (12 bytes) + ciphertext+tag blob.
    session_key_hex must be 64 hex chars (32 bytes) — full key, never truncated.
    """
    key   = bytes.fromhex(session_key_hex)   # 32 bytes for AES-256
    nonce = secrets.token_bytes(12)          # 96-bit GCM nonce
    ct    = AESGCM(key).encrypt(nonce, data, None)
    return nonce + ct                        # prepend nonce for storage


def ibc_setup():
    master_priv = ec.generate_private_key(ec.SECP256R1())
    master_pub = master_priv.public_key()
    return master_priv, master_pub


def ibc_extract(master_priv, identity: str):
    h = hashlib.sha256(identity.encode()).digest()
    h_int = int.from_bytes(h, 'big')
    order = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551
    scalar = h_int % order
    priv_int = master_priv.private_numbers().private_value
    derived_priv_int = (priv_int * scalar) % order
    return ec.derive_private_key(derived_priv_int, ec.SECP256R1())


def ibc_extract_keys(master_priv, identity: str):
    derived_priv = ibc_extract(master_priv, identity)
    derived_pub = derived_priv.public_key()
    return derived_priv, derived_pub


def serialize_private_key(private_key) -> str:
    pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem.decode()


def deserialize_private_key(pem_str: str):
    return serialization.load_pem_private_key(pem_str.encode(), password=None)


def serialize_public_key(public_key) -> str:
    pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return pem.decode()


def deserialize_public_key(pem_str: str):
    return serialization.load_pem_public_key(pem_str.encode())
