"""Cryptographic operations for the Password Manager."""

import secrets
import string
from argon2 import PasswordHasher
from argon2.low_level import hash_secret_raw, Type
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


# Argon2id parameters
ARGON2_MEMORY_COST = 65536  # 64 MB
ARGON2_TIME_COST = 3        # 3 iterations
ARGON2_PARALLELISM = 4      # 4 parallel threads
ARGON2_HASH_LEN = 32        # 256-bit key

SALT_LENGTH = 16            # 16 bytes
NONCE_LENGTH = 12           # 96-bit nonce for AES-GCM


def generate_salt() -> bytes:
    """Generate a cryptographically secure random 16-byte salt."""
    return secrets.token_bytes(SALT_LENGTH)


def derive_key(password: str, salt: bytes) -> bytes:
    """
    Derive a 256-bit encryption key from password using Argon2id.

    Args:
        password: The master password
        salt: Random salt bytes

    Returns:
        32-byte derived key suitable for AES-256
    """
    return hash_secret_raw(
        secret=password.encode('utf-8'),
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID  # Argon2id
    )


def hash_master_password(password: str, salt: bytes) -> bytes:
    """
    Create a verification hash of the master password.

    This uses the high-level Argon2 hasher which includes its own
    internal salt and parameters in the output, suitable for verification.

    Args:
        password: The master password
        salt: Salt to incorporate (used as a prefix to password for domain separation)

    Returns:
        Argon2id hash bytes for verification
    """
    ph = PasswordHasher(
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID
    )
    # Combine salt with password for domain separation
    combined = salt.hex() + password
    return ph.hash(combined).encode('utf-8')


def verify_master_password(password: str, salt: bytes, hash_bytes: bytes) -> bool:
    """
    Verify a master password against its stored hash.

    Args:
        password: The password to verify
        salt: The original salt used during hashing
        hash_bytes: The stored hash to verify against

    Returns:
        True if password is correct, False otherwise
    """
    ph = PasswordHasher(
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID
    )
    combined = salt.hex() + password
    try:
        ph.verify(hash_bytes.decode('utf-8'), combined)
        return True
    except Exception:
        return False


def encrypt(plaintext: str, key: bytes) -> tuple[bytes, bytes]:
    """
    Encrypt plaintext using AES-256-GCM.

    Args:
        plaintext: The string to encrypt
        key: 32-byte encryption key

    Returns:
        Tuple of (ciphertext, nonce)
    """
    nonce = secrets.token_bytes(NONCE_LENGTH)
    aesgcm = AESGCM(key)
    ciphertext = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
    return ciphertext, nonce


def decrypt(ciphertext: bytes, nonce: bytes, key: bytes) -> str:
    """
    Decrypt ciphertext using AES-256-GCM.

    Args:
        ciphertext: The encrypted data (includes GCM tag)
        nonce: The 12-byte nonce used during encryption
        key: 32-byte encryption key

    Returns:
        Decrypted plaintext string

    Raises:
        cryptography.exceptions.InvalidTag: If decryption fails (wrong key or tampered data)
    """
    aesgcm = AESGCM(key)
    plaintext = aesgcm.decrypt(nonce, ciphertext, None)
    return plaintext.decode('utf-8')


def generate_password(length: int = 16) -> str:
    """
    Generate a cryptographically secure random password.

    The password will contain a mix of uppercase, lowercase,
    digits, and special characters.

    Args:
        length: Desired password length (minimum 8, default 16)

    Returns:
        Randomly generated password string
    """
    if length < 8:
        length = 8

    # Character sets
    lowercase = string.ascii_lowercase
    uppercase = string.ascii_uppercase
    digits = string.digits
    special = "!@#$%^&*()_+-=[]{}|;:,.<>?"

    all_chars = lowercase + uppercase + digits + special

    # Ensure at least one character from each category
    password = [
        secrets.choice(lowercase),
        secrets.choice(uppercase),
        secrets.choice(digits),
        secrets.choice(special),
    ]

    # Fill the rest randomly
    password.extend(secrets.choice(all_chars) for _ in range(length - 4))

    # Shuffle to avoid predictable positions
    password_list = list(password)
    secrets.SystemRandom().shuffle(password_list)

    return ''.join(password_list)
