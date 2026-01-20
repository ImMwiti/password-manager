"""SQLite database operations for the Password Manager."""

import sqlite3
from pathlib import Path
from typing import Optional


def get_connection(db_path: str) -> sqlite3.Connection:
    """Get a database connection with row factory enabled."""
    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db(db_path: str) -> None:
    """
    Initialize the database with required tables.

    Creates the master and credentials tables if they don't exist.

    Args:
        db_path: Path to the SQLite database file
    """
    # Ensure parent directory exists
    Path(db_path).parent.mkdir(parents=True, exist_ok=True)

    conn = get_connection(db_path)
    cursor = conn.cursor()

    # Master password verification table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS master (
            id INTEGER PRIMARY KEY,
            salt BLOB NOT NULL,
            verification_hash BLOB NOT NULL
        )
    ''')

    # Encrypted credentials table
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS credentials (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            service TEXT NOT NULL,
            username TEXT NOT NULL,
            encrypted_password BLOB NOT NULL,
            nonce BLOB NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')

    # Index for faster service lookups
    cursor.execute('''
        CREATE INDEX IF NOT EXISTS idx_credentials_service
        ON credentials(service)
    ''')

    conn.commit()
    conn.close()


def is_initialized(db_path: str) -> bool:
    """
    Check if the database has been initialized with a master password.

    Args:
        db_path: Path to the SQLite database file

    Returns:
        True if master password is set, False otherwise
    """
    if not Path(db_path).exists():
        return False

    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute('SELECT COUNT(*) FROM master')
    count = cursor.fetchone()[0]

    conn.close()
    return count > 0


def store_master(db_path: str, salt: bytes, verification_hash: bytes) -> None:
    """
    Store the master password salt and verification hash.

    Args:
        db_path: Path to the SQLite database file
        salt: Random salt used for key derivation
        verification_hash: Argon2id hash for password verification
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()

    # Clear any existing master entry and insert new one
    cursor.execute('DELETE FROM master')
    cursor.execute(
        'INSERT INTO master (id, salt, verification_hash) VALUES (1, ?, ?)',
        (salt, verification_hash)
    )

    conn.commit()
    conn.close()


def get_master(db_path: str) -> Optional[tuple[bytes, bytes]]:
    """
    Retrieve the master password salt and verification hash.

    Args:
        db_path: Path to the SQLite database file

    Returns:
        Tuple of (salt, verification_hash) or None if not set
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute('SELECT salt, verification_hash FROM master WHERE id = 1')
    row = cursor.fetchone()

    conn.close()

    if row:
        return (row['salt'], row['verification_hash'])
    return None


def add_credential(
    db_path: str,
    service: str,
    username: str,
    encrypted_password: bytes,
    nonce: bytes
) -> int:
    """
    Add a new encrypted credential to the database.

    Args:
        db_path: Path to the SQLite database file
        service: Service name (e.g., "GitHub")
        username: Username for the service
        encrypted_password: AES-GCM encrypted password
        nonce: Nonce used for encryption

    Returns:
        The ID of the newly inserted credential
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute(
        '''INSERT INTO credentials (service, username, encrypted_password, nonce)
           VALUES (?, ?, ?, ?)''',
        (service, username, encrypted_password, nonce)
    )

    credential_id = cursor.lastrowid
    conn.commit()
    conn.close()

    return credential_id


def get_credential(db_path: str, service: str) -> list[dict]:
    """
    Retrieve all credentials for a given service.

    Args:
        db_path: Path to the SQLite database file
        service: Service name to search for (case-insensitive)

    Returns:
        List of credential dictionaries with id, service, username,
        encrypted_password, nonce, created_at, updated_at
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute(
        '''SELECT id, service, username, encrypted_password, nonce,
                  created_at, updated_at
           FROM credentials
           WHERE LOWER(service) = LOWER(?)''',
        (service,)
    )

    results = []
    for row in cursor.fetchall():
        results.append({
            'id': row['id'],
            'service': row['service'],
            'username': row['username'],
            'encrypted_password': row['encrypted_password'],
            'nonce': row['nonce'],
            'created_at': row['created_at'],
            'updated_at': row['updated_at']
        })

    conn.close()
    return results


def get_all_credentials(db_path: str) -> list[dict]:
    """
    Retrieve all credentials from the database.

    Args:
        db_path: Path to the SQLite database file

    Returns:
        List of all credential dictionaries
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute(
        '''SELECT id, service, username, encrypted_password, nonce,
                  created_at, updated_at
           FROM credentials
           ORDER BY service, username'''
    )

    results = []
    for row in cursor.fetchall():
        results.append({
            'id': row['id'],
            'service': row['service'],
            'username': row['username'],
            'encrypted_password': row['encrypted_password'],
            'nonce': row['nonce'],
            'created_at': row['created_at'],
            'updated_at': row['updated_at']
        })

    conn.close()
    return results


def list_services(db_path: str) -> list[str]:
    """
    List all unique service names in the database.

    Args:
        db_path: Path to the SQLite database file

    Returns:
        List of unique service names, sorted alphabetically
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute(
        'SELECT DISTINCT service FROM credentials ORDER BY service'
    )

    services = [row['service'] for row in cursor.fetchall()]

    conn.close()
    return services


def delete_credential(db_path: str, credential_id: int) -> bool:
    """
    Delete a credential by its ID.

    Args:
        db_path: Path to the SQLite database file
        credential_id: ID of the credential to delete

    Returns:
        True if a credential was deleted, False if not found
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute('DELETE FROM credentials WHERE id = ?', (credential_id,))

    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()

    return deleted


def delete_credential_by_service_username(
    db_path: str,
    service: str,
    username: str
) -> bool:
    """
    Delete a credential by service and username.

    Args:
        db_path: Path to the SQLite database file
        service: Service name
        username: Username

    Returns:
        True if a credential was deleted, False if not found
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute(
        '''DELETE FROM credentials
           WHERE LOWER(service) = LOWER(?) AND username = ?''',
        (service, username)
    )

    deleted = cursor.rowcount > 0
    conn.commit()
    conn.close()

    return deleted


def update_credential(
    db_path: str,
    credential_id: int,
    encrypted_password: bytes,
    nonce: bytes
) -> bool:
    """
    Update an existing credential's encrypted password.

    Args:
        db_path: Path to the SQLite database file
        credential_id: ID of the credential to update
        encrypted_password: New encrypted password
        nonce: New nonce used for encryption

    Returns:
        True if updated, False if credential not found
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute(
        '''UPDATE credentials
           SET encrypted_password = ?, nonce = ?, updated_at = CURRENT_TIMESTAMP
           WHERE id = ?''',
        (encrypted_password, nonce, credential_id)
    )

    updated = cursor.rowcount > 0
    conn.commit()
    conn.close()

    return updated


def clear_all_credentials(db_path: str) -> None:
    """
    Delete all credentials from the database.

    Used during master password change to re-encrypt all data.

    Args:
        db_path: Path to the SQLite database file
    """
    conn = get_connection(db_path)
    cursor = conn.cursor()

    cursor.execute('DELETE FROM credentials')

    conn.commit()
    conn.close()
