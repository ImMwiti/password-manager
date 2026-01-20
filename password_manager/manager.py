"""Core Password Manager business logic."""

from typing import Optional
from . import crypto
from . import database


class PasswordManagerError(Exception):
    """Base exception for Password Manager errors."""
    pass


class NotInitializedError(PasswordManagerError):
    """Raised when trying to use manager before initialization."""
    pass


class AlreadyInitializedError(PasswordManagerError):
    """Raised when trying to initialize an already initialized manager."""
    pass


class NotUnlockedError(PasswordManagerError):
    """Raised when trying to access credentials without unlocking."""
    pass


class InvalidPasswordError(PasswordManagerError):
    """Raised when master password verification fails."""
    pass


class CredentialNotFoundError(PasswordManagerError):
    """Raised when a requested credential doesn't exist."""
    pass


class PasswordManager:
    """
    Secure Password Manager with AES-256-GCM encryption.

    This class manages encrypted credential storage using a master password.
    The master password is used to derive an encryption key via Argon2id,
    and all stored passwords are encrypted with AES-256-GCM.
    """

    def __init__(self, db_path: str = "passwords.db"):
        """
        Initialize the Password Manager.

        Args:
            db_path: Path to the SQLite database file
        """
        self.db_path = db_path
        self._key: Optional[bytes] = None
        self._salt: Optional[bytes] = None

        # Initialize database tables
        database.init_db(self.db_path)

    @property
    def is_initialized(self) -> bool:
        """Check if a master password has been set."""
        return database.is_initialized(self.db_path)

    @property
    def is_unlocked(self) -> bool:
        """Check if the manager is unlocked (key is available)."""
        return self._key is not None

    def setup(self, master_password: str) -> None:
        """
        Set up the Password Manager with a master password (first-time setup).

        Args:
            master_password: The master password to use

        Raises:
            AlreadyInitializedError: If master password is already set
            ValueError: If password is empty or too short
        """
        if self.is_initialized:
            raise AlreadyInitializedError(
                "Password Manager is already initialized. "
                "Use change_master_password() to change the master password."
            )

        if not master_password or len(master_password) < 8:
            raise ValueError("Master password must be at least 8 characters long")

        # Generate salt and verification hash
        salt = crypto.generate_salt()
        verification_hash = crypto.hash_master_password(master_password, salt)

        # Store in database
        database.store_master(self.db_path, salt, verification_hash)

        # Derive and store key in memory
        self._salt = salt
        self._key = crypto.derive_key(master_password, salt)

    def unlock(self, master_password: str) -> bool:
        """
        Verify master password and unlock the manager.

        Args:
            master_password: The master password to verify

        Returns:
            True if unlock was successful

        Raises:
            NotInitializedError: If master password hasn't been set
            InvalidPasswordError: If the password is incorrect
        """
        if not self.is_initialized:
            raise NotInitializedError(
                "Password Manager is not initialized. Run setup first."
            )

        master_data = database.get_master(self.db_path)
        if not master_data:
            raise NotInitializedError("Master password data not found.")

        salt, verification_hash = master_data

        if not crypto.verify_master_password(master_password, salt, verification_hash):
            raise InvalidPasswordError("Invalid master password.")

        # Derive and store key in memory
        self._salt = salt
        self._key = crypto.derive_key(master_password, salt)

        return True

    def lock(self) -> None:
        """
        Lock the manager by clearing the encryption key from memory.

        After calling this, unlock() must be called again to access credentials.
        """
        self._key = None
        # Note: In a production system, you might want to use secure memory
        # clearing techniques here to prevent key recovery from memory dumps

    def _require_unlocked(self) -> None:
        """Ensure the manager is unlocked before operations."""
        if not self.is_unlocked:
            raise NotUnlockedError(
                "Password Manager is locked. Call unlock() first."
            )

    def add(self, service: str, username: str, password: str) -> int:
        """
        Add a new credential.

        Args:
            service: Service name (e.g., "GitHub", "Gmail")
            username: Username for the service
            password: Password to store (will be encrypted)

        Returns:
            The ID of the newly added credential

        Raises:
            NotUnlockedError: If the manager is locked
            ValueError: If any parameter is empty
        """
        self._require_unlocked()

        if not service or not service.strip():
            raise ValueError("Service name cannot be empty")
        if not username or not username.strip():
            raise ValueError("Username cannot be empty")
        if not password:
            raise ValueError("Password cannot be empty")

        # Encrypt the password
        encrypted_password, nonce = crypto.encrypt(password, self._key)

        # Store in database
        credential_id = database.add_credential(
            self.db_path,
            service.strip(),
            username.strip(),
            encrypted_password,
            nonce
        )

        return credential_id

    def get(self, service: str) -> list[dict]:
        """
        Retrieve credentials for a service.

        Args:
            service: Service name to look up

        Returns:
            List of credential dictionaries with 'id', 'service',
            'username', 'password', 'created_at', 'updated_at'

        Raises:
            NotUnlockedError: If the manager is locked
        """
        self._require_unlocked()

        credentials = database.get_credential(self.db_path, service)

        results = []
        for cred in credentials:
            # Decrypt the password
            decrypted_password = crypto.decrypt(
                cred['encrypted_password'],
                cred['nonce'],
                self._key
            )

            results.append({
                'id': cred['id'],
                'service': cred['service'],
                'username': cred['username'],
                'password': decrypted_password,
                'created_at': cred['created_at'],
                'updated_at': cred['updated_at']
            })

        return results

    def list_services(self) -> list[str]:
        """
        List all stored service names.

        Returns:
            List of unique service names

        Raises:
            NotUnlockedError: If the manager is locked
        """
        self._require_unlocked()
        return database.list_services(self.db_path)

    def delete(self, service: str, username: str) -> bool:
        """
        Delete a credential by service and username.

        Args:
            service: Service name
            username: Username

        Returns:
            True if deleted, False if not found

        Raises:
            NotUnlockedError: If the manager is locked
        """
        self._require_unlocked()
        return database.delete_credential_by_service_username(
            self.db_path, service, username
        )

    def delete_by_id(self, credential_id: int) -> bool:
        """
        Delete a credential by its ID.

        Args:
            credential_id: ID of the credential to delete

        Returns:
            True if deleted, False if not found

        Raises:
            NotUnlockedError: If the manager is locked
        """
        self._require_unlocked()
        return database.delete_credential(self.db_path, credential_id)

    def update_password(self, credential_id: int, new_password: str) -> bool:
        """
        Update the password for an existing credential.

        Args:
            credential_id: ID of the credential to update
            new_password: New password to set

        Returns:
            True if updated, False if credential not found

        Raises:
            NotUnlockedError: If the manager is locked
            ValueError: If new_password is empty
        """
        self._require_unlocked()

        if not new_password:
            raise ValueError("Password cannot be empty")

        # Encrypt the new password
        encrypted_password, nonce = crypto.encrypt(new_password, self._key)

        return database.update_credential(
            self.db_path, credential_id, encrypted_password, nonce
        )

    def generate_password(self, length: int = 16) -> str:
        """
        Generate a secure random password.

        Args:
            length: Desired password length (minimum 8)

        Returns:
            Randomly generated password string
        """
        return crypto.generate_password(length)

    def change_master_password(
        self,
        current_password: str,
        new_password: str
    ) -> None:
        """
        Change the master password and re-encrypt all stored credentials.

        Args:
            current_password: Current master password (for verification)
            new_password: New master password to set

        Raises:
            NotInitializedError: If manager isn't initialized
            InvalidPasswordError: If current password is wrong
            ValueError: If new password is invalid
        """
        # Verify current password and unlock if needed
        if not self.is_unlocked:
            self.unlock(current_password)
        else:
            # Verify the current password even if already unlocked
            master_data = database.get_master(self.db_path)
            salt, verification_hash = master_data
            if not crypto.verify_master_password(
                current_password, salt, verification_hash
            ):
                raise InvalidPasswordError("Current password is incorrect")

        if not new_password or len(new_password) < 8:
            raise ValueError("New password must be at least 8 characters long")

        # Get all credentials and decrypt them with old key
        all_credentials = database.get_all_credentials(self.db_path)
        decrypted_credentials = []

        for cred in all_credentials:
            decrypted_password = crypto.decrypt(
                cred['encrypted_password'],
                cred['nonce'],
                self._key
            )
            decrypted_credentials.append({
                'service': cred['service'],
                'username': cred['username'],
                'password': decrypted_password
            })

        # Generate new salt and key
        new_salt = crypto.generate_salt()
        new_verification_hash = crypto.hash_master_password(new_password, new_salt)
        new_key = crypto.derive_key(new_password, new_salt)

        # Update master password in database
        database.store_master(self.db_path, new_salt, new_verification_hash)

        # Clear all credentials
        database.clear_all_credentials(self.db_path)

        # Re-encrypt and store all credentials with new key
        for cred in decrypted_credentials:
            encrypted_password, nonce = crypto.encrypt(cred['password'], new_key)
            database.add_credential(
                self.db_path,
                cred['service'],
                cred['username'],
                encrypted_password,
                nonce
            )

        # Update internal state
        self._salt = new_salt
        self._key = new_key
