#!/usr/bin/env python3
"""Test script for the Password Manager."""

import os
import sys
import tempfile

# Add the parent directory to the path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from password_manager.manager import (
    PasswordManager,
    AlreadyInitializedError,
    NotInitializedError,
    InvalidPasswordError,
    NotUnlockedError,
)


def test_password_manager():
    """Run comprehensive tests on the Password Manager."""

    # Use a temporary database file
    with tempfile.NamedTemporaryFile(suffix='.db', delete=False) as f:
        db_path = f.name

    print(f"Testing with database: {db_path}")
    print("=" * 50)

    try:
        # Test 1: Initialize manager
        print("\n[Test 1] Initializing Password Manager...")
        pm = PasswordManager(db_path)
        assert not pm.is_initialized, "Should not be initialized yet"

        pm.setup("MySecureMasterPassword123!")
        assert pm.is_initialized, "Should be initialized now"
        assert pm.is_unlocked, "Should be unlocked after setup"
        print("  [OK] Initialization successful")

        # Test 2: Try to initialize again (should fail)
        print("\n[Test 2] Testing double initialization prevention...")
        try:
            pm.setup("AnotherPassword")
            assert False, "Should have raised AlreadyInitializedError"
        except AlreadyInitializedError:
            print("  [OK] Double initialization prevented")

        # Test 3: Add credentials
        print("\n[Test 3] Adding credentials...")
        pm.add("GitHub", "user@example.com", "github_secret_123")
        pm.add("Gmail", "user@example.com", "gmail_password_456")
        pm.add("GitHub", "work@company.com", "work_github_pass")
        print("  [OK] Added 3 credentials")

        # Test 4: List services
        print("\n[Test 4] Listing services...")
        services = pm.list_services()
        assert "GitHub" in services, "GitHub should be in services"
        assert "Gmail" in services, "Gmail should be in services"
        print(f"  [OK] Services: {services}")

        # Test 5: Retrieve credentials
        print("\n[Test 5] Retrieving credentials...")
        github_creds = pm.get("GitHub")
        assert len(github_creds) == 2, "Should have 2 GitHub credentials"

        for cred in github_creds:
            print(f"  - {cred['username']}: {cred['password']}")

        gmail_creds = pm.get("Gmail")
        assert len(gmail_creds) == 1, "Should have 1 Gmail credential"
        assert gmail_creds[0]['password'] == "gmail_password_456"
        print("  [OK] Credentials retrieved and decrypted correctly")

        # Test 6: Lock and unlock
        print("\n[Test 6] Testing lock/unlock...")
        pm.lock()
        assert not pm.is_unlocked, "Should be locked"

        try:
            pm.get("GitHub")
            assert False, "Should have raised NotUnlockedError"
        except NotUnlockedError:
            print("  [OK] Access denied when locked")

        # Test 7: Unlock with correct password
        print("\n[Test 7] Testing unlock with correct password...")
        pm.unlock("MySecureMasterPassword123!")
        assert pm.is_unlocked, "Should be unlocked"
        print("  [OK] Unlock successful")

        # Test 8: Unlock with wrong password
        print("\n[Test 8] Testing unlock with wrong password...")
        pm.lock()
        try:
            pm.unlock("WrongPassword")
            assert False, "Should have raised InvalidPasswordError"
        except InvalidPasswordError:
            print("  [OK] Invalid password rejected")

        # Test 9: Generate password
        print("\n[Test 9] Testing password generation...")
        pm.unlock("MySecureMasterPassword123!")

        gen_pass = pm.generate_password(20)
        assert len(gen_pass) == 20, "Generated password should be 20 chars"
        print(f"  [OK] Generated password: {gen_pass}")

        # Test 10: Update password
        print("\n[Test 10] Testing password update...")
        github_creds = pm.get("GitHub")
        cred_id = github_creds[0]['id']
        pm.update_password(cred_id, "new_updated_password")

        updated_creds = pm.get("GitHub")
        updated_cred = next(c for c in updated_creds if c['id'] == cred_id)
        assert updated_cred['password'] == "new_updated_password"
        print("  [OK] Password updated successfully")

        # Test 11: Delete credential
        print("\n[Test 11] Testing credential deletion...")
        pm.delete("Gmail", "user@example.com")
        gmail_creds = pm.get("Gmail")
        assert len(gmail_creds) == 0, "Gmail credential should be deleted"
        print("  [OK] Credential deleted")

        # Test 12: Change master password
        print("\n[Test 12] Testing master password change...")
        pm.change_master_password(
            "MySecureMasterPassword123!",
            "NewMasterPassword456!"
        )

        # Verify old password no longer works
        pm.lock()
        try:
            pm.unlock("MySecureMasterPassword123!")
            assert False, "Old password should not work"
        except InvalidPasswordError:
            print("  [OK] Old password rejected")

        # Verify new password works
        pm.unlock("NewMasterPassword456!")
        print("  [OK] New password accepted")

        # Verify credentials are still accessible
        github_creds = pm.get("GitHub")
        assert len(github_creds) == 2, "Should still have 2 GitHub credentials"
        print("  [OK] Credentials still accessible after password change")

        print("\n" + "=" * 50)
        print("ALL TESTS PASSED!")
        print("=" * 50)

    finally:
        # Cleanup
        if os.path.exists(db_path):
            os.remove(db_path)
            print(f"\nCleaned up test database: {db_path}")


if __name__ == "__main__":
    test_password_manager()
