#!/usr/bin/env python3
"""Command-line interface for the Password Manager."""

import argparse
import getpass
import sys
from pathlib import Path

from .manager import (
    PasswordManager,
    AlreadyInitializedError,
    NotInitializedError,
    InvalidPasswordError,
    NotUnlockedError,
)


# Default database location in user's home directory
DEFAULT_DB_PATH = Path.home() / ".password_manager" / "passwords.db"


def get_manager(db_path: str = None) -> PasswordManager:
    """Create a PasswordManager instance with the specified database path."""
    if db_path is None:
        db_path = str(DEFAULT_DB_PATH)
    return PasswordManager(db_path)


def prompt_master_password(prompt: str = "Master password: ") -> str:
    """Securely prompt for the master password."""
    return getpass.getpass(prompt)


def cmd_init(args) -> int:
    """Initialize the password manager with a new master password."""
    manager = get_manager(args.database)

    if manager.is_initialized:
        print("Error: Password Manager is already initialized.")
        print("Use 'change-master' to change the master password.")
        return 1

    print("Setting up Password Manager...")
    print("Choose a strong master password (minimum 8 characters).")
    print()

    password = prompt_master_password("Enter master password: ")
    confirm = prompt_master_password("Confirm master password: ")

    if password != confirm:
        print("Error: Passwords do not match.")
        return 1

    try:
        manager.setup(password)
        print()
        print("Password Manager initialized successfully!")
        print(f"Database location: {args.database or DEFAULT_DB_PATH}")
        print()
        print("IMPORTANT: Remember your master password!")
        print("If you forget it, your stored passwords cannot be recovered.")
        return 0
    except ValueError as e:
        print(f"Error: {e}")
        return 1


def cmd_add(args) -> int:
    """Add a new credential."""
    manager = get_manager(args.database)

    if not manager.is_initialized:
        print("Error: Password Manager is not initialized. Run 'init' first.")
        return 1

    # Unlock the manager
    password = prompt_master_password()
    try:
        manager.unlock(password)
    except InvalidPasswordError:
        print("Error: Invalid master password.")
        return 1

    service = args.service

    # Prompt for username
    username = input("Username: ").strip()
    if not username:
        print("Error: Username cannot be empty.")
        return 1

    # Prompt for password or generate one
    print("Enter password (or press Enter to generate one):")
    credential_password = getpass.getpass("Password: ")

    if not credential_password:
        length = args.generate_length if hasattr(args, 'generate_length') else 16
        credential_password = manager.generate_password(length)
        print(f"Generated password: {credential_password}")

    try:
        manager.add(service, username, credential_password)
        print(f"Credential for '{service}' added successfully!")
        return 0
    except ValueError as e:
        print(f"Error: {e}")
        return 1
    finally:
        manager.lock()


def cmd_get(args) -> int:
    """Retrieve credentials for a service."""
    manager = get_manager(args.database)

    if not manager.is_initialized:
        print("Error: Password Manager is not initialized. Run 'init' first.")
        return 1

    # Unlock the manager
    password = prompt_master_password()
    try:
        manager.unlock(password)
    except InvalidPasswordError:
        print("Error: Invalid master password.")
        return 1

    try:
        credentials = manager.get(args.service)

        if not credentials:
            print(f"No credentials found for '{args.service}'.")
            return 0

        print(f"\nCredentials for '{args.service}':")
        print("-" * 40)

        for cred in credentials:
            print(f"  Username: {cred['username']}")
            if args.show_password:
                print(f"  Password: {cred['password']}")
            else:
                print(f"  Password: {'*' * 12} (use -s to show)")
            print(f"  Created:  {cred['created_at']}")
            print(f"  Updated:  {cred['updated_at']}")
            print()

        # Copy to clipboard hint
        if not args.show_password and len(credentials) == 1:
            print("Tip: Use -s flag to show the password.")

        return 0
    finally:
        manager.lock()


def cmd_list(args) -> int:
    """List all stored services."""
    manager = get_manager(args.database)

    if not manager.is_initialized:
        print("Error: Password Manager is not initialized. Run 'init' first.")
        return 1

    # Unlock the manager
    password = prompt_master_password()
    try:
        manager.unlock(password)
    except InvalidPasswordError:
        print("Error: Invalid master password.")
        return 1

    try:
        services = manager.list_services()

        if not services:
            print("No credentials stored yet.")
            return 0

        print("\nStored services:")
        print("-" * 30)
        for service in services:
            print(f"  - {service}")
        print()
        print(f"Total: {len(services)} service(s)")

        return 0
    finally:
        manager.lock()


def cmd_delete(args) -> int:
    """Delete a credential."""
    manager = get_manager(args.database)

    if not manager.is_initialized:
        print("Error: Password Manager is not initialized. Run 'init' first.")
        return 1

    # Unlock the manager
    password = prompt_master_password()
    try:
        manager.unlock(password)
    except InvalidPasswordError:
        print("Error: Invalid master password.")
        return 1

    try:
        # First, show credentials for this service
        credentials = manager.get(args.service)

        if not credentials:
            print(f"No credentials found for '{args.service}'.")
            return 0

        if len(credentials) == 1:
            cred = credentials[0]
            confirm = input(
                f"Delete credential for '{cred['username']}' at '{args.service}'? (y/N): "
            )
            if confirm.lower() == 'y':
                if manager.delete(args.service, cred['username']):
                    print("Credential deleted successfully.")
                else:
                    print("Error: Failed to delete credential.")
                    return 1
            else:
                print("Deletion cancelled.")
        else:
            print(f"\nMultiple credentials found for '{args.service}':")
            for i, cred in enumerate(credentials, 1):
                print(f"  {i}. {cred['username']}")

            choice = input("\nEnter number to delete (or 'c' to cancel): ")
            if choice.lower() == 'c':
                print("Deletion cancelled.")
                return 0

            try:
                idx = int(choice) - 1
                if 0 <= idx < len(credentials):
                    cred = credentials[idx]
                    if manager.delete_by_id(cred['id']):
                        print(f"Credential for '{cred['username']}' deleted.")
                    else:
                        print("Error: Failed to delete credential.")
                        return 1
                else:
                    print("Invalid selection.")
                    return 1
            except ValueError:
                print("Invalid input.")
                return 1

        return 0
    finally:
        manager.lock()


def cmd_generate(args) -> int:
    """Generate a secure random password."""
    manager = get_manager(args.database)
    password = manager.generate_password(args.length)

    print(f"Generated password: {password}")
    print(f"Length: {len(password)} characters")

    return 0


def menu_add(manager) -> None:
    """Interactive menu: Add a new credential."""
    service = input("Service name (e.g., GitHub, Gmail): ").strip()
    if not service:
        print("Error: Service name cannot be empty.")
        return

    username = input("Username: ").strip()
    if not username:
        print("Error: Username cannot be empty.")
        return

    print("Enter password (or press Enter to generate one):")
    credential_password = getpass.getpass("Password: ")

    if not credential_password:
        credential_password = manager.generate_password(16)
        print(f"Generated password: {credential_password}")

    try:
        manager.add(service, username, credential_password)
        print(f"Credential for '{service}' added successfully!")
    except ValueError as e:
        print(f"Error: {e}")


def menu_view(manager) -> None:
    """Interactive menu: View saved passwords."""
    services = manager.list_services()

    if not services:
        print("No credentials stored yet.")
        return

    print("\nStored services:")
    print("-" * 30)
    for i, service in enumerate(services, 1):
        print(f"  {i}. {service}")
    print()

    choice = input("Enter number to view details (or press Enter to go back): ").strip()
    if not choice:
        return

    try:
        idx = int(choice) - 1
        if 0 <= idx < len(services):
            service = services[idx]
            credentials = manager.get(service)

            print(f"\nCredentials for '{service}':")
            print("-" * 40)

            for cred in credentials:
                print(f"  Username: {cred['username']}")
                print(f"  Password: {cred['password']}")
                print(f"  Created:  {cred['created_at']}")
                print(f"  Updated:  {cred['updated_at']}")
                print()
        else:
            print("Invalid selection.")
    except ValueError:
        print("Invalid input.")


def menu_generate(manager) -> None:
    """Interactive menu: Generate a random password."""
    length_input = input("Password length (default 16): ").strip()

    if length_input:
        try:
            length = int(length_input)
            if length < 8:
                print("Warning: Password length should be at least 8 characters.")
                length = max(length, 4)
        except ValueError:
            print("Invalid length, using default of 16.")
            length = 16
    else:
        length = 16

    password = manager.generate_password(length)
    print(f"\nGenerated password: {password}")
    print(f"Length: {len(password)} characters")


def menu_delete(manager) -> None:
    """Interactive menu: Delete a credential."""
    services = manager.list_services()

    if not services:
        print("No credentials stored yet.")
        return

    print("\nStored services:")
    print("-" * 30)
    for i, service in enumerate(services, 1):
        print(f"  {i}. {service}")
    print()

    choice = input("Enter number to delete (or press Enter to cancel): ").strip()
    if not choice:
        return

    try:
        idx = int(choice) - 1
        if 0 <= idx < len(services):
            service = services[idx]
            credentials = manager.get(service)

            if len(credentials) == 1:
                cred = credentials[0]
                confirm = input(
                    f"Delete credential for '{cred['username']}' at '{service}'? (y/N): "
                )
                if confirm.lower() == 'y':
                    if manager.delete(service, cred['username']):
                        print("Credential deleted successfully.")
                    else:
                        print("Error: Failed to delete credential.")
                else:
                    print("Deletion cancelled.")
            else:
                print(f"\nMultiple credentials found for '{service}':")
                for i, cred in enumerate(credentials, 1):
                    print(f"  {i}. {cred['username']}")

                sub_choice = input("\nEnter number to delete (or 'c' to cancel): ")
                if sub_choice.lower() == 'c':
                    print("Deletion cancelled.")
                    return

                try:
                    sub_idx = int(sub_choice) - 1
                    if 0 <= sub_idx < len(credentials):
                        cred = credentials[sub_idx]
                        if manager.delete_by_id(cred['id']):
                            print(f"Credential for '{cred['username']}' deleted.")
                        else:
                            print("Error: Failed to delete credential.")
                    else:
                        print("Invalid selection.")
                except ValueError:
                    print("Invalid input.")
        else:
            print("Invalid selection.")
    except ValueError:
        print("Invalid input.")


def interactive_menu(manager) -> None:
    """Main interactive menu loop."""
    while True:
        print("\nWhat would you like to do?")
        print("1. Add new password")
        print("2. View saved passwords")
        print("3. Generate a password")
        print("4. Delete a password")
        print("5. Exit")

        choice = input("\nChoice: ").strip()

        if choice == "1":
            menu_add(manager)
        elif choice == "2":
            menu_view(manager)
        elif choice == "3":
            menu_generate(manager)
        elif choice == "4":
            menu_delete(manager)
        elif choice == "5":
            print("\nGoodbye!")
            break
        else:
            print("Invalid choice. Please enter 1-5.")


def cmd_interactive(args) -> int:
    """Run the interactive menu mode."""
    manager = get_manager(args.database)

    print("\n=== Password Manager ===\n")

    if not manager.is_initialized:
        print("Password Manager is not initialized.")
        setup = input("Would you like to set it up now? (y/N): ").strip()
        if setup.lower() != 'y':
            print("Run 'password-manager init' to initialize.")
            return 1

        print("\nChoose a strong master password (minimum 8 characters).\n")
        password = prompt_master_password("Enter master password: ")
        confirm = prompt_master_password("Confirm master password: ")

        if password != confirm:
            print("Error: Passwords do not match.")
            return 1

        try:
            manager.setup(password)
            print("\nPassword Manager initialized successfully!")
            print(f"Database location: {args.database or DEFAULT_DB_PATH}\n")
        except ValueError as e:
            print(f"Error: {e}")
            return 1

        # Unlock after setup
        manager.unlock(password)
        print("Unlocked successfully!")
    else:
        password = prompt_master_password("Enter master password: ")
        try:
            manager.unlock(password)
            print("\nUnlocked successfully!")
        except InvalidPasswordError:
            print("Error: Invalid master password.")
            return 1

    try:
        interactive_menu(manager)
        return 0
    finally:
        manager.lock()


def cmd_change_master(args) -> int:
    """Change the master password."""
    manager = get_manager(args.database)

    if not manager.is_initialized:
        print("Error: Password Manager is not initialized. Run 'init' first.")
        return 1

    print("Changing master password...")
    print("This will re-encrypt all stored credentials.")
    print()

    current_password = prompt_master_password("Current master password: ")
    new_password = prompt_master_password("New master password: ")
    confirm = prompt_master_password("Confirm new password: ")

    if new_password != confirm:
        print("Error: New passwords do not match.")
        return 1

    try:
        manager.change_master_password(current_password, new_password)
        print()
        print("Master password changed successfully!")
        print("All credentials have been re-encrypted.")
        return 0
    except InvalidPasswordError:
        print("Error: Current password is incorrect.")
        return 1
    except ValueError as e:
        print(f"Error: {e}")
        return 1
    finally:
        manager.lock()


def main():
    """Main entry point for the CLI."""
    parser = argparse.ArgumentParser(
        prog="password-manager",
        description="Secure Password Manager with AES-256-GCM encryption"
    )

    parser.add_argument(
        "-d", "--database",
        help=f"Path to database file (default: {DEFAULT_DB_PATH})",
        default=None
    )

    subparsers = parser.add_subparsers(
        title="commands",
        dest="command"
    )

    # init command
    init_parser = subparsers.add_parser(
        "init",
        help="Initialize the password manager with a master password"
    )
    init_parser.set_defaults(func=cmd_init)

    # add command
    add_parser = subparsers.add_parser(
        "add",
        help="Add a new credential"
    )
    add_parser.add_argument(
        "service",
        help="Service name (e.g., GitHub, Gmail)"
    )
    add_parser.add_argument(
        "-g", "--generate-length",
        type=int,
        default=16,
        help="Length for generated password (default: 16)"
    )
    add_parser.set_defaults(func=cmd_add)

    # get command
    get_parser = subparsers.add_parser(
        "get",
        help="Retrieve credentials for a service"
    )
    get_parser.add_argument(
        "service",
        help="Service name to look up"
    )
    get_parser.add_argument(
        "-s", "--show-password",
        action="store_true",
        help="Show the password in plaintext"
    )
    get_parser.set_defaults(func=cmd_get)

    # list command
    list_parser = subparsers.add_parser(
        "list",
        help="List all stored services"
    )
    list_parser.set_defaults(func=cmd_list)

    # delete command
    delete_parser = subparsers.add_parser(
        "delete",
        help="Delete a credential"
    )
    delete_parser.add_argument(
        "service",
        help="Service name"
    )
    delete_parser.set_defaults(func=cmd_delete)

    # generate command
    generate_parser = subparsers.add_parser(
        "generate",
        help="Generate a secure random password"
    )
    generate_parser.add_argument(
        "length",
        type=int,
        nargs="?",
        default=16,
        help="Password length (default: 16)"
    )
    generate_parser.set_defaults(func=cmd_generate)

    # change-master command
    change_master_parser = subparsers.add_parser(
        "change-master",
        help="Change the master password"
    )
    change_master_parser.set_defaults(func=cmd_change_master)

    args = parser.parse_args()

    try:
        # Default to interactive mode if no command specified
        if args.command is None:
            sys.exit(cmd_interactive(args))
        else:
            sys.exit(args.func(args))
    except KeyboardInterrupt:
        print("\nOperation cancelled.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}")
        sys.exit(1)


if __name__ == "__main__":
    main()
