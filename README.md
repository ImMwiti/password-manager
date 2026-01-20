# Password Manager

A secure command-line password manager built with Python, using industry-standard cryptography.

## Features

- **Argon2id** key derivation (memory-hard, resistant to GPU/ASIC attacks)
- **AES-256-GCM** authenticated encryption
- SQLite storage for encrypted credentials
- Secure random password generation
- Master password change with automatic re-encryption

## Installation

```bash
# Clone the repository
git clone https://github.com/ImMwiti/password-manager.git
cd password-manager

# Install dependencies
pip install -r password_manager/requirements.txt
```

## Usage

### Initialize (first-time setup)
```bash
python -m password_manager.main init
```

### Add a credential
```bash
python -m password_manager.main add github
```

### Retrieve a credential
```bash
python -m password_manager.main get github -s
```

### List all services
```bash
python -m password_manager.main list
```

### Delete a credential
```bash
python -m password_manager.main delete github
```

### Generate a secure password
```bash
python -m password_manager.main generate 20
```

### Change master password
```bash
python -m password_manager.main change-master
```

## Security

| Component | Implementation |
|-----------|----------------|
| Key Derivation | Argon2id (64MB memory, 3 iterations, 4 parallelism) |
| Encryption | AES-256-GCM with unique 96-bit nonces |
| Storage | SQLite with encrypted passwords only |
| Master Password | Never stored, only verification hash |

### Security Properties

- **Master password is never stored** - only a verification hash
- **Each password encrypted independently** - with unique random nonces
- **Authenticated encryption** - detects tampering via GCM authentication tag
- **Memory-hard KDF** - Argon2id resistant to brute-force attacks

## Project Structure

```
password_manager/
├── __init__.py          # Package initialization
├── main.py              # CLI entry point
├── crypto.py            # Cryptographic operations
├── database.py          # SQLite operations
├── manager.py           # Core PasswordManager class
└── requirements.txt     # Dependencies
```

## Dependencies

- `cryptography` - AES-GCM implementation
- `argon2-cffi` - Argon2id key derivation
- `sqlite3` - Built-in Python module

## License

MIT
