# Secure File Sharing System

This project implements a secure file sharing system using cryptographic primitives to ensure confidentiality, integrity, and authentication in the presence of adversaries. Users can log in, store, edit, and securely share files with other users, even in hostile environments.

## Features

- User authentication and account management
- Secure file storage and access control
- File sharing between users with access revocation support
- End-to-end confidentiality and integrity guarantees
- Resistance to common cryptographic attacks

## Technologies & Cryptographic Libraries Used

This system uses several cryptographic and serialization libraries available in Go:

- `KeyStore`: for securely managing user keys
- `DataStore`: for persistent storage abstraction
- `UUID`: for generating unique identifiers
- `encoding/json`: for marshaling and unmarshaling structured data
- Cryptographic functions from the `crypto` package:
  - **Cryptographic Hashing** (SHA-256)
  - **Symmetric-Key Encryption** (AES-GCM)
  - **HMAC** (Hash-based Message Authentication Code)
  - **Public-Key Encryption** (RSA or ECIES)
  - **Digital Signatures** (RSA/ECDSA)
  - **Password-Based Key Derivation** (PBKDF2)

## Usage

1. Clone the repository:
   ```bash
   git clone https://github.com/sophienazarian/Secure-File-Sharing-System
   cd Secure-File-Sharing-System
