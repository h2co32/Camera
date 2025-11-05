# PQCamera Decrypt - Post-Quantum Photo Decryption Utility

A command-line utility for decrypting photos encrypted with ML-KEM-768 (Kyber768) by the GrapheneOS Camera app.

## Features

- **Post-Quantum Secure**: Uses ML-KEM-768 (NIST FIPS 203) for key encapsulation
- **Authenticated Encryption**: ChaCha20-Poly1305 for fast, secure photo decryption
- **Cross-Platform**: Compiles to native binaries for Windows, macOS, and Linux
- **Simple CLI**: Easy-to-use command-line interface

## Installation

### Prerequisites

- [Rust](https://www.rust-lang.org/tools/install) (1.70 or later)

### Building from Source

```bash
cd pqcamera-decrypt
cargo build --release
```

The compiled binary will be in `target/release/pqcamera-decrypt` (or `.exe` on Windows).

### Installing

```bash
cargo install --path .
```

This installs `pqcamera-decrypt` to your Cargo bin directory.

## Usage

Basic usage:

```bash
pqcamera-decrypt -i encrypted_photo.pqcenc -k private_key.pem
```

Specify output path:

```bash
pqcamera-decrypt -i encrypted_photo.pqcenc -k private_key.pem -o decrypted.jpg
```

### Options

- `-i, --input <FILE>` - Path to the encrypted photo file (.pqcenc)
- `-k, --private-key <FILE>` - Path to the ML-KEM-768 private key file (PEM format)
- `-o, --output <FILE>` - Output path for decrypted JPEG (optional, defaults to input with .jpg extension)
- `-h, --help` - Print help information
- `-V, --version` - Print version information

## File Format

Encrypted files use the following format:

```
[MAGIC: "PQCAMENC" 8 bytes]
[VERSION: 4 bytes, little-endian]
[KEM_CIPHERTEXT_LENGTH: 4 bytes, little-endian]
[KEM_CIPHERTEXT: ~1088 bytes for ML-KEM-768]
[NONCE: 12 bytes]
[ENCRYPTED_JPEG + AUTH_TAG: remaining bytes]
```

## Security

- **ML-KEM-768**: 256-bit post-quantum security level
- **ChaCha20-Poly1305**: Authenticated encryption with 256-bit keys
- **HKDF-SHA256**: Key derivation from KEM shared secret

## Example Workflow

1. Generate a keypair in the Camera app
2. Export the private key to your computer
3. Take encrypted photos
4. Transfer encrypted photos to your computer
5. Decrypt using this utility:

```bash
pqcamera-decrypt -i IMG_20250101_120000_000.pqcenc -k camera_mlkem_private_key_*.pem
```

## Building for Different Platforms

### Windows

```bash
cargo build --release --target x86_64-pc-windows-msvc
```

### macOS

```bash
cargo build --release --target x86_64-apple-darwin  # Intel
cargo build --release --target aarch64-apple-darwin  # Apple Silicon
```

### Linux

```bash
cargo build --release --target x86_64-unknown-linux-gnu
```

## License

This utility is part of the GrapheneOS Camera project.

## Security Considerations

**IMPORTANT**: Keep your private key safe! Without it, encrypted photos cannot be recovered.

- Store private keys securely (encrypted storage, password manager, etc.)
- Never share your private key
- Make backups of your private key in secure locations
- Consider using different keypairs for different purposes
