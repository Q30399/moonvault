# Changelog

All notable changes to MoonVault will be documented in this file.

## [0.1.0] - 2026-08-12

### Added
- SHA-256, SHA-512, SHA-384, SHA-512/256 hash algorithms (FIPS 180-4)
- HMAC-SHA-256 message authentication code (RFC 2104)
- PBKDF2-HMAC-SHA-256 password-based key derivation (RFC 2898)
- bcrypt password hashing with full Blowfish cipher implementation
- scrypt memory-hard password hashing (RFC 7914, Salsa20/8 core)
- Argon2id memory-hard password hashing (RFC 9106, Blake2b core)
- AES-256-GCM authenticated encryption (FIPS 197, NIST SP 800-38D)
- ChaCha20-Poly1305 AEAD with Poly1305 MAC (RFC 8439)
- HKDF-SHA-256 key derivation (RFC 5869)
- TOTP/HOTP two-factor authentication (RFC 6238, RFC 4226)
- Constant-time comparison utilities for timing attack prevention
- Secure random number generation
- Password strength evaluation and generation
- Base32 encoding/decoding for TOTP secrets
- 71 comprehensive test cases
- GitHub Actions CI configuration
- Complete API documentation in README
