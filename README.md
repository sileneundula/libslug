# Slug20 Library

## Description

`slug20` is a tool used to encrypt data inspired by **minisign**. It is simple, minimilastic, and has advanced security built-in. It implements `zeroize`, `subtle`, and `subtle-encoding` for maxmimum security.

On top of encryption, it creates a new standard for Modern Certificates using YAML. Its format (`X59CERT`) is lightweight and can easily be serialized.

It extends to include development of modern, decentralized PKI systems and modular formats for use with different systems.

## Features

- **Default Encryption:** ECIES Encryption over Curve25519 using AES-GCM
- **Post-Quantum Encryption:** ML-KEM
- **Signature Schemes:** ED25519, Schnorr over Ristretto (Curve25519)
- **Post-Quantum Signature Schemes:** SPHINCS+ (SHAKE256) (Level 5), ML_DSA56 (Level 3), FALCON1024
- **Cert Format:** X59 Certificate Standard
- **Message-Types:** Supports UTF-8 Messages (so we can include emojis)
- **Encryption:** AES-GCM 256 + XChaCha20-Poly1305
- **Randomness Generation:** Supports Randomness Generation from the Operating System. Supports VRFs via Schnorr

## X59Registar

X59Registar is a novel project being developed for decentralized public-key infrastructures using the X59CERT format in YAML.
