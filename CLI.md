# CryptoShift CLI

Command-line interface for CryptoShift cryptographic operations.

## Installation

```bash
# Build the CLI
cargo build --release --features cli

# Install system-wide
cargo install --path . --features cli
```

## Usage

### List Supported Algorithms

```bash
# List all algorithms
cryptoshift list

# List only classical algorithms
cryptoshift list --filter classical

# List only post-quantum algorithms
cryptoshift list --filter post-quantum
```

### Get Algorithm Information

```bash
cryptoshift info ed25519
cryptoshift info dilithium3
cryptoshift info ecdsa-p384
```

### Generate Key Pairs

**Classical algorithms:**
```bash
# Generate Ed25519 key pair
cryptoshift keygen --algorithm ed25519 --output mykey

# Generate RSA-4096 key pair
cryptoshift keygen --algorithm rsa4096 --output rsakey

# Generate ECDSA P-384 key pair
cryptoshift keygen --algorithm ecdsa-p384 --output eckey
```

**Post-quantum algorithms:**
```bash
# Generate Dilithium3 key pair (recommended)
cryptoshift keygen --algorithm dilithium3 --output pqckey

# Generate Dilithium5 key pair (high security)
cryptoshift keygen --algorithm dilithium5 --output highsec
```

**Hybrid mode:**
```bash
# Generate hybrid key pair (Ed25519 + Dilithium3)
cryptoshift keygen --algorithm default --output hybrid --hybrid

# Generate high-security hybrid (P-384 + Dilithium5)
cryptoshift keygen --algorithm high-security --output hybrid --hybrid
```

This creates multiple files:
- `hybrid.classical.pub` / `hybrid.classical.key` - Classical keys
- `hybrid.pqc.pub` / `hybrid.pqc.key` - Post-quantum keys

### Sign Messages

**Sign a string:**
```bash
cryptoshift sign \
    --key mykey.key \
    --input "Hello, CryptoShift!" \
    --output message.sig
```

**Sign a file:**
```bash
cryptoshift sign \
    --key mykey.key \
    --input document.pdf \
    --output document.sig \
    --file
```

### Verify Signatures

**Verify a string signature:**
```bash
cryptoshift verify \
    --key mykey.pub \
    --input "Hello, CryptoShift!" \
    --signature message.sig
```

**Verify a file signature:**
```bash
cryptoshift verify \
    --key mykey.pub \
    --input document.pdf \
    --signature document.sig \
    --file
```

## Examples

### Complete Workflow

```bash
# 1. Generate a post-quantum key pair
cryptoshift keygen --algorithm dilithium3 --output mykey

# 2. Sign a message
echo "Important message" > message.txt
cryptoshift sign --key mykey.key --input message.txt --output message.sig --file

# 3. Verify the signature
cryptoshift verify --key mykey.pub --input message.txt --signature message.sig --file
# Output: Signature is VALID
```

### Hybrid Cryptography Workflow

```bash
# 1. Generate hybrid keys
cryptoshift keygen --algorithm default --output hybrid --hybrid

# 2. You now have 4 files:
#    - hybrid.classical.pub/.key (Ed25519)
#    - hybrid.pqc.pub/.key (Dilithium3)

# 3. Sign with classical algorithm
cryptoshift sign --key hybrid.classical.key --input data.txt --output classical.sig --file

# 4. Sign with post-quantum algorithm
cryptoshift sign --key hybrid.pqc.key --input data.txt --output pqc.sig --file

# 5. Verify both signatures
cryptoshift verify --key hybrid.classical.pub --input data.txt --signature classical.sig --file
cryptoshift verify --key hybrid.pqc.pub --input data.txt --signature pqc.sig --file
```

## Supported Algorithms

### Classical
- `ed25519` - EdDSA (128-bit security) - **Recommended**
- `rsa2048` - RSA 2048-bit (112-bit security)
- `rsa3072` - RSA 3072-bit (128-bit security)
- `rsa4096` - RSA 4096-bit (152-bit security)
- `ecdsa-p256` - ECDSA P-256 (128-bit security)
- `ecdsa-p384` - ECDSA P-384 (192-bit security)

### Post-Quantum (NIST-approved)
- `dilithium2` - Dilithium Level 2 (128-bit security)
- `dilithium3` - Dilithium Level 3 (192-bit security) - **Recommended**
- `dilithium5` - Dilithium Level 5 (256-bit security)

## Output Formats

Key files are stored in raw binary format:
- `.pub` files contain the public key
- `.key` files contain the private key (keep these secure!)
- `.sig` files contain the signature

## Security Notes

- **Private keys are sensitive!** Store `.key` files securely.
- Use appropriate file permissions: `chmod 600 *.key`
- Post-quantum signatures are larger than classical ones
- Hybrid mode provides defense in depth

## Help

For detailed help on any command:
```bash
cryptoshift help
cryptoshift help keygen
cryptoshift help sign
cryptoshift help verify
```

## Version

```bash
cryptoshift --version
```

