//! CryptoShift CLI - Command-line interface for crypto operations.
//!
//! A comprehensive CLI tool for cryptographic operations using the CryptoShift
//! SDK: key generation, signing, verification, hybrid (KEM-DEM) encryption,
//! migration planning, and cryptographic inventory scanning.
//!
//! Keys are stored in a small self-describing format that records which
//! algorithm produced them, so `sign`/`verify`/`encrypt`/`decrypt` no longer
//! have to guess.

use clap::{Parser, Subcommand};
use cryptoshift::*;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs;
use std::path::{Path, PathBuf};

#[derive(Parser)]
#[command(name = "cryptoshift")]
#[command(about = "Crypto-agility CLI for classical and post-quantum cryptography", long_about = None)]
#[command(version)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a new key pair
    Keygen {
        /// Algorithm (ed25519, x25519, rsa2048, rsa3072, rsa4096, ecdsa-p256,
        /// ecdsa-p384, dilithium2/3/5, kyber512/768/1024)
        #[arg(short, long)]
        algorithm: String,

        /// Output file for the key pair (without extension)
        #[arg(short, long)]
        output: PathBuf,
    },

    /// Sign a message or file
    Sign {
        /// Private key file (.key)
        #[arg(short, long)]
        key: PathBuf,

        /// Input message (string, or file path with --file)
        #[arg(short, long)]
        input: String,

        /// Output signature file
        #[arg(short, long)]
        output: PathBuf,

        /// Treat input as a file path
        #[arg(short, long)]
        file: bool,
    },

    /// Verify a signature
    Verify {
        /// Public key file (.pub)
        #[arg(short, long)]
        key: PathBuf,

        /// Input message (string, or file path with --file)
        #[arg(short, long)]
        input: String,

        /// Signature file
        #[arg(short, long)]
        signature: PathBuf,

        /// Treat input as a file path
        #[arg(short = 'f', long)]
        file: bool,
    },

    /// Encrypt a message or file to a recipient's public key (Kyber or X25519)
    Encrypt {
        /// Recipient public key file (.pub)
        #[arg(short, long)]
        key: PathBuf,

        /// Input message (string, or file path with --file)
        #[arg(short, long)]
        input: String,

        /// Output encrypted message file
        #[arg(short, long)]
        output: PathBuf,

        /// Treat input as a file path
        #[arg(short, long)]
        file: bool,
    },

    /// Decrypt a message produced by `encrypt`
    Decrypt {
        /// Recipient private key file (.key)
        #[arg(short, long)]
        key: PathBuf,

        /// Encrypted message file
        #[arg(short, long)]
        input: PathBuf,

        /// Output plaintext file (omit to print to stdout)
        #[arg(short, long)]
        output: Option<PathBuf>,
    },

    /// Plan and simulate a classical-to-post-quantum migration
    Migrate {
        /// Service or system name for the plan
        #[arg(short, long, default_value = "service")]
        name: String,

        /// Operations to simulate per stage
        #[arg(short, long, default_value = "1000")]
        samples: u64,
    },

    /// Scan source files for cryptographic usage and quantum risk
    Scan {
        /// File or directory to scan
        path: PathBuf,
    },

    /// Show information about an algorithm
    Info {
        /// Algorithm name
        algorithm: String,
    },

    /// List all supported algorithms
    List {
        /// Filter by type (classical, post-quantum, all)
        #[arg(short, long, default_value = "all")]
        filter: String,
    },
}

/// Self-describing on-disk key format.
#[derive(Serialize, Deserialize)]
struct StoredKey {
    algorithm: AlgorithmType,
    is_private: bool,
    key: Vec<u8>,
}

impl StoredKey {
    fn write(path: &Path, algorithm: AlgorithmType, is_private: bool, key: &[u8]) -> Result<()> {
        let stored = StoredKey {
            algorithm,
            is_private,
            key: key.to_vec(),
        };
        let bytes = bincode::serialize(&stored)
            .map_err(|e| Error::SerializationError(format!("Failed to encode key: {}", e)))?;
        fs::write(path, bytes)?;
        Ok(())
    }

    fn read(path: &Path) -> Result<Self> {
        let bytes = fs::read(path)?;
        bincode::deserialize(&bytes)
            .map_err(|e| Error::SerializationError(format!("Failed to decode key {:?}: {}", path, e)))
    }
}

/// A permissive policy for CLI operations: hybrid mode accepts both classical
/// and post-quantum algorithms, and the minimum security level is relaxed so
/// the user's explicit algorithm choice is honored.
fn op_policy() -> CryptoPolicy {
    CryptoPolicy::new("cli")
        .set_mode(CryptoMode::Hybrid)
        .set_min_security_level(0)
}

fn fingerprint(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    hex::encode(&digest[..8])
}

fn main() -> Result<()> {
    env_logger::init();
    let cli = Cli::parse();

    match cli.command {
        Commands::Keygen { algorithm, output } => handle_keygen(algorithm, output),
        Commands::Sign {
            key,
            input,
            output,
            file,
        } => handle_sign(key, input, output, file),
        Commands::Verify {
            key,
            input,
            signature,
            file,
        } => handle_verify(key, input, signature, file),
        Commands::Encrypt {
            key,
            input,
            output,
            file,
        } => handle_encrypt(key, input, output, file),
        Commands::Decrypt { key, input, output } => handle_decrypt(key, input, output),
        Commands::Migrate { name, samples } => handle_migrate(name, samples),
        Commands::Scan { path } => handle_scan(path),
        Commands::Info { algorithm } => handle_info(algorithm),
        Commands::List { filter } => handle_list(filter),
    }
}

fn read_message(input: &str, is_file: bool) -> Result<Vec<u8>> {
    if is_file {
        println!("   Reading file: {}", input);
        Ok(fs::read(input)?)
    } else {
        Ok(input.as_bytes().to_vec())
    }
}

fn handle_keygen(algorithm: String, output: PathBuf) -> Result<()> {
    let algo = parse_algorithm(&algorithm)?;
    println!("Generating key pair...");
    println!("   Algorithm: {}", algo);

    let generator = KeyPairGenerator::new(op_policy());
    let keypair = generator.generate(algo)?;

    let pub_file = output.with_extension("pub");
    let priv_file = output.with_extension("key");

    StoredKey::write(&pub_file, algo, false, keypair.public_key())?;
    StoredKey::write(&priv_file, algo, true, keypair.private_key().as_bytes())?;

    println!("Key pair generated:");
    println!("   Public key:  {:?}", pub_file);
    println!("   Private key: {:?}", priv_file);
    println!("   Public size:  {} bytes", keypair.public_key_size());
    println!("   Private size: {} bytes", keypair.private_key_size());
    println!("   Fingerprint:  {}", fingerprint(keypair.public_key()));
    Ok(())
}

fn handle_sign(key: PathBuf, input: String, output: PathBuf, is_file: bool) -> Result<()> {
    println!("Signing message...");
    let message = read_message(&input, is_file)?;

    let stored = StoredKey::read(&key)?;
    if !stored.is_private {
        return Err(Error::invalid_key("Signing requires a private key (.key)"));
    }

    // Signing only needs the private key bytes and the algorithm tag.
    let keypair = KeyPair::new(stored.algorithm, Vec::new(), stored.key);
    let signer = Signer::new(op_policy());
    let signature = signer.sign(&keypair, &message)?;

    let bytes = bincode::serialize(&signature)
        .map_err(|e| Error::SerializationError(format!("Failed to encode signature: {}", e)))?;
    fs::write(&output, bytes)?;

    println!("Message signed:");
    println!("   Algorithm: {}", signature.algorithm());
    println!("   Signature: {:?}", output);
    println!("   Size:      {} bytes", signature.len());
    Ok(())
}

fn handle_verify(key: PathBuf, input: String, signature: PathBuf, is_file: bool) -> Result<()> {
    println!("Verifying signature...");
    let message = read_message(&input, is_file)?;

    let stored = StoredKey::read(&key)?;
    let sig_bytes = fs::read(&signature)?;
    let sig: Signature = bincode::deserialize(&sig_bytes)
        .map_err(|e| Error::SerializationError(format!("Failed to decode signature: {}", e)))?;

    if stored.algorithm != sig.algorithm() {
        return Err(Error::InvalidSignature(format!(
            "Key algorithm {} does not match signature algorithm {}",
            stored.algorithm,
            sig.algorithm()
        )));
    }

    let verifier = Verifier::new(op_policy());
    match verifier.verify(&stored.key, &message, &sig) {
        Ok(_) => {
            println!("Signature is VALID ({})", sig.algorithm());
            Ok(())
        }
        Err(e) => {
            println!("Signature is INVALID: {}", e);
            Err(e)
        }
    }
}

fn handle_encrypt(key: PathBuf, input: String, output: PathBuf, is_file: bool) -> Result<()> {
    println!("Encrypting message...");
    let plaintext = read_message(&input, is_file)?;

    let stored = StoredKey::read(&key)?;
    let encryptor = Encryptor::new(op_policy());
    let message = encryptor.encrypt(stored.algorithm, &stored.key, &plaintext)?;

    fs::write(&output, message.to_bytes()?)?;

    println!("Message encrypted:");
    println!("   KEM algorithm:  {}", message.algorithm());
    println!("   Output:         {:?}", output);
    println!("   Plaintext size: {} bytes", plaintext.len());
    println!("   Ciphertext size:{} bytes", message.total_size());
    Ok(())
}

fn handle_decrypt(key: PathBuf, input: PathBuf, output: Option<PathBuf>) -> Result<()> {
    println!("Decrypting message...");

    let stored = StoredKey::read(&key)?;
    if !stored.is_private {
        return Err(Error::invalid_key("Decryption requires a private key (.key)"));
    }

    let msg_bytes = fs::read(&input)?;
    let message = EncryptedMessage::from_bytes(&msg_bytes)?;

    let keypair = KeyPair::new(stored.algorithm, Vec::new(), stored.key);
    let decryptor = Decryptor::new(op_policy());
    let plaintext = decryptor.decrypt(&keypair, &message)?;

    match output {
        Some(path) => {
            fs::write(&path, &plaintext)?;
            println!("Decrypted {} bytes -> {:?}", plaintext.len(), path);
        }
        None => {
            println!("Decrypted plaintext:");
            println!("{}", String::from_utf8_lossy(&plaintext));
        }
    }
    Ok(())
}

fn handle_migrate(name: String, samples: u64) -> Result<()> {
    let mut orchestrator = MigrationOrchestrator::with_default_plan(&name);
    let plan = orchestrator.plan().clone();

    println!("Migration plan for '{}'", name);
    println!(
        "   {} -> {}",
        AlgorithmType::Classical(plan.classical_algorithm()),
        AlgorithmType::PostQuantum(plan.pqc_algorithm())
    );
    println!("   {} stages\n", plan.len());

    loop {
        orchestrator.reset_stats();
        for _ in 0..samples {
            orchestrator.select_algorithm();
        }
        println!("{}", orchestrator.report());

        if orchestrator.advance().is_err() {
            break;
        }
    }

    println!("\nMigration simulation complete.");
    Ok(())
}

fn handle_scan(path: PathBuf) -> Result<()> {
    println!("Scanning {:?} for cryptographic usage...\n", path);

    let inventory = CryptoInventory::new();
    let mut report = InventoryReport::default();

    if path.is_dir() {
        let mut files = Vec::new();
        collect_files(&path, &mut files)?;
        for file in files {
            if let Ok(findings) = inventory.scan_file(&file) {
                report.findings.extend(findings);
            }
        }
    } else {
        report.findings.extend(inventory.scan_file(&path)?);
    }

    if report.findings.is_empty() {
        println!("No cryptographic usage detected.");
    } else {
        for finding in &report.findings {
            println!(
                "  [{}] {}:{}  {}  -> {}",
                finding.risk.label(),
                finding.source,
                finding.line,
                finding.primitive,
                finding.recommendation
            );
        }
        println!();
    }

    println!("{}", report.summary());
    Ok(())
}

/// Recursively collect text-like files, skipping common noise directories.
fn collect_files(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for entry in fs::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if path.is_dir() {
            if matches!(name.as_ref(), ".git" | "target" | "node_modules") {
                continue;
            }
            collect_files(&path, out)?;
        } else {
            out.push(path);
        }
    }
    Ok(())
}

fn handle_info(algorithm: String) -> Result<()> {
    let algo = parse_algorithm(&algorithm)?;

    println!("Algorithm Information");
    println!("   Name: {}", algo.name());
    println!(
        "   Type: {}",
        if algo.is_classical() {
            "Classical"
        } else {
            "Post-Quantum"
        }
    );
    println!("   Security Level: {} bits", algo.security_level());
    println!("   Category: {:?}", algo.category());

    match algo {
        AlgorithmType::Classical(ClassicalAlgorithm::Ed25519) => {
            println!("\n   Details:");
            println!("   - Fast elliptic curve signatures");
            println!("   - Public key: 32 bytes, Signature: 64 bytes");
            println!("   - Quantum status: VULNERABLE (use hybrid with Dilithium)");
        }
        AlgorithmType::PostQuantum(PostQuantumAlgorithm::Dilithium3) => {
            println!("\n   Details:");
            println!("   - NIST-selected post-quantum signature (ML-DSA)");
            println!("   - Public key: ~1,952 bytes, Signature: ~3,300 bytes");
            println!("   - Quantum status: SAFE");
        }
        AlgorithmType::PostQuantum(PostQuantumAlgorithm::Kyber768) => {
            println!("\n   Details:");
            println!("   - NIST-selected post-quantum KEM (ML-KEM)");
            println!("   - Used for key establishment, paired with AES-256-GCM");
            println!("   - Quantum status: SAFE");
        }
        _ => {}
    }
    Ok(())
}

fn handle_list(filter: String) -> Result<()> {
    println!("Supported Algorithms\n");

    let show_classical = filter == "all" || filter == "classical";
    let show_pqc = filter == "all" || filter == "post-quantum" || filter == "pqc";

    if show_classical {
        println!("Classical Algorithms:");
        println!("  ed25519       - EdDSA signature (128-bit)");
        println!("  x25519        - ECDH key exchange (128-bit)");
        println!("  rsa2048       - RSA signature (112-bit)");
        println!("  rsa3072       - RSA signature (128-bit)");
        println!("  rsa4096       - RSA signature (152-bit)");
        println!("  ecdsa-p256    - ECDSA signature (128-bit)");
        println!("  ecdsa-p384    - ECDSA signature (192-bit)");
        println!();
    }

    if show_pqc {
        println!("Post-Quantum Algorithms (NIST-selected):");
        println!("  dilithium2    - ML-DSA signature (128-bit)");
        println!("  dilithium3    - ML-DSA signature (192-bit)");
        println!("  dilithium5    - ML-DSA signature (256-bit)");
        println!("  kyber512      - ML-KEM key exchange (128-bit)");
        println!("  kyber768      - ML-KEM key exchange (192-bit)");
        println!("  kyber1024     - ML-KEM key exchange (256-bit)");
        println!();
    }

    println!("Use 'cryptoshift info <algorithm>' for details");
    Ok(())
}

fn parse_algorithm(name: &str) -> Result<AlgorithmType> {
    match name.to_lowercase().as_str() {
        "ed25519" => Ok(AlgorithmType::Classical(ClassicalAlgorithm::Ed25519)),
        "x25519" => Ok(AlgorithmType::Classical(ClassicalAlgorithm::X25519)),
        "rsa2048" => Ok(AlgorithmType::Classical(ClassicalAlgorithm::RSA2048)),
        "rsa3072" => Ok(AlgorithmType::Classical(ClassicalAlgorithm::RSA3072)),
        "rsa4096" => Ok(AlgorithmType::Classical(ClassicalAlgorithm::RSA4096)),
        "ecdsa-p256" | "ecdsa-256" | "p256" => {
            Ok(AlgorithmType::Classical(ClassicalAlgorithm::EcdsaP256))
        }
        "ecdsa-p384" | "ecdsa-384" | "p384" => {
            Ok(AlgorithmType::Classical(ClassicalAlgorithm::EcdsaP384))
        }
        "dilithium2" | "dil2" => Ok(AlgorithmType::PostQuantum(PostQuantumAlgorithm::Dilithium2)),
        "dilithium3" | "dil3" => Ok(AlgorithmType::PostQuantum(PostQuantumAlgorithm::Dilithium3)),
        "dilithium5" | "dil5" => Ok(AlgorithmType::PostQuantum(PostQuantumAlgorithm::Dilithium5)),
        "kyber512" => Ok(AlgorithmType::PostQuantum(PostQuantumAlgorithm::Kyber512)),
        "kyber768" => Ok(AlgorithmType::PostQuantum(PostQuantumAlgorithm::Kyber768)),
        "kyber1024" => Ok(AlgorithmType::PostQuantum(PostQuantumAlgorithm::Kyber1024)),
        _ => Err(Error::UnsupportedAlgorithm(format!(
            "Unknown algorithm: {}",
            name
        ))),
    }
}
