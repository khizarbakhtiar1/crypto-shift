//! Python bindings for CryptoShift via PyO3.

use cryptoshift::{
    AlgorithmType, ClassicalAlgorithm, CryptoInventory, CryptoMode, CryptoPolicy,
    Decryptor, Encryptor, KeyPair, KeyPairGenerator, PostQuantumAlgorithm, Signer, Signature,
    Verifier, VERSION,
};
use pyo3::exceptions::{PyRuntimeError, PyValueError};
use pyo3::prelude::*;

fn parse_algorithm(name: &str) -> PyResult<AlgorithmType> {
    match name.to_lowercase().as_str() {
        "ed25519" => Ok(AlgorithmType::Classical(ClassicalAlgorithm::Ed25519)),
        "x25519" => Ok(AlgorithmType::Classical(ClassicalAlgorithm::X25519)),
        "rsa2048" => Ok(AlgorithmType::Classical(ClassicalAlgorithm::RSA2048)),
        "rsa3072" => Ok(AlgorithmType::Classical(ClassicalAlgorithm::RSA3072)),
        "rsa4096" => Ok(AlgorithmType::Classical(ClassicalAlgorithm::RSA4096)),
        "ecdsa-p256" | "p256" => Ok(AlgorithmType::Classical(ClassicalAlgorithm::EcdsaP256)),
        "ecdsa-p384" | "p384" => Ok(AlgorithmType::Classical(ClassicalAlgorithm::EcdsaP384)),
        "dilithium2" => Ok(AlgorithmType::PostQuantum(PostQuantumAlgorithm::Dilithium2)),
        "dilithium3" => Ok(AlgorithmType::PostQuantum(PostQuantumAlgorithm::Dilithium3)),
        "dilithium5" => Ok(AlgorithmType::PostQuantum(PostQuantumAlgorithm::Dilithium5)),
        "kyber512" => Ok(AlgorithmType::PostQuantum(PostQuantumAlgorithm::Kyber512)),
        "kyber768" => Ok(AlgorithmType::PostQuantum(PostQuantumAlgorithm::Kyber768)),
        "kyber1024" => Ok(AlgorithmType::PostQuantum(PostQuantumAlgorithm::Kyber1024)),
        other => Err(PyValueError::new_err(format!("unknown algorithm: {}", other))),
    }
}

fn op_policy() -> CryptoPolicy {
    CryptoPolicy::new("python")
        .set_mode(CryptoMode::Hybrid)
        .set_min_security_level(0)
}

/// Return the CryptoShift library version string.
#[pyfunction]
fn version() -> &'static str {
    VERSION
}

/// Generate a key pair for `algorithm`. Returns `(public_key, private_key)` bytes.
#[pyfunction]
fn keygen(algorithm: &str) -> PyResult<(Vec<u8>, Vec<u8>)> {
    let algo = parse_algorithm(algorithm)?;
    let generator = KeyPairGenerator::new(op_policy());
    let keypair = generator
        .generate(algo)
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    Ok((
        keypair.public_key().to_vec(),
        keypair.private_key().as_bytes().to_vec(),
    ))
}

/// Sign `message` with `private_key`. Returns serialized signature bytes.
#[pyfunction]
fn sign(algorithm: &str, private_key: &[u8], message: &[u8]) -> PyResult<Vec<u8>> {
    let algo = parse_algorithm(algorithm)?;
    let keypair = KeyPair::new(algo, Vec::new(), private_key.to_vec());
    let signer = Signer::new(op_policy());
    let signature = signer
        .sign(&keypair, message)
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    bincode::serialize(&signature).map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

/// Verify a signature. Returns `True` if valid.
#[pyfunction]
fn verify(algorithm: &str, public_key: &[u8], message: &[u8], signature: &[u8]) -> PyResult<bool> {
    let _algo = parse_algorithm(algorithm)?;
    let sig: Signature =
        bincode::deserialize(signature).map_err(|e| PyValueError::new_err(e.to_string()))?;
    let verifier = Verifier::new(op_policy());
    Ok(verifier
        .verify(public_key, message, &sig)
        .is_ok())
}

/// Encrypt `plaintext` for `public_key`. Returns serialized ciphertext bytes.
#[pyfunction]
fn encrypt(algorithm: &str, public_key: &[u8], plaintext: &[u8]) -> PyResult<Vec<u8>> {
    let algo = parse_algorithm(algorithm)?;
    let encryptor = Encryptor::new(op_policy());
    let message = encryptor
        .encrypt(algo, public_key, plaintext)
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    message.to_bytes()
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

/// Decrypt `ciphertext` with `private_key`. Returns plaintext bytes.
#[pyfunction]
fn decrypt(algorithm: &str, private_key: &[u8], ciphertext: &[u8]) -> PyResult<Vec<u8>> {
    let algo = parse_algorithm(algorithm)?;
    let message = cryptoshift::EncryptedMessage::from_bytes(ciphertext)
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))?;
    let keypair = KeyPair::new(algo, Vec::new(), private_key.to_vec());
    let decryptor = Decryptor::new(op_policy());
    decryptor
        .decrypt(&keypair, &message)
        .map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

/// Scan source text for cryptographic usage. Returns a dict with summary and findings.
#[pyfunction]
fn scan(sources: Vec<(String, String)>) -> PyResult<String> {
    let inventory = CryptoInventory::new();
    let report = inventory.scan_all(sources.iter().map(|(n, c)| (n.as_str(), c.as_str())));

    let findings: Vec<serde_json::Value> = report
        .findings
        .iter()
        .map(|f| {
            serde_json::json!({
                "source": f.source,
                "line": f.line,
                "primitive": f.primitive,
                "risk": f.risk.label(),
                "recommendation": f.recommendation,
            })
        })
        .collect();

    let output = serde_json::json!({
        "summary": report.summary(),
        "risk_score": report.risk_score(),
        "findings": findings,
    });

    serde_json::to_string_pretty(&output).map_err(|e| PyRuntimeError::new_err(e.to_string()))
}

/// CryptoShift Python module — post-quantum crypto-agility SDK.
#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(version, m)?)?;
    m.add_function(wrap_pyfunction!(keygen, m)?)?;
    m.add_function(wrap_pyfunction!(sign, m)?)?;
    m.add_function(wrap_pyfunction!(verify, m)?)?;
    m.add_function(wrap_pyfunction!(encrypt, m)?)?;
    m.add_function(wrap_pyfunction!(decrypt, m)?)?;
    m.add_function(wrap_pyfunction!(scan, m)?)?;

    let algorithms = vec![
        "ed25519", "x25519", "rsa2048", "rsa3072", "rsa4096",
        "ecdsa-p256", "ecdsa-p384", "dilithium2", "dilithium3", "dilithium5",
        "kyber512", "kyber768", "kyber1024",
    ];
    m.add("ALGORITHMS", algorithms)?;

    Ok(())
}
