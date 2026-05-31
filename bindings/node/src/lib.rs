//! Node.js bindings for CryptoShift via napi-rs.

use cryptoshift::{
    AlgorithmType, ClassicalAlgorithm, CryptoInventory, CryptoMode, CryptoPolicy,
    Decryptor, Encryptor, KeyPair, KeyPairGenerator, PostQuantumAlgorithm, Signer, Signature,
    Verifier, VERSION,
};
use napi::bindgen_prelude::*;
use napi_derive::napi;

fn parse_algorithm(name: &str) -> Result<AlgorithmType> {
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
        other => Err(Error::from_reason(format!("unknown algorithm: {}", other))),
    }
}

fn op_policy() -> CryptoPolicy {
    CryptoPolicy::new("node")
        .set_mode(CryptoMode::Hybrid)
        .set_min_security_level(0)
}

#[napi]
pub struct KeyPairResult {
    pub public_key: Buffer,
    pub private_key: Buffer,
}

#[napi]
pub fn version() -> String {
    VERSION.to_string()
}

#[napi]
pub fn keygen(algorithm: String) -> Result<KeyPairResult> {
    let algo = parse_algorithm(&algorithm)?;
    let generator = KeyPairGenerator::new(op_policy());
    let keypair = generator
        .generate(algo)
        .map_err(|e| Error::from_reason(e.to_string()))?;
    Ok(KeyPairResult {
        public_key: keypair.public_key().to_vec().into(),
        private_key: keypair.private_key().as_bytes().to_vec().into(),
    })
}

#[napi]
pub fn sign(algorithm: String, private_key: Buffer, message: Buffer) -> Result<Buffer> {
    let algo = parse_algorithm(&algorithm)?;
    let keypair = KeyPair::new(algo, Vec::new(), private_key.to_vec());
    let signer = Signer::new(op_policy());
    let signature = signer
        .sign(&keypair, &message)
        .map_err(|e| Error::from_reason(e.to_string()))?;
    let bytes = bincode::serialize(&signature).map_err(|e| Error::from_reason(e.to_string()))?;
    Ok(bytes.into())
}

#[napi]
pub fn verify(
    algorithm: String,
    public_key: Buffer,
    message: Buffer,
    signature: Buffer,
) -> Result<bool> {
    let _algo = parse_algorithm(&algorithm)?;
    let sig: Signature =
        bincode::deserialize(&signature).map_err(|e| Error::from_reason(e.to_string()))?;
    let verifier = Verifier::new(op_policy());
    Ok(verifier
        .verify(&public_key, &message, &sig)
        .is_ok())
}

#[napi]
pub fn encrypt(algorithm: String, public_key: Buffer, plaintext: Buffer) -> Result<Buffer> {
    let algo = parse_algorithm(&algorithm)?;
    let encryptor = Encryptor::new(op_policy());
    let message = encryptor
        .encrypt(algo, &public_key, &plaintext)
        .map_err(|e| Error::from_reason(e.to_string()))?;
    let bytes = message
        .to_bytes()
        .map_err(|e| Error::from_reason(e.to_string()))?;
    Ok(bytes.into())
}

#[napi]
pub fn decrypt(algorithm: String, private_key: Buffer, ciphertext: Buffer) -> Result<Buffer> {
    let algo = parse_algorithm(&algorithm)?;
    let message = cryptoshift::EncryptedMessage::from_bytes(&ciphertext)
        .map_err(|e| Error::from_reason(e.to_string()))?;
    let keypair = KeyPair::new(algo, Vec::new(), private_key.to_vec());
    let decryptor = Decryptor::new(op_policy());
    let plain = decryptor
        .decrypt(&keypair, &message)
        .map_err(|e| Error::from_reason(e.to_string()))?;
    Ok(plain.into())
}

#[napi(object)]
pub struct ScanSource {
    pub name: String,
    pub content: String,
}

#[napi]
pub fn scan(sources: Vec<ScanSource>) -> Result<String> {
    let inventory = CryptoInventory::new();
    let pairs: Vec<(&str, &str)> = sources
        .iter()
        .map(|s| (s.name.as_str(), s.content.as_str()))
        .collect();
    let report = inventory.scan_all(pairs);

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

    serde_json::to_string_pretty(&output).map_err(|e| Error::from_reason(e.to_string()))
}

#[napi]
pub fn algorithms() -> Vec<String> {
    vec![
        "ed25519".into(),
        "x25519".into(),
        "rsa2048".into(),
        "rsa3072".into(),
        "rsa4096".into(),
        "ecdsa-p256".into(),
        "ecdsa-p384".into(),
        "dilithium2".into(),
        "dilithium3".into(),
        "dilithium5".into(),
        "kyber512".into(),
        "kyber768".into(),
        "kyber1024".into(),
    ]
}
