//! Cryptographic inventory and discovery.
//!
//! Before an organization can migrate to post-quantum cryptography it must first
//! answer a deceptively hard question: *where is cryptography even being used?*
//!
//! This module provides a lightweight scanner that inspects source code (or any
//! text) for tell-tale references to cryptographic primitives, classifies each
//! finding by quantum risk, and produces an actionable report. It is heuristic
//! by design — it points humans at the right files rather than proving anything.

use crate::error::Result;
use std::path::Path;

/// Quantum-risk classification for a discovered cryptographic usage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RiskLevel {
    /// Broken by a large-scale quantum computer (Shor's algorithm).
    QuantumVulnerable,
    /// Already broken or badly weakened by classical attacks.
    ClassicallyBroken,
    /// Believed to remain secure against quantum attacks.
    QuantumSafe,
}

impl RiskLevel {
    /// A short label suitable for reports.
    pub fn label(&self) -> &'static str {
        match self {
            RiskLevel::QuantumVulnerable => "QUANTUM-VULNERABLE",
            RiskLevel::ClassicallyBroken => "BROKEN",
            RiskLevel::QuantumSafe => "QUANTUM-SAFE",
        }
    }
}

/// A single cryptographic usage discovered during a scan.
#[derive(Debug, Clone)]
pub struct Finding {
    /// Logical source name (file path, module, etc.).
    pub source: String,
    /// 1-based line number where the match was found.
    pub line: usize,
    /// The primitive that was matched (e.g. "RSA", "Dilithium").
    pub primitive: String,
    /// Quantum-risk classification.
    pub risk: RiskLevel,
    /// Suggested remediation.
    pub recommendation: String,
}

/// A pattern the scanner looks for.
struct Signature {
    needle: &'static str,
    primitive: &'static str,
    risk: RiskLevel,
    recommendation: &'static str,
}

/// The built-in detection rules. Needles are matched case-insensitively.
const SIGNATURES: &[Signature] = &[
    // Quantum-vulnerable public-key cryptography.
    Signature { needle: "rsa", primitive: "RSA", risk: RiskLevel::QuantumVulnerable, recommendation: "Migrate to Dilithium (signatures) or Kyber (key exchange)." },
    Signature { needle: "ecdsa", primitive: "ECDSA", risk: RiskLevel::QuantumVulnerable, recommendation: "Migrate signatures to Dilithium or FALCON." },
    Signature { needle: "ed25519", primitive: "Ed25519", risk: RiskLevel::QuantumVulnerable, recommendation: "Pair with or migrate to Dilithium in hybrid mode." },
    Signature { needle: "x25519", primitive: "X25519", risk: RiskLevel::QuantumVulnerable, recommendation: "Pair with or migrate to Kyber KEM in hybrid mode." },
    Signature { needle: "ecdh", primitive: "ECDH", risk: RiskLevel::QuantumVulnerable, recommendation: "Migrate key exchange to Kyber KEM." },
    Signature { needle: "diffie-hellman", primitive: "Diffie-Hellman", risk: RiskLevel::QuantumVulnerable, recommendation: "Migrate key exchange to Kyber KEM." },
    Signature { needle: "secp256", primitive: "secp256 curve", risk: RiskLevel::QuantumVulnerable, recommendation: "Migrate to a post-quantum scheme." },
    Signature { needle: "dsa", primitive: "DSA", risk: RiskLevel::QuantumVulnerable, recommendation: "Migrate signatures to Dilithium." },
    // Classically broken / deprecated primitives.
    Signature { needle: "md5", primitive: "MD5", risk: RiskLevel::ClassicallyBroken, recommendation: "Replace with SHA-256 or SHA-3 immediately." },
    Signature { needle: "sha1", primitive: "SHA-1", risk: RiskLevel::ClassicallyBroken, recommendation: "Replace with SHA-256 or SHA-3." },
    Signature { needle: "sha-1", primitive: "SHA-1", risk: RiskLevel::ClassicallyBroken, recommendation: "Replace with SHA-256 or SHA-3." },
    Signature { needle: "des", primitive: "DES/3DES", risk: RiskLevel::ClassicallyBroken, recommendation: "Replace with AES-256-GCM." },
    Signature { needle: "rc4", primitive: "RC4", risk: RiskLevel::ClassicallyBroken, recommendation: "Replace with AES-256-GCM or ChaCha20-Poly1305." },
    // Post-quantum and quantum-safe primitives.
    Signature { needle: "dilithium", primitive: "Dilithium", risk: RiskLevel::QuantumSafe, recommendation: "Post-quantum signature — no action needed." },
    Signature { needle: "ml-dsa", primitive: "ML-DSA", risk: RiskLevel::QuantumSafe, recommendation: "Post-quantum signature — no action needed." },
    Signature { needle: "kyber", primitive: "Kyber", risk: RiskLevel::QuantumSafe, recommendation: "Post-quantum KEM — no action needed." },
    Signature { needle: "ml-kem", primitive: "ML-KEM", risk: RiskLevel::QuantumSafe, recommendation: "Post-quantum KEM — no action needed." },
    Signature { needle: "falcon", primitive: "FALCON", risk: RiskLevel::QuantumSafe, recommendation: "Post-quantum signature — no action needed." },
    Signature { needle: "sphincs", primitive: "SPHINCS+", risk: RiskLevel::QuantumSafe, recommendation: "Post-quantum signature — no action needed." },
    Signature { needle: "aes-256", primitive: "AES-256", risk: RiskLevel::QuantumSafe, recommendation: "Symmetric cipher with adequate quantum margin." },
    Signature { needle: "sha-256", primitive: "SHA-256", risk: RiskLevel::QuantumSafe, recommendation: "Hash with adequate quantum margin." },
    Signature { needle: "sha256", primitive: "SHA-256", risk: RiskLevel::QuantumSafe, recommendation: "Hash with adequate quantum margin." },
    Signature { needle: "sha3", primitive: "SHA-3", risk: RiskLevel::QuantumSafe, recommendation: "Hash with adequate quantum margin." },
];

/// Returns `true` if `needle` appears in `haystack` at the start of a token.
///
/// We require the character immediately before the match to not be an ASCII
/// alphanumeric. This stops short needles from matching inside larger crypto
/// tokens (for example, `dsa` inside `ecdsa`) while still allowing matches that
/// begin after separators such as spaces, `_`, `:` or `.`.
fn needle_present(haystack: &str, needle: &str) -> bool {
    let bytes = haystack.as_bytes();
    let mut start = 0;
    while let Some(pos) = haystack[start..].find(needle) {
        let abs = start + pos;
        let leading_boundary = abs == 0 || !bytes[abs - 1].is_ascii_alphanumeric();
        if leading_boundary {
            return true;
        }
        start = abs + needle.len();
        if start > haystack.len() {
            break;
        }
    }
    false
}

/// Aggregated results of a scan.
#[derive(Debug, Clone, Default)]
pub struct InventoryReport {
    /// All findings, in discovery order.
    pub findings: Vec<Finding>,
}

impl InventoryReport {
    /// Number of findings at a given risk level.
    pub fn count(&self, risk: RiskLevel) -> usize {
        self.findings.iter().filter(|f| f.risk == risk).count()
    }

    /// Total number of findings.
    pub fn total(&self) -> usize {
        self.findings.len()
    }

    /// A migration-urgency score from 0 (nothing to do) to 100 (act now).
    ///
    /// Broken primitives weigh most heavily, followed by quantum-vulnerable
    /// public-key crypto; quantum-safe usage does not add urgency.
    pub fn risk_score(&self) -> u8 {
        let broken = self.count(RiskLevel::ClassicallyBroken);
        let vulnerable = self.count(RiskLevel::QuantumVulnerable);
        if broken == 0 && vulnerable == 0 {
            return 0;
        }
        let raw = broken * 25 + vulnerable * 10;
        raw.min(100) as u8
    }

    /// Render a human-readable summary.
    pub fn summary(&self) -> String {
        format!(
            "Crypto inventory: {} finding(s) | {} broken, {} quantum-vulnerable, {} quantum-safe | risk score {}/100",
            self.total(),
            self.count(RiskLevel::ClassicallyBroken),
            self.count(RiskLevel::QuantumVulnerable),
            self.count(RiskLevel::QuantumSafe),
            self.risk_score(),
        )
    }
}

/// The cryptographic discovery scanner.
#[derive(Default)]
pub struct CryptoInventory;

impl CryptoInventory {
    /// Create a new scanner.
    pub fn new() -> Self {
        Self
    }

    /// Scan a block of text, attributing findings to `source`.
    pub fn scan_text(&self, source: &str, content: &str) -> Vec<Finding> {
        let mut findings = Vec::new();
        for (idx, line) in content.lines().enumerate() {
            let lower = line.to_lowercase();
            for sig in SIGNATURES {
                if needle_present(&lower, sig.needle) {
                    findings.push(Finding {
                        source: source.to_string(),
                        line: idx + 1,
                        primitive: sig.primitive.to_string(),
                        risk: sig.risk,
                        recommendation: sig.recommendation.to_string(),
                    });
                }
            }
        }
        findings
    }

    /// Scan a file on disk.
    pub fn scan_file<P: AsRef<Path>>(&self, path: P) -> Result<Vec<Finding>> {
        let path = path.as_ref();
        let content = std::fs::read_to_string(path)?;
        Ok(self.scan_text(&path.display().to_string(), &content))
    }

    /// Scan many named text blocks and aggregate into a report.
    pub fn scan_all<'a, I>(&self, sources: I) -> InventoryReport
    where
        I: IntoIterator<Item = (&'a str, &'a str)>,
    {
        let mut report = InventoryReport::default();
        for (name, content) in sources {
            report.findings.extend(self.scan_text(name, content));
        }
        report
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detects_rsa_as_vulnerable() {
        let inv = CryptoInventory::new();
        let findings = inv.scan_text("auth.rs", "let key = RsaPrivateKey::new(rng, 2048);");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].primitive, "RSA");
        assert_eq!(findings[0].risk, RiskLevel::QuantumVulnerable);
        assert_eq!(findings[0].line, 1);
    }

    #[test]
    fn test_detects_broken_md5() {
        let inv = CryptoInventory::new();
        let findings = inv.scan_text("hash.go", "h := md5.New()");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].risk, RiskLevel::ClassicallyBroken);
    }

    #[test]
    fn test_detects_quantum_safe() {
        let inv = CryptoInventory::new();
        let findings = inv.scan_text("pqc.rs", "use pqcrypto_kyber::kyber768;");
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].primitive, "Kyber");
        assert_eq!(findings[0].risk, RiskLevel::QuantumSafe);
    }

    #[test]
    fn test_no_crypto_no_findings() {
        let inv = CryptoInventory::new();
        let findings = inv.scan_text("main.rs", "fn main() { println!(\"hello\"); }");
        assert!(findings.is_empty());
    }

    #[test]
    fn test_report_aggregation_and_score() {
        let inv = CryptoInventory::new();
        let report = inv.scan_all([
            ("a.rs", "RsaPrivateKey and ecdsa::SigningKey"),
            ("b.rs", "md5 digest"),
            ("c.rs", "dilithium3 signature"),
        ]);

        assert_eq!(report.count(RiskLevel::QuantumVulnerable), 2);
        assert_eq!(report.count(RiskLevel::ClassicallyBroken), 1);
        assert_eq!(report.count(RiskLevel::QuantumSafe), 1);
        assert_eq!(report.total(), 4);

        // 1 broken (25) + 2 vulnerable (20) = 45.
        assert_eq!(report.risk_score(), 45);
    }

    #[test]
    fn test_clean_report_has_zero_score() {
        let inv = CryptoInventory::new();
        let report = inv.scan_all([("safe.rs", "dilithium and kyber and aes-256")]);
        assert_eq!(report.risk_score(), 0);
        assert_eq!(report.count(RiskLevel::QuantumSafe), 3);
    }

    #[test]
    fn test_line_numbers() {
        let inv = CryptoInventory::new();
        let content = "clean line\nanother clean line\nuses RSA here";
        let findings = inv.scan_text("multi.rs", content);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].line, 3);
    }
}
