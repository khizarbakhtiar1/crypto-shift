//! Criterion benchmarks comparing classical and post-quantum operations.
//!
//! Run with: `cargo bench`

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use cryptoshift::{
    AlgorithmType, ClassicalAlgorithm, CryptoMode, CryptoPolicy, Decryptor, Encryptor,
    KeyPairGenerator, PostQuantumAlgorithm, Signer, Verifier,
};

fn hybrid_policy() -> CryptoPolicy {
    CryptoPolicy::new("bench")
        .set_mode(CryptoMode::Hybrid)
        .set_min_security_level(0)
}

fn bench_keygen(c: &mut Criterion) {
    let policy = hybrid_policy();
    let mut group = c.benchmark_group("keygen");

    let cases = [
        ("ed25519", AlgorithmType::Classical(ClassicalAlgorithm::Ed25519)),
        ("ecdsa_p256", AlgorithmType::Classical(ClassicalAlgorithm::EcdsaP256)),
        ("dilithium2", AlgorithmType::PostQuantum(PostQuantumAlgorithm::Dilithium2)),
        ("dilithium3", AlgorithmType::PostQuantum(PostQuantumAlgorithm::Dilithium3)),
        ("kyber768", AlgorithmType::PostQuantum(PostQuantumAlgorithm::Kyber768)),
    ];

    for (name, algo) in cases {
        let generator = KeyPairGenerator::new(policy.clone());
        group.bench_function(name, |b| {
            b.iter(|| generator.generate(black_box(algo)).unwrap())
        });
    }
    group.finish();
}

fn bench_sign(c: &mut Criterion) {
    let policy = hybrid_policy();
    let message = b"benchmark message for signing throughput comparison";
    let mut group = c.benchmark_group("sign");

    let cases = [
        ("ed25519", AlgorithmType::Classical(ClassicalAlgorithm::Ed25519)),
        ("ecdsa_p256", AlgorithmType::Classical(ClassicalAlgorithm::EcdsaP256)),
        ("dilithium2", AlgorithmType::PostQuantum(PostQuantumAlgorithm::Dilithium2)),
        ("dilithium3", AlgorithmType::PostQuantum(PostQuantumAlgorithm::Dilithium3)),
    ];

    for (name, algo) in cases {
        let generator = KeyPairGenerator::new(policy.clone());
        let keypair = generator.generate(algo).unwrap();
        let signer = Signer::new(policy.clone());
        group.bench_function(name, |b| {
            b.iter(|| signer.sign(black_box(&keypair), black_box(message)).unwrap())
        });
    }
    group.finish();
}

fn bench_verify(c: &mut Criterion) {
    let policy = hybrid_policy();
    let message = b"benchmark message for verification throughput comparison";
    let mut group = c.benchmark_group("verify");

    let cases = [
        ("ed25519", AlgorithmType::Classical(ClassicalAlgorithm::Ed25519)),
        ("dilithium3", AlgorithmType::PostQuantum(PostQuantumAlgorithm::Dilithium3)),
    ];

    for (name, algo) in cases {
        let generator = KeyPairGenerator::new(policy.clone());
        let keypair = generator.generate(algo).unwrap();
        let signer = Signer::new(policy.clone());
        let signature = signer.sign(&keypair, message).unwrap();
        let verifier = Verifier::new(policy.clone());
        group.bench_function(name, |b| {
            b.iter(|| {
                verifier
                    .verify(black_box(keypair.public_key()), black_box(message), black_box(&signature))
                    .unwrap()
            })
        });
    }
    group.finish();
}

fn bench_encryption(c: &mut Criterion) {
    let policy = hybrid_policy();
    let plaintext = vec![0x42u8; 1024];
    let mut group = c.benchmark_group("encrypt_roundtrip");

    let cases = [
        ("x25519", AlgorithmType::Classical(ClassicalAlgorithm::X25519)),
        ("kyber768", AlgorithmType::PostQuantum(PostQuantumAlgorithm::Kyber768)),
    ];

    for (name, algo) in cases {
        let generator = KeyPairGenerator::new(policy.clone());
        let keypair = generator.generate(algo).unwrap();
        let encryptor = Encryptor::new(policy.clone());
        let decryptor = Decryptor::new(policy.clone());
        group.bench_function(name, |b| {
            b.iter(|| {
                let msg = encryptor
                    .encrypt(algo, keypair.public_key(), black_box(&plaintext))
                    .unwrap();
                decryptor.decrypt(&keypair, &msg).unwrap()
            })
        });
    }
    group.finish();
}

criterion_group!(benches, bench_keygen, bench_sign, bench_verify, bench_encryption);
criterion_main!(benches);
