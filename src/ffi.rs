//! C-compatible FFI for language bindings (Python, Node.js, etc.).
//!
//! All functions return `0` on success or a negative error code. When a call
//! fails, [`cryptoshift_last_error`] contains a human-readable message.
//!
//! Buffers returned by CryptoShift must be freed with [`cryptoshift_buffer_free`].

use crate::algorithms::{AlgorithmType, ClassicalAlgorithm, PostQuantumAlgorithm};
use crate::encryption::{Decryptor, Encryptor};
use crate::keypair::{KeyPair, KeyPairGenerator};
use crate::policy::{CryptoMode, CryptoPolicy};
use crate::signature::{Signature, Signer, Verifier};
use std::cell::RefCell;
use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::ptr;

thread_local! {
    static LAST_ERROR: RefCell<Option<CString>> = const { RefCell::new(None) };
}

/// Opaque buffer returned to C callers.
#[repr(C)]
pub struct CryptoshiftBuffer {
    data: *mut u8,
    len: usize,
}

/// Algorithm identifiers for the C API.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CryptoshiftAlgorithm {
    Ed25519 = 1,
    X25519 = 2,
    Rsa2048 = 3,
    Rsa3072 = 4,
    Rsa4096 = 5,
    EcdsaP256 = 6,
    EcdsaP384 = 7,
    Dilithium2 = 10,
    Dilithium3 = 11,
    Dilithium5 = 12,
    Kyber512 = 20,
    Kyber768 = 21,
    Kyber1024 = 22,
}

/// Error codes returned by FFI functions.
#[repr(C)]
pub enum CryptoshiftError {
    Ok = 0,
    InvalidArgument = -1,
    UnsupportedAlgorithm = -2,
    CryptoError = -3,
    InvalidKey = -4,
    InvalidSignature = -5,
    OutOfMemory = -6,
}

fn set_error(msg: impl Into<String>) {
    LAST_ERROR.with(|e| {
        *e.borrow_mut() = CString::new(msg.into()).ok();
    });
}

fn set_error_from(err: crate::Error) {
    set_error(err.to_string());
}

fn op_policy() -> CryptoPolicy {
    CryptoPolicy::new("ffi")
        .set_mode(CryptoMode::Hybrid)
        .set_min_security_level(0)
}

fn algo_from_id(id: CryptoshiftAlgorithm) -> Result<AlgorithmType, CryptoshiftError> {
    match id {
        CryptoshiftAlgorithm::Ed25519 => {
            Ok(AlgorithmType::Classical(ClassicalAlgorithm::Ed25519))
        }
        CryptoshiftAlgorithm::X25519 => Ok(AlgorithmType::Classical(ClassicalAlgorithm::X25519)),
        CryptoshiftAlgorithm::Rsa2048 => Ok(AlgorithmType::Classical(ClassicalAlgorithm::RSA2048)),
        CryptoshiftAlgorithm::Rsa3072 => Ok(AlgorithmType::Classical(ClassicalAlgorithm::RSA3072)),
        CryptoshiftAlgorithm::Rsa4096 => Ok(AlgorithmType::Classical(ClassicalAlgorithm::RSA4096)),
        CryptoshiftAlgorithm::EcdsaP256 => {
            Ok(AlgorithmType::Classical(ClassicalAlgorithm::EcdsaP256))
        }
        CryptoshiftAlgorithm::EcdsaP384 => {
            Ok(AlgorithmType::Classical(ClassicalAlgorithm::EcdsaP384))
        }
        CryptoshiftAlgorithm::Dilithium2 => {
            Ok(AlgorithmType::PostQuantum(PostQuantumAlgorithm::Dilithium2))
        }
        CryptoshiftAlgorithm::Dilithium3 => {
            Ok(AlgorithmType::PostQuantum(PostQuantumAlgorithm::Dilithium3))
        }
        CryptoshiftAlgorithm::Dilithium5 => {
            Ok(AlgorithmType::PostQuantum(PostQuantumAlgorithm::Dilithium5))
        }
        CryptoshiftAlgorithm::Kyber512 => {
            Ok(AlgorithmType::PostQuantum(PostQuantumAlgorithm::Kyber512))
        }
        CryptoshiftAlgorithm::Kyber768 => {
            Ok(AlgorithmType::PostQuantum(PostQuantumAlgorithm::Kyber768))
        }
        CryptoshiftAlgorithm::Kyber1024 => {
            Ok(AlgorithmType::PostQuantum(PostQuantumAlgorithm::Kyber1024))
        }
    }
}

fn make_buffer(bytes: Vec<u8>) -> Result<CryptoshiftBuffer, CryptoshiftError> {
    let mut boxed = bytes.into_boxed_slice();
    let len = boxed.len();
    let data = boxed.as_mut_ptr();
    std::mem::forget(boxed);
    Ok(CryptoshiftBuffer { data, len })
}

fn read_slice<'a>(data: *const u8, len: usize) -> Result<&'a [u8], CryptoshiftError> {
    if data.is_null() || len == 0 {
        return Err(CryptoshiftError::InvalidArgument);
    }
    // SAFETY: caller guarantees `data` points to `len` valid bytes for the call duration.
    Ok(unsafe { std::slice::from_raw_parts(data, len) })
}

fn write_out(out: *mut CryptoshiftBuffer, buf: CryptoshiftBuffer) -> Result<(), CryptoshiftError> {
    if out.is_null() {
        return Err(CryptoshiftError::InvalidArgument);
    }
    // SAFETY: `out` is non-null and writable for one `CryptoshiftBuffer`.
    unsafe { *out = buf };
    Ok(())
}

/// Return the library version string (static, do not free).
#[no_mangle]
pub extern "C" fn cryptoshift_version() -> *const c_char {
    concat!(env!("CARGO_PKG_VERSION"), "\0").as_ptr() as *const c_char
}

/// Return the last error message, or null if none.
#[no_mangle]
pub extern "C" fn cryptoshift_last_error() -> *const c_char {
    LAST_ERROR.with(|e| {
        e.borrow()
            .as_ref()
            .map(|s| s.as_ptr())
            .unwrap_or(ptr::null())
    })
}

/// Free a buffer previously returned by CryptoShift.
#[no_mangle]
pub unsafe extern "C" fn cryptoshift_buffer_free(buf: CryptoshiftBuffer) {
    if !buf.data.is_null() && buf.len > 0 {
        drop(Box::from_raw(std::slice::from_raw_parts_mut(buf.data, buf.len)));
    }
}

/// Generate a key pair for `algorithm`. Public and private keys are returned in
/// separate buffers.
#[no_mangle]
pub unsafe extern "C" fn cryptoshift_keygen(
    algorithm: CryptoshiftAlgorithm,
    public_key_out: *mut CryptoshiftBuffer,
    private_key_out: *mut CryptoshiftBuffer,
) -> i32 {
    let result: Result<(), CryptoshiftError> = (|| {
        let algo = algo_from_id(algorithm)?;
        let generator = KeyPairGenerator::new(op_policy());
        let keypair = generator
            .generate(algo)
            .map_err(|e| {
                set_error_from(e);
                CryptoshiftError::CryptoError
            })?;

        let pub_buf = make_buffer(keypair.public_key().to_vec()).map_err(|e| {
            set_error("out of memory");
            e
        })?;
        let priv_buf = match make_buffer(keypair.private_key().as_bytes().to_vec()) {
            Ok(b) => b,
            Err(e) => {
                unsafe { cryptoshift_buffer_free(pub_buf) };
                set_error("out of memory");
                return Err(e);
            }
        };

        write_out(public_key_out, pub_buf)?;
        write_out(private_key_out, priv_buf)?;
        Ok(())
    })();

    match result {
        Ok(()) => CryptoshiftError::Ok as i32,
        Err(code) => code as i32,
    }
}

/// Sign a message. `private_key` must match `algorithm`.
#[no_mangle]
pub unsafe extern "C" fn cryptoshift_sign(
    algorithm: CryptoshiftAlgorithm,
    private_key: *const u8,
    private_key_len: usize,
    message: *const u8,
    message_len: usize,
    signature_out: *mut CryptoshiftBuffer,
) -> i32 {
    let result: Result<(), CryptoshiftError> = (|| {
        let algo = algo_from_id(algorithm)?;
        let priv_bytes = read_slice(private_key, private_key_len)?;
        let msg = read_slice(message, message_len)?;

        let keypair = KeyPair::new(algo, Vec::new(), priv_bytes.to_vec());
        let signer = Signer::new(op_policy());
        let signature = signer.sign(&keypair, msg).map_err(|e| {
            set_error_from(e);
            CryptoshiftError::CryptoError
        })?;

        let bytes = bincode::serialize(&signature).map_err(|e| {
            set_error(format!("serialization failed: {}", e));
            CryptoshiftError::CryptoError
        })?;

        write_out(signature_out, make_buffer(bytes)?)?;
        Ok(())
    })();

    match result {
        Ok(()) => CryptoshiftError::Ok as i32,
        Err(code) => code as i32,
    }
}

/// Verify a signature. Returns 0 if valid, negative on error or invalid signature.
#[no_mangle]
pub unsafe extern "C" fn cryptoshift_verify(
    algorithm: CryptoshiftAlgorithm,
    public_key: *const u8,
    public_key_len: usize,
    message: *const u8,
    message_len: usize,
    signature: *const u8,
    signature_len: usize,
) -> i32 {
    let result: Result<(), CryptoshiftError> = (|| {
        let _algo = algo_from_id(algorithm)?;
        let pub_bytes = read_slice(public_key, public_key_len)?;
        let msg = read_slice(message, message_len)?;
        let sig_bytes = read_slice(signature, signature_len)?;

        let sig: Signature = bincode::deserialize(sig_bytes).map_err(|e| {
            set_error(format!("invalid signature encoding: {}", e));
            CryptoshiftError::InvalidSignature
        })?;

        let verifier = Verifier::new(op_policy());
        verifier.verify(pub_bytes, msg, &sig).map_err(|e| {
            set_error_from(e);
            CryptoshiftError::InvalidSignature
        })?;
        Ok(())
    })();

    match result {
        Ok(()) => CryptoshiftError::Ok as i32,
        Err(code) => code as i32,
    }
}

/// Encrypt plaintext for a recipient public key (KEM-DEM).
#[no_mangle]
pub unsafe extern "C" fn cryptoshift_encrypt(
    algorithm: CryptoshiftAlgorithm,
    public_key: *const u8,
    public_key_len: usize,
    plaintext: *const u8,
    plaintext_len: usize,
    ciphertext_out: *mut CryptoshiftBuffer,
) -> i32 {
    let result: Result<(), CryptoshiftError> = (|| {
        let algo = algo_from_id(algorithm)?;
        let pub_bytes = read_slice(public_key, public_key_len)?;
        let plain = read_slice(plaintext, plaintext_len)?;

        let encryptor = Encryptor::new(op_policy());
        let message = encryptor.encrypt(algo, pub_bytes, plain).map_err(|e| {
            set_error_from(e);
            CryptoshiftError::CryptoError
        })?;

        let bytes = message.to_bytes().map_err(|e| {
            set_error_from(e);
            CryptoshiftError::CryptoError
        })?;

        write_out(ciphertext_out, make_buffer(bytes)?)?;
        Ok(())
    })();

    match result {
        Ok(()) => CryptoshiftError::Ok as i32,
        Err(code) => code as i32,
    }
}

/// Decrypt a message with a private key.
#[no_mangle]
pub unsafe extern "C" fn cryptoshift_decrypt(
    algorithm: CryptoshiftAlgorithm,
    private_key: *const u8,
    private_key_len: usize,
    ciphertext: *const u8,
    ciphertext_len: usize,
    plaintext_out: *mut CryptoshiftBuffer,
) -> i32 {
    let result: Result<(), CryptoshiftError> = (|| {
        let algo = algo_from_id(algorithm)?;
        let priv_bytes = read_slice(private_key, private_key_len)?;
        let ct = read_slice(ciphertext, ciphertext_len)?;

        let message = crate::encryption::EncryptedMessage::from_bytes(ct).map_err(|e| {
            set_error_from(e);
            CryptoshiftError::CryptoError
        })?;

        let keypair = KeyPair::new(algo, Vec::new(), priv_bytes.to_vec());
        let decryptor = Decryptor::new(op_policy());
        let plain = decryptor.decrypt(&keypair, &message).map_err(|e| {
            set_error_from(e);
            CryptoshiftError::CryptoError
        })?;

        write_out(plaintext_out, make_buffer(plain)?)?;
        Ok(())
    })();

    match result {
        Ok(()) => CryptoshiftError::Ok as i32,
        Err(code) => code as i32,
    }
}

/// Scan text for cryptographic usage. `sources_json` is a JSON array of
/// `[{"name": "file.rs", "content": "..."}]` objects.
#[no_mangle]
pub unsafe extern "C" fn cryptoshift_scan_text(
    sources_json: *const c_char,
    report_json_out: *mut CryptoshiftBuffer,
) -> i32 {
    let result: Result<(), CryptoshiftError> = (|| {
        if sources_json.is_null() {
            return Err(CryptoshiftError::InvalidArgument);
        }
        let json_str = CStr::from_ptr(sources_json).to_str().map_err(|_| {
            set_error("invalid UTF-8 in sources_json");
            CryptoshiftError::InvalidArgument
        })?;

        #[derive(serde::Deserialize)]
        struct SourceEntry {
            name: String,
            content: String,
        }

        let sources: Vec<SourceEntry> = serde_json::from_str(json_str).map_err(|e| {
            set_error(format!("invalid sources JSON: {}", e));
            CryptoshiftError::InvalidArgument
        })?;

        let inventory = crate::inventory::CryptoInventory::new();
        let mut report = crate::inventory::InventoryReport::default();
        for entry in sources {
            report
                .findings
                .extend(inventory.scan_text(&entry.name, &entry.content));
        }

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

        let bytes = serde_json::to_vec(&output).map_err(|e| {
            set_error(format!("JSON serialization failed: {}", e));
            CryptoshiftError::CryptoError
        })?;

        write_out(report_json_out, make_buffer(bytes)?)?;
        Ok(())
    })();

    match result {
        Ok(()) => CryptoshiftError::Ok as i32,
        Err(code) => code as i32,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ffi_keygen_sign_verify_ed25519() {
        let mut pub_buf = CryptoshiftBuffer {
            data: ptr::null_mut(),
            len: 0,
        };
        let mut priv_buf = CryptoshiftBuffer {
            data: ptr::null_mut(),
            len: 0,
        };

        let rc = unsafe {
            cryptoshift_keygen(
                CryptoshiftAlgorithm::Ed25519,
                &mut pub_buf,
                &mut priv_buf,
            )
        };
        assert_eq!(rc, 0);
        assert!(pub_buf.len > 0);
        assert!(priv_buf.len > 0);

        let message = b"ffi test message";
        let mut sig_buf = CryptoshiftBuffer {
            data: ptr::null_mut(),
            len: 0,
        };

        let rc = unsafe {
            cryptoshift_sign(
                CryptoshiftAlgorithm::Ed25519,
                priv_buf.data,
                priv_buf.len,
                message.as_ptr(),
                message.len(),
                &mut sig_buf,
            )
        };
        assert_eq!(rc, 0);

        let rc = unsafe {
            cryptoshift_verify(
                CryptoshiftAlgorithm::Ed25519,
                pub_buf.data,
                pub_buf.len,
                message.as_ptr(),
                message.len(),
                sig_buf.data,
                sig_buf.len,
            )
        };
        assert_eq!(rc, 0);

        unsafe {
            cryptoshift_buffer_free(sig_buf);
            cryptoshift_buffer_free(pub_buf);
            cryptoshift_buffer_free(priv_buf);
        }
    }

    #[test]
    fn test_ffi_encrypt_decrypt_kyber768() {
        let mut pub_buf = CryptoshiftBuffer {
            data: ptr::null_mut(),
            len: 0,
        };
        let mut priv_buf = CryptoshiftBuffer {
            data: ptr::null_mut(),
            len: 0,
        };

        unsafe {
            cryptoshift_keygen(
                CryptoshiftAlgorithm::Kyber768,
                &mut pub_buf,
                &mut priv_buf,
            )
        };

        let plain = b"secret via ffi";
        let mut ct_buf = CryptoshiftBuffer {
            data: ptr::null_mut(),
            len: 0,
        };
        let mut out_buf = CryptoshiftBuffer {
            data: ptr::null_mut(),
            len: 0,
        };

        let rc = unsafe {
            cryptoshift_encrypt(
                CryptoshiftAlgorithm::Kyber768,
                pub_buf.data,
                pub_buf.len,
                plain.as_ptr(),
                plain.len(),
                &mut ct_buf,
            )
        };
        assert_eq!(rc, 0);

        let rc = unsafe {
            cryptoshift_decrypt(
                CryptoshiftAlgorithm::Kyber768,
                priv_buf.data,
                priv_buf.len,
                ct_buf.data,
                ct_buf.len,
                &mut out_buf,
            )
        };
        assert_eq!(rc, 0);

        let recovered =
            unsafe { std::slice::from_raw_parts(out_buf.data, out_buf.len) };
        assert_eq!(recovered, plain);

        unsafe {
            cryptoshift_buffer_free(out_buf);
            cryptoshift_buffer_free(ct_buf);
            cryptoshift_buffer_free(pub_buf);
            cryptoshift_buffer_free(priv_buf);
        }
    }
}
