//! High-performance, idiomatic Rust port of RPG Maker MV/MZ Decrypter.
//!
//! Provides core streaming decryption, header manipulation, key extraction/derivation,
//! and multi-threaded parallel batch processing.
//!
//! # Quick Start
//!
//! ```rust
//! use rpgmv_decrypter::{Decrypter, EncryptionKey};
//!
//! # fn main() -> Result<(), Box<dyn std::error::Error>> {
//! let key = EncryptionKey::from_hex("d41d8cd98f00b204e9800998ecf8427e")?;
//! let decrypter = Decrypter::new(Some(key));
//!
//! let original = b"Plaintext asset data payload with more than 16 bytes";
//! let encrypted = decrypter.encrypt_bytes(original)?;
//! let decrypted = decrypter.decrypt_bytes(&encrypted, false)?;
//! assert_eq!(decrypted, original);
//! # Ok(())
//! # }
//! ```

#[cfg(feature = "cli")]
pub mod cli;
pub mod engine;
pub mod error;
pub mod extensions;
pub mod finder;
pub mod header;
pub mod key;
pub mod processor;

// Convenient re-exports for library consumers
pub use engine::Decrypter;
pub use error::{DecryptionError, Result};
pub use extensions::{
    decrypted_path, encrypted_path, is_encrypted_audio, is_encrypted_extension, is_encrypted_image,
    target_decrypted_extension, target_encrypted_extension, AssetKind, EngineFormat,
};
pub use finder::{find_first_encrypted_image, find_system_json, verify_rpg_dir};
pub use header::{HeaderConfig, DEFAULT_HEADER_LEN, PNG_HEADER};
pub use key::{
    extract_key_from_system_json, load_key_from_system_file, EncryptionKey, SystemJsonInfo,
};
pub use processor::{
    FailedFile, FileProcessor, ProcessSummary, ProcessorOptions, ProgressCallback,
};
