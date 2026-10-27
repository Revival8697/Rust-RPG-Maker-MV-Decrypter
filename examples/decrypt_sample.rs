//! Example demonstrating how to use `rpgmv_decrypter` programmatically.

use rpgmv_decrypter::{Decrypter, EncryptionKey, PNG_HEADER};
use std::error::Error;

fn main() -> Result<(), Box<dyn Error>> {
    println!("=== RPG Maker MV/MZ Decrypter Library Example ===");

    // 1. Initialize an encryption key from hex
    let hex_key = "d41d8cd98f00b204e9800998ecf8427e";
    let key = EncryptionKey::from_hex(hex_key)?;
    println!("Encryption Key (hex): {}", key.to_hex());

    // 2. Instantiate decrypter
    let decrypter = Decrypter::new(Some(key.clone()));

    // 3. Encrypt sample image data
    let mut fake_png = PNG_HEADER.to_vec();
    fake_png.extend_from_slice(b"IHDR\0\0\x01\0\0\0\x01\x08\x06\0\0\0sample_png_payload");

    let encrypted = decrypter.encrypt_bytes(&fake_png)?;
    println!("Original byte count:  {}", fake_png.len());
    println!(
        "Encrypted byte count: {} (includes 16-byte fake header)",
        encrypted.len()
    );

    // 4. Decrypt sample image data with the key
    let decrypted = decrypter.decrypt_bytes(&encrypted, false)?;
    assert_eq!(decrypted, fake_png);
    println!("Key-based Decryption: SUCCESS (byte match confirmed)");

    // 5. Restore PNG without a key
    let decrypter_no_key = Decrypter::new(None);
    let restored = decrypter_no_key.decrypt_bytes(&encrypted, true)?;
    assert_eq!(&restored[..16], &PNG_HEADER);
    println!("Keyless PNG Restoration: SUCCESS (magic PNG header restored)");

    println!("\nAll library demonstration operations completed successfully!");
    Ok(())
}
