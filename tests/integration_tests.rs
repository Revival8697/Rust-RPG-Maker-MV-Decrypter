use std::fs;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;
use tempfile::tempdir;

use rpgmv_decrypter::engine::Decrypter;
use rpgmv_decrypter::header::{HeaderConfig, PNG_HEADER};
use rpgmv_decrypter::key::EncryptionKey;
use rpgmv_decrypter::processor::{FileProcessor, ProcessorOptions};

#[test]
fn test_batch_decryption_and_restoration_pipeline() {
    let temp = tempdir().unwrap();
    let project_dir = temp.path().join("game");
    let www_dir = project_dir.join("www");
    let data_dir = www_dir.join("data");
    let audio_dir = www_dir.join("audio").join("bgm");
    let img_dir = www_dir.join("img").join("characters");

    fs::create_dir_all(&data_dir).unwrap();
    fs::create_dir_all(&audio_dir).unwrap();
    fs::create_dir_all(&img_dir).unwrap();

    // 1. Create a System.json with a known key
    let hex_key = "d41d8cd98f00b204e9800998ecf8427e";
    let system_json = format!(
        r#"{{
            "gameTitle": "Test Game",
            "encryptionKey": "{}",
            "hasEncryptedImages": true,
            "hasEncryptedAudio": true
        }}"#,
        hex_key
    );
    fs::write(data_dir.join("System.json"), system_json).unwrap();

    let key = EncryptionKey::from_hex(hex_key).unwrap();
    let decrypter = Decrypter::new(Some(key));

    // 2. Prepare sample assets
    let original_audio = b"OggS_SIMULATED_VORBIS_AUDIO_PAYLOAD_FOR_TESTING";
    let mut original_image = PNG_HEADER.to_vec();
    original_image.extend_from_slice(b"IHDR_DATA_AND_CHUNK_STREAM_PAYLOAD");

    // 3. Encrypt them
    let encrypted_audio = decrypter.encrypt_bytes(original_audio).unwrap();
    let encrypted_image = decrypter.encrypt_bytes(&original_image).unwrap();

    fs::write(audio_dir.join("Theme1.rpgmvo"), &encrypted_audio).unwrap();
    fs::write(img_dir.join("Actor1.rpgmvp"), &encrypted_image).unwrap();

    // 4. Run batch decryption into output directory
    let output_dir = temp.path().join("output");
    let options = ProcessorOptions {
        output_dir: Some(output_dir.clone()),
        in_place: false,
        overwrite: true,
        restore_images: false,
        worker_threads: Some(2),
        progress_callback: None,
    };

    let processor = FileProcessor::new(&decrypter, options);
    let summary = processor.decrypt_all(&project_dir).unwrap();

    assert_eq!(summary.files_processed, 2);
    assert_eq!(summary.files_failed, 0);

    // 5. Verify output files exist with decrypted extensions and contents match exactly
    let decrypted_audio_path = output_dir
        .join("www")
        .join("audio")
        .join("bgm")
        .join("Theme1.ogg");
    let decrypted_image_path = output_dir
        .join("www")
        .join("img")
        .join("characters")
        .join("Actor1.png");

    assert!(decrypted_audio_path.exists());
    assert!(decrypted_image_path.exists());

    let recovered_audio = fs::read(&decrypted_audio_path).unwrap();
    let recovered_image = fs::read(&decrypted_image_path).unwrap();

    assert_eq!(recovered_audio, original_audio);
    assert_eq!(recovered_image, original_image);
}

#[test]
fn test_in_place_image_restore_without_key() {
    let temp = tempdir().unwrap();
    let img_dir = temp.path().join("img");
    fs::create_dir_all(&img_dir).unwrap();

    let hex_key = "11223344556677889900aabbccddeeff";
    let key = EncryptionKey::from_hex(hex_key).unwrap();
    let encrypter = Decrypter::new(Some(key));

    let mut original_png = PNG_HEADER.to_vec();
    original_png.extend_from_slice(b"Secret image graphic content");

    let encrypted = encrypter.encrypt_bytes(&original_png).unwrap();
    let enc_path = img_dir.join("Picture1.png_"); // MZ extension
    fs::write(&enc_path, &encrypted).unwrap();

    // Restore without key
    let restore_decrypter =
        Decrypter::new(None).with_header_config(HeaderConfig::new().with_ignore_fake_header(true));

    let options = ProcessorOptions {
        output_dir: None,
        in_place: true,
        overwrite: true,
        restore_images: true,
        worker_threads: Some(1),
        progress_callback: None,
    };

    let processor = FileProcessor::new(&restore_decrypter, options);
    let summary = processor.decrypt_all(&img_dir).unwrap();

    assert_eq!(summary.files_processed, 1);
    let restored_file = img_dir.join("Picture1.png");
    assert!(restored_file.exists());

    let restored_data = fs::read(restored_file).unwrap();
    assert_eq!(restored_data, original_png);
}

#[test]
fn test_single_file_custom_output_filename() {
    let temp = tempdir().unwrap();
    let key = EncryptionKey::from_hex("00112233445566778899aabbccddeeff").unwrap();
    let decrypter = Decrypter::new(Some(key));

    let mut original_image = PNG_HEADER.to_vec();
    original_image.extend_from_slice(b"custom_destination_file_test");
    let encrypted = decrypter.encrypt_bytes(&original_image).unwrap();

    let input_file = temp.path().join("hero.rpgmvp");
    fs::write(&input_file, &encrypted).unwrap();

    // Specify a direct file path for -o rather than a directory
    let output_file = temp.path().join("custom_named_hero.png");

    let options = ProcessorOptions {
        output_dir: Some(output_file.clone()),
        in_place: false,
        overwrite: true,
        restore_images: false,
        worker_threads: Some(1),
        progress_callback: None,
    };

    let processor = FileProcessor::new(&decrypter, options);
    let summary = processor.decrypt_all(&input_file).unwrap();

    assert_eq!(summary.files_processed, 1);
    assert_eq!(summary.files_failed, 0);
    assert!(output_file.exists());
    assert!(!output_file.is_dir());

    let recovered = fs::read(&output_file).unwrap();
    assert_eq!(recovered, original_image);
}

#[test]
fn test_atomic_in_place_overwrite() {
    let temp = tempdir().unwrap();
    let key = EncryptionKey::from_hex("00112233445566778899aabbccddeeff").unwrap();
    let decrypter = Decrypter::new(Some(key));

    let mut original_image = PNG_HEADER.to_vec();
    original_image.extend_from_slice(b"atomic_overwrite_in_place_payload");
    let encrypted = decrypter.encrypt_bytes(&original_image).unwrap();

    let target_file = temp.path().join("asset.bin");
    fs::write(&target_file, &encrypted).unwrap();

    // Decrypt where src == dst: atomic temp file ensures target_file is not truncated before reading
    let written = decrypter
        .decrypt_file(&target_file, &target_file, false)
        .unwrap();
    assert_eq!(written, original_image.len() as u64);

    let recovered = fs::read(&target_file).unwrap();
    assert_eq!(recovered, original_image);
}

#[test]
fn test_process_summary_failure_tracking() {
    let temp = tempdir().unwrap();
    let key = EncryptionKey::from_hex("00112233445566778899aabbccddeeff").unwrap();
    let decrypter = Decrypter::new(Some(key));

    // Create a corrupted file (< 32 bytes)
    let bad_file = temp.path().join("corrupted.rpgmvp");
    fs::write(&bad_file, b"short").unwrap();

    let options = ProcessorOptions {
        output_dir: Some(temp.path().join("out")),
        in_place: false,
        overwrite: true,
        restore_images: false,
        worker_threads: Some(1),
        progress_callback: None,
    };

    let processor = FileProcessor::new(&decrypter, options);
    let summary = processor.decrypt_all(&bad_file).unwrap();

    assert_eq!(summary.files_processed, 0);
    assert_eq!(summary.files_failed, 1);
    assert_eq!(summary.failed_files.len(), 1);
    assert_eq!(summary.failed_files[0].path, bad_file);
    assert!(summary.failed_files[0].error.contains("too short"));
}

#[test]
fn test_progress_callback() {
    let temp = tempdir().unwrap();
    let key = EncryptionKey::from_hex("00112233445566778899aabbccddeeff").unwrap();
    let decrypter = Decrypter::new(Some(key));

    let mut original_image = PNG_HEADER.to_vec();
    original_image.extend_from_slice(b"progress_callback_test");
    let encrypted = decrypter.encrypt_bytes(&original_image).unwrap();

    let f1 = temp.path().join("img1.rpgmvp");
    let f2 = temp.path().join("img2.rpgmvp");
    fs::write(&f1, &encrypted).unwrap();
    fs::write(&f2, &encrypted).unwrap();

    let call_count = Arc::new(AtomicUsize::new(0));
    let call_count_clone = call_count.clone();

    let options = ProcessorOptions {
        output_dir: Some(temp.path().join("out")),
        in_place: false,
        overwrite: true,
        restore_images: false,
        worker_threads: Some(1),
        progress_callback: Some(Arc::new(move |_done, _total| {
            call_count_clone.fetch_add(1, Ordering::SeqCst);
        })),
    };

    let processor = FileProcessor::new(&decrypter, options);
    let summary = processor.decrypt_all(temp.path()).unwrap();

    assert_eq!(summary.files_processed, 2);
    assert!(call_count.load(Ordering::SeqCst) >= 2);
}

#[test]
fn test_summary_json_serialization() {
    let temp = tempdir().unwrap();
    let key = EncryptionKey::from_hex("00112233445566778899aabbccddeeff").unwrap();
    let decrypter = Decrypter::new(Some(key));

    let mut original_image = PNG_HEADER.to_vec();
    original_image.extend_from_slice(b"json_test");
    let encrypted = decrypter.encrypt_bytes(&original_image).unwrap();

    let f1 = temp.path().join("img1.rpgmvp");
    fs::write(&f1, &encrypted).unwrap();

    let options = ProcessorOptions {
        output_dir: Some(temp.path().join("out")),
        in_place: false,
        overwrite: true,
        restore_images: false,
        worker_threads: Some(1),
        progress_callback: None,
    };

    let processor = FileProcessor::new(&decrypter, options);
    let summary = processor.decrypt_all(&f1).unwrap();

    let json_str = serde_json::to_string(&summary).unwrap();
    assert!(json_str.contains("\"files_processed\":1"));
    assert!(json_str.contains("\"files_failed\":0"));
    assert!(json_str.contains("\"failed_files\":[]"));
}
