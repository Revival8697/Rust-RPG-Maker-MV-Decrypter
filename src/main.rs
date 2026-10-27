//! CLI entry point for the RPG Maker MV/MZ Decrypter tool.

use std::io::{stderr, IsTerminal, Write};
use std::path::{Path, PathBuf};
use std::process::ExitCode;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::Arc;

use anyhow::{bail, Context, Result};
use clap::Parser;
use serde::Serialize;

use rpgmv_decrypter::cli::{Cli, Commands, DecryptArgs, DetectKeyArgs, EncryptArgs, RestoreArgs};
use rpgmv_decrypter::engine::Decrypter;
use rpgmv_decrypter::finder::{find_first_encrypted_image, find_system_json, verify_rpg_dir};
use rpgmv_decrypter::header::HeaderConfig;
use rpgmv_decrypter::key::{load_key_from_system_file, EncryptionKey, SystemJsonInfo};
use rpgmv_decrypter::processor::{
    FileProcessor, ProcessSummary, ProcessorOptions, ProgressCallback,
};

#[derive(Serialize)]
struct JsonKeyResult<'a> {
    status: &'static str,
    command: &'static str,
    target: &'a str,
    key: String,
    has_encrypted_images: Option<bool>,
    has_encrypted_audio: Option<bool>,
}

#[derive(Serialize)]
struct JsonBatchResult<'a> {
    status: &'static str,
    command: &'static str,
    target: &'a str,
    key: Option<String>,
    summary: &'a ProcessSummary,
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    let is_json = cli.json;

    match run_app(cli) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            if is_json {
                let err_obj = serde_json::json!({
                    "status": "error",
                    "error": format!("{:#}", err)
                });
                eprintln!("{}", err_obj);
            } else {
                eprintln!("\n[FATAL ERROR] {:#}", err);
            }
            ExitCode::FAILURE
        }
    }
}

fn run_app(cli: Cli) -> Result<()> {
    let json = cli.json;
    let quiet = cli.quiet;

    match cli.command {
        Commands::Decrypt(args) => handle_decrypt(args, json, quiet),
        Commands::Restore(args) => handle_restore(args, json, quiet),
        Commands::DetectKey(args) => handle_detect_key(args, json, quiet),
        Commands::Encrypt(args) => handle_encrypt(args, json, quiet),
    }
}

/// Creates a terminal progress bar callback if stderr is connected to a TTY and not in quiet/json mode.
fn create_cli_progress_callback(quiet: bool, json: bool) -> Option<ProgressCallback> {
    if quiet || json || !stderr().is_terminal() {
        return None;
    }

    let last_printed_percent = Arc::new(AtomicUsize::new(usize::MAX));

    Some(Arc::new(move |done: usize, total: usize| {
        if total == 0 {
            return;
        }
        let percent = (done * 100) / total;
        let prev = last_printed_percent.swap(percent, Ordering::Relaxed);
        if prev != percent || done == total {
            let width = 28;
            let filled = (percent * width) / 100;
            let empty = width - filled;
            let bar: String = "=".repeat(filled) + &" ".repeat(empty);
            eprint!(
                "\r\x1b[KProgress: [{}] {}/{} ({}%)",
                bar, done, total, percent
            );
            let _ = stderr().flush();
            if done == total {
                eprintln!();
            }
        }
    }))
}

/// Resolves or automatically discovers the encryption key for a project or file.
fn resolve_key(
    explicit_key: Option<&str>,
    input_path: &Path,
    header_len: usize,
    quiet: bool,
) -> Result<(EncryptionKey, Option<SystemJsonInfo>)> {
    // 1. Explicit key given via CLI flag
    if let Some(hex_key) = explicit_key {
        if !quiet {
            println!("[KEY] Using user-provided encryption key: {}", hex_key);
        }
        let key = EncryptionKey::from_hex(hex_key).context("Failed to parse provided hex key")?;
        return Ok((key, None));
    }

    // 2. If input is directly a System.json file
    if input_path.is_file() {
        if let Some(file_name) = input_path.file_name().and_then(|s| s.to_str()) {
            if file_name.eq_ignore_ascii_case("system.json") {
                let (key, info) = load_key_from_system_file(input_path, None)?;
                if !quiet {
                    println!(
                        "[KEY] Extracted key from '{}': {}",
                        input_path.display(),
                        key.to_hex()
                    );
                }
                return Ok((key, Some(info)));
            }
        }
        // If input is an encrypted image file, derive key from it
        if let Ok(key) = EncryptionKey::derive_from_png_file(input_path, header_len) {
            if !quiet {
                println!(
                    "[KEY] Derived key from image '{}': {}",
                    input_path.display(),
                    key.to_hex()
                );
            }
            return Ok((key, None));
        }
    }

    // 3. Search for System.json within project directory
    if let Some(sys_path) = find_system_json(input_path) {
        match load_key_from_system_file(&sys_path, None) {
            Ok((key, info)) => {
                if !quiet {
                    println!(
                        "[KEY] Detected key from '{}': {}",
                        sys_path.display(),
                        key.to_hex()
                    );
                    if let Some(imgs) = info.has_encrypted_images {
                        println!("[INFO] Project hasEncryptedImages: {}", imgs);
                    }
                    if let Some(audio) = info.has_encrypted_audio {
                        println!("[INFO] Project hasEncryptedAudio: {}", audio);
                    }
                }
                return Ok((key, Some(info)));
            }
            Err(e) => {
                if !quiet {
                    eprintln!(
                        "[WARN] Found System.json at '{}' but could not extract key: {}",
                        sys_path.display(),
                        e
                    );
                }
            }
        }
    }

    // 4. Fallback: Derive key from an encrypted PNG inside the project directory
    if let Some(img_path) = find_first_encrypted_image(input_path) {
        if !quiet {
            println!(
                "[KEY] System.json had no key. Attempting derivation from encrypted image: {}",
                img_path.display()
            );
        }
        match EncryptionKey::derive_from_png_file(&img_path, header_len) {
            Ok(derived_key) => {
                if !quiet {
                    println!(
                        "[KEY] Successfully derived key from image: {}",
                        derived_key.to_hex()
                    );
                }
                return Ok((derived_key, None));
            }
            Err(e) => {
                if !quiet {
                    eprintln!(
                        "[WARN] Failed to derive key from '{}': {}",
                        img_path.display(),
                        e
                    );
                }
            }
        }
    }

    bail!(
        "Encryption key could not be detected automatically. Please supply one via '-k <HEX_KEY>'."
    );
}

fn handle_decrypt(args: DecryptArgs, json: bool, quiet: bool) -> Result<()> {
    if !args.input.exists() {
        bail!("Target input path does not exist: {}", args.input.display());
    }

    if args.verify_project_dir && args.input.is_dir() && !verify_rpg_dir(&args.input) {
        bail!(
            "Directory '{}' does not appear to be a valid RPG Maker project.",
            args.input.display()
        );
    }

    let (key, _) = resolve_key(
        args.key.as_deref(),
        &args.input,
        args.header_len,
        quiet || json,
    )?;

    let header_config = HeaderConfig::new()
        .with_header_len(args.header_len)?
        .with_ignore_fake_header(!args.verify_header);

    let engine = Decrypter::new(Some(key.clone())).with_header_config(header_config);

    let output_dir = if args.in_place {
        None
    } else {
        Some(args.output.unwrap_or_else(|| PathBuf::from("output")))
    };

    let options = ProcessorOptions {
        output_dir,
        in_place: args.in_place,
        overwrite: !args.no_overwrite,
        restore_images: false,
        worker_threads: args.threads,
        progress_callback: create_cli_progress_callback(quiet, json),
    };

    if !json && !quiet {
        println!("\n=== Starting RPG Maker MV/MZ Decryption ===");
        println!("Source:        {}", args.input.display());
        if args.in_place {
            println!("Output Mode:   In-Place (decrypted next to originals)");
        } else {
            println!(
                "Output Dir:    {}",
                options.output_dir.as_ref().unwrap().display()
            );
        }
        println!(
            "Fake Header:   {}",
            if args.verify_header {
                "Strict Verification"
            } else {
                "Ignored / Stripped"
            }
        );
    }

    let processor = FileProcessor::new(&engine, options);
    let summary = processor.decrypt_all(&args.input)?;

    if json {
        let res = JsonBatchResult {
            status: "success",
            command: "decrypt",
            target: &args.input.to_string_lossy(),
            key: Some(key.to_hex()),
            summary: &summary,
        };
        println!("{}", serde_json::to_string_pretty(&res)?);
    } else {
        print_summary("Decryption Complete", &summary, quiet);
    }

    Ok(())
}

fn handle_restore(args: RestoreArgs, json: bool, quiet: bool) -> Result<()> {
    if !args.input.exists() {
        bail!("Target input path does not exist: {}", args.input.display());
    }

    let header_config = HeaderConfig::new()
        .with_header_len(args.header_len)?
        .with_ignore_fake_header(true);

    let engine = Decrypter::new(None).with_header_config(header_config);

    let output_dir = if args.in_place {
        None
    } else {
        Some(args.output.unwrap_or_else(|| PathBuf::from("output")))
    };

    let options = ProcessorOptions {
        output_dir,
        in_place: args.in_place,
        overwrite: !args.no_overwrite,
        restore_images: true,
        worker_threads: args.threads,
        progress_callback: create_cli_progress_callback(quiet, json),
    };

    if !json && !quiet {
        println!("\n=== Restoring RPG Maker PNG Images (No Key Required) ===");
        println!("Source:     {}", args.input.display());
        if args.in_place {
            println!("Mode:       In-Place");
        } else {
            println!(
                "Output Dir: {}",
                options.output_dir.as_ref().unwrap().display()
            );
        }
    }

    let processor = FileProcessor::new(&engine, options);
    let summary = processor.decrypt_all(&args.input)?;

    if json {
        let res = JsonBatchResult {
            status: "success",
            command: "restore",
            target: &args.input.to_string_lossy(),
            key: None,
            summary: &summary,
        };
        println!("{}", serde_json::to_string_pretty(&res)?);
    } else {
        print_summary("Image Restoration Complete", &summary, quiet);
    }

    Ok(())
}

fn handle_detect_key(args: DetectKeyArgs, json: bool, quiet: bool) -> Result<()> {
    if !args.input.exists() {
        bail!("Target path does not exist: {}", args.input.display());
    }

    if !json && !quiet {
        println!("Searching for encryption key in: {}", args.input.display());
    }

    if args.from_png {
        let (key, img_path) = if args.input.is_file() {
            let key = EncryptionKey::derive_from_png_file(&args.input, args.header_len)?;
            (key, args.input.clone())
        } else if let Some(img_path) = find_first_encrypted_image(&args.input) {
            let key = EncryptionKey::derive_from_png_file(&img_path, args.header_len)?;
            (key, img_path)
        } else {
            bail!("No encrypted PNG image (.rpgmvp or .png_) found in directory.");
        };

        if json {
            let res = JsonKeyResult {
                status: "success",
                command: "detect-key",
                target: &img_path.to_string_lossy(),
                key: key.to_hex(),
                has_encrypted_images: None,
                has_encrypted_audio: None,
            };
            println!("{}", serde_json::to_string_pretty(&res)?);
        } else {
            println!(
                "\n[SUCCESS] Derived encryption key from image: {}",
                key.to_hex()
            );
        }
        return Ok(());
    }

    // Default search flow
    let (key, sys_info) = resolve_key(None, &args.input, args.header_len, quiet || json)?;

    if json {
        let res = JsonKeyResult {
            status: "success",
            command: "detect-key",
            target: &args.input.to_string_lossy(),
            key: key.to_hex(),
            has_encrypted_images: sys_info.as_ref().and_then(|i| i.has_encrypted_images),
            has_encrypted_audio: sys_info.as_ref().and_then(|i| i.has_encrypted_audio),
        };
        println!("{}", serde_json::to_string_pretty(&res)?);
    } else {
        println!("\n========================================");
        println!(" Detected Encryption Key: {}", key.to_hex());
        println!("========================================");
    }

    Ok(())
}

fn handle_encrypt(args: EncryptArgs, json: bool, quiet: bool) -> Result<()> {
    if !args.input.exists() {
        bail!("Target input path does not exist: {}", args.input.display());
    }

    let (key, _) = resolve_key(
        args.key.as_deref(),
        &args.input,
        args.header_len,
        quiet || json,
    )?;

    let header_config = HeaderConfig::new().with_header_len(args.header_len)?;
    let engine = Decrypter::new(Some(key.clone())).with_header_config(header_config);

    let output_dir = if args.in_place {
        None
    } else {
        Some(args.output.unwrap_or_else(|| PathBuf::from("output")))
    };

    let options = ProcessorOptions {
        output_dir,
        in_place: args.in_place,
        overwrite: !args.no_overwrite,
        restore_images: false,
        worker_threads: args.threads,
        progress_callback: create_cli_progress_callback(quiet, json),
    };

    if !json && !quiet {
        println!("\n=== Starting RPG Maker Asset Encryption ===");
        println!("Source:      {}", args.input.display());
        println!(
            "Target Type: {}",
            if args.mz {
                "RPG Maker MZ (.png_, .m4a_, .ogg_)"
            } else {
                "RPG Maker MV (.rpgmvp, .rpgmvm, .rpgmvo)"
            }
        );
    }

    let processor = FileProcessor::new(&engine, options);
    let summary = processor.encrypt_all(&args.input, !args.mz)?;

    if json {
        let res = JsonBatchResult {
            status: "success",
            command: "encrypt",
            target: &args.input.to_string_lossy(),
            key: Some(key.to_hex()),
            summary: &summary,
        };
        println!("{}", serde_json::to_string_pretty(&res)?);
    } else {
        print_summary("Encryption Complete", &summary, quiet);
    }

    Ok(())
}

fn print_summary(title: &str, summary: &ProcessSummary, quiet: bool) {
    if quiet {
        return;
    }

    println!("\n--- {} ---", title);
    println!("Files processed: {}", summary.files_processed);
    println!("Files skipped:   {}", summary.files_skipped);
    println!("Files failed:    {}", summary.files_failed);
    println!(
        "Total payload:   {:.2} MB",
        (summary.bytes_written as f64) / (1024.0 * 1024.0)
    );
    println!("Elapsed time:    {:.2?}", summary.elapsed);
    println!("Throughput:      {:.2} MB/s", summary.throughput_mbps);

    if !summary.failed_files.is_empty() {
        eprintln!("\nFailed files ({}):", summary.failed_files.len());
        for f in summary.failed_files.iter().take(10) {
            eprintln!("  - '{}': {}", f.path.display(), f.error);
        }
        if summary.failed_files.len() > 10 {
            eprintln!("  ... and {} more", summary.failed_files.len() - 10);
        }
    }
}
