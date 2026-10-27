//! Command-line argument definitions using Clap (derive API).

use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

/// High-performance CLI tool for decrypting and encrypting RPG Maker MV/MZ assets.
#[derive(Debug, Parser)]
#[command(
    name = "rpgmv-decrypter",
    version,
    about = "Blazing-fast, memory-safe RPG Maker MV/MZ decrypter written in Rust",
    long_about = "A multi-threaded CLI utility to decrypt and restore RPG Maker MV (.rpgmvp, .rpgmvm, .rpgmvo) \
                  and MZ (.png_, .m4a_, .ogg_) encrypted assets with automatic key detection."
)]
pub struct Cli {
    /// Output result in machine-readable JSON format
    #[arg(long, global = true, help = "Output result in structured JSON format")]
    pub json: bool,

    /// Suppress non-essential banner and progress output
    #[arg(
        short,
        long,
        global = true,
        help = "Suppress banner and non-essential progress output"
    )]
    pub quiet: bool,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Debug, Subcommand)]
pub enum Commands {
    /// Decrypt RPG Maker MV/MZ files or entire project directories
    #[command(visible_alias = "dec")]
    Decrypt(DecryptArgs),

    /// Restore PNG image files without an encryption key
    Restore(RestoreArgs),

    /// Detect and display the encryption key from System.json or encrypted PNGs
    #[command(visible_alias = "key")]
    DetectKey(DetectKeyArgs),

    /// (Re-)Encrypt asset files to RPG Maker MV or MZ format
    #[command(visible_alias = "enc")]
    Encrypt(EncryptArgs),
}

#[derive(Debug, Args)]
pub struct DecryptArgs {
    /// Target path to project directory or individual encrypted file
    #[arg(value_name = "TARGET_PATH")]
    pub input: PathBuf,

    /// Destination directory for decrypted files (defaults to 'output' directory)
    #[arg(short, long, value_name = "DIR")]
    pub output: Option<PathBuf>,

    /// Save decrypted files directly into the project directory alongside originals
    #[arg(short = 'i', long)]
    pub in_place: bool,

    /// 32-character hexadecimal encryption key (auto-detected if omitted)
    #[arg(short = 'k', long, value_name = "HEX_KEY")]
    pub key: Option<String>,

    /// Strictly verify the RPG Maker fake header signature (errors out on mismatch)
    #[arg(long, default_value_t = false)]
    pub verify_header: bool,

    /// Verify that target directory is a valid RPG Maker project
    #[arg(long, default_value_t = false)]
    pub verify_project_dir: bool,

    /// Number of worker threads for parallel file processing (defaults to all logical CPU cores)
    #[arg(short = 'j', long, value_name = "THREADS")]
    pub threads: Option<usize>,

    /// Custom header length in bytes (default: 16)
    #[arg(long, default_value_t = 16)]
    pub header_len: usize,

    /// Do not overwrite existing destination files
    #[arg(long, default_value_t = false)]
    pub no_overwrite: bool,
}

#[derive(Debug, Args)]
pub struct RestoreArgs {
    /// Target path to project directory or encrypted PNG image
    #[arg(value_name = "TARGET_PATH")]
    pub input: PathBuf,

    /// Destination directory for restored files (defaults to 'output' directory)
    #[arg(short, long, value_name = "DIR")]
    pub output: Option<PathBuf>,

    /// Save restored files directly in-place beside original files
    #[arg(short = 'i', long)]
    pub in_place: bool,

    /// Number of worker threads for parallel processing
    #[arg(short = 'j', long, value_name = "THREADS")]
    pub threads: Option<usize>,

    /// Custom header length in bytes (default: 16)
    #[arg(long, default_value_t = 16)]
    pub header_len: usize,

    /// Do not overwrite existing destination files
    #[arg(long, default_value_t = false)]
    pub no_overwrite: bool,
}

#[derive(Debug, Args)]
pub struct DetectKeyArgs {
    /// Target path to project directory, System.json, or encrypted PNG image
    #[arg(value_name = "TARGET_PATH")]
    pub input: PathBuf,

    /// Force key derivation from an encrypted PNG file rather than System.json
    #[arg(long, default_value_t = false)]
    pub from_png: bool,

    /// Custom header length in bytes (default: 16)
    #[arg(long, default_value_t = 16)]
    pub header_len: usize,
}

#[derive(Debug, Args)]
pub struct EncryptArgs {
    /// Target path to project directory or unencrypted file
    #[arg(value_name = "TARGET_PATH")]
    pub input: PathBuf,

    /// Destination directory for encrypted files
    #[arg(short, long, value_name = "DIR")]
    pub output: Option<PathBuf>,

    /// Save encrypted files directly in-place
    #[arg(short = 'i', long)]
    pub in_place: bool,

    /// 32-character hexadecimal encryption key (auto-detected from System.json if omitted)
    #[arg(short = 'k', long, value_name = "HEX_KEY")]
    pub key: Option<String>,

    /// Encrypt using RPG Maker MZ format (.png_, .m4a_, .ogg_) instead of MV (.rpgmvp, etc.)
    #[arg(long, default_value_t = false)]
    pub mz: bool,

    /// Number of worker threads for parallel processing
    #[arg(short = 'j', long, value_name = "THREADS")]
    pub threads: Option<usize>,

    /// Custom header length in bytes (default: 16)
    #[arg(long, default_value_t = 16)]
    pub header_len: usize,

    /// Do not overwrite existing destination files
    #[arg(long, default_value_t = false)]
    pub no_overwrite: bool,
}
