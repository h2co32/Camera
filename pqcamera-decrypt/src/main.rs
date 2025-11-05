use anyhow::{Context, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
use chacha20poly1305::{
    aead::{Aead, KeyInit},
    ChaCha20Poly1305,
};
use clap::Parser;
use hkdf::Hkdf;
use pqc_kyber::{Keypair, KEM_CIPHERTEXT_BYTES, KYBER_SECRET_KEY_BYTES, SECRET_KEY_BYTES};
use sha2::Sha256;
use std::fs;
use std::io::{Read, Write};
use std::path::PathBuf;

const MAGIC: &[u8] = b"PQCAMENC";
const VERSION: u32 = 1;
const NONCE_SIZE: usize = 12;
const HKDF_INFO: &[u8] = b"GrapheneOS Camera PQC Photo Encryption v1";

/// Post-Quantum Camera Photo Decryption Utility
///
/// Decrypts photos encrypted with ML-KEM-768 (Kyber768) by the GrapheneOS Camera app.
#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Args {
    /// Path to the encrypted photo file (.pqcenc)
    #[arg(short, long)]
    input: PathBuf,

    /// Path to the private key file (PEM format)
    #[arg(short = 'k', long)]
    private_key: PathBuf,

    /// Output path for decrypted JPEG (optional, defaults to input filename with .jpg)
    #[arg(short, long)]
    output: Option<PathBuf>,
}

fn main() -> Result<()> {
    let args = Args::parse();

    println!("PQCamera Decrypt - Post-Quantum Photo Decryption Utility");
    println!("=========================================================\n");

    // Load private key
    println!("[1/4] Loading private key from: {}", args.private_key.display());
    let private_key = load_private_key(&args.private_key)
        .context("Failed to load private key")?;

    // Load encrypted file
    println!("[2/4] Loading encrypted photo from: {}", args.input.display());
    let encrypted_data = fs::read(&args.input)
        .context("Failed to read encrypted file")?;

    // Decrypt photo
    println!("[3/4] Decrypting photo with ML-KEM-768...");
    let decrypted_jpeg = decrypt_photo(&encrypted_data, &private_key)
        .context("Failed to decrypt photo")?;

    // Save decrypted photo
    let output_path = args.output.unwrap_or_else(|| {
        let mut path = args.input.clone();
        path.set_extension("jpg");
        path
    });

    println!("[4/4] Saving decrypted photo to: {}", output_path.display());
    fs::write(&output_path, &decrypted_jpeg)
        .context("Failed to write decrypted file")?;

    println!("\n✓ Successfully decrypted photo!");
    println!("  Original size: {} bytes", encrypted_data.len());
    println!("  Decrypted size: {} bytes", decrypted_jpeg.len());
    println!("  Output: {}", output_path.display());

    Ok(())
}

/// Load and parse ML-KEM-768 private key from PEM format
fn load_private_key(path: &PathBuf) -> Result<[u8; KYBER_SECRET_KEY_BYTES]> {
    let pem_content = fs::read_to_string(path)?;

    // Remove PEM headers and whitespace
    let cleaned = pem_content
        .lines()
        .filter(|line| !line.contains("-----BEGIN") && !line.contains("-----END"))
        .collect::<String>();

    // Decode base64
    let decoded = BASE64.decode(cleaned.trim())
        .context("Invalid base64 in private key file")?;

    // Verify key size
    if decoded.len() != KYBER_SECRET_KEY_BYTES {
        anyhow::bail!(
            "Invalid private key size: expected {} bytes, got {}",
            KYBER_SECRET_KEY_BYTES,
            decoded.len()
        );
    }

    let mut key = [0u8; KYBER_SECRET_KEY_BYTES];
    key.copy_from_slice(&decoded);
    Ok(key)
}

/// Decrypt photo using ML-KEM-768 + ChaCha20-Poly1305
fn decrypt_photo(encrypted_data: &[u8], private_key: &[u8; KYBER_SECRET_KEY_BYTES]) -> Result<Vec<u8>> {
    let mut offset = 0;

    // 1. Verify magic header
    if encrypted_data.len() < 8 {
        anyhow::bail!("File too small to be a valid encrypted photo");
    }
    let magic = &encrypted_data[offset..offset + 8];
    offset += 8;

    if magic != MAGIC {
        anyhow::bail!("Invalid file format: missing magic header");
    }

    // 2. Read version
    if encrypted_data.len() < offset + 4 {
        anyhow::bail!("File truncated: missing version");
    }
    let version = u32::from_le_bytes([
        encrypted_data[offset],
        encrypted_data[offset + 1],
        encrypted_data[offset + 2],
        encrypted_data[offset + 3],
    ]);
    offset += 4;

    if version != VERSION {
        anyhow::bail!("Unsupported file version: {}", version);
    }

    // 3. Read KEM ciphertext length
    if encrypted_data.len() < offset + 4 {
        anyhow::bail!("File truncated: missing ciphertext length");
    }
    let kem_ciphertext_len = u32::from_le_bytes([
        encrypted_data[offset],
        encrypted_data[offset + 1],
        encrypted_data[offset + 2],
        encrypted_data[offset + 3],
    ]) as usize;
    offset += 4;

    // 4. Read KEM ciphertext
    if encrypted_data.len() < offset + kem_ciphertext_len {
        anyhow::bail!("File truncated: missing KEM ciphertext");
    }
    let kem_ciphertext = &encrypted_data[offset..offset + kem_ciphertext_len];
    offset += kem_ciphertext_len;

    // 5. Read nonce
    if encrypted_data.len() < offset + NONCE_SIZE {
        anyhow::bail!("File truncated: missing nonce");
    }
    let nonce = &encrypted_data[offset..offset + NONCE_SIZE];
    offset += NONCE_SIZE;

    // 6. Read encrypted JPEG data
    if encrypted_data.len() < offset {
        anyhow::bail!("File truncated: missing encrypted data");
    }
    let encrypted_jpeg = &encrypted_data[offset..];

    // 7. Perform ML-KEM decapsulation
    println!("   → Decapsulating shared secret with ML-KEM-768...");

    // Convert private key to Keypair structure (we need the public key too for pqc_kyber)
    // Since we only have the secret key, we'll use the decapsulation directly
    let mut kem_ct = [0u8; KEM_CIPHERTEXT_BYTES];
    if kem_ciphertext.len() != KEM_CIPHERTEXT_BYTES {
        anyhow::bail!("Invalid KEM ciphertext size");
    }
    kem_ct.copy_from_slice(kem_ciphertext);

    // Decapsulate to get shared secret
    let mut secret_key_array = [0u8; KYBER_SECRET_KEY_BYTES];
    secret_key_array.copy_from_slice(private_key);

    let shared_secret = pqc_kyber::decapsulate(&kem_ct, &secret_key_array)
        .map_err(|_| anyhow::anyhow!("KEM decapsulation failed"))?;

    // 8. Derive symmetric key using HKDF-SHA256
    println!("   → Deriving symmetric key with HKDF-SHA256...");
    let hkdf = Hkdf::<Sha256>::new(None, &shared_secret);
    let mut symmetric_key = [0u8; 32];
    hkdf.expand(HKDF_INFO, &mut symmetric_key)
        .context("HKDF expansion failed")?;

    // 9. Decrypt with ChaCha20-Poly1305
    println!("   → Decrypting photo with ChaCha20-Poly1305...");
    let cipher = ChaCha20Poly1305::new(&symmetric_key.into());
    let decrypted = cipher
        .decrypt(nonce.into(), encrypted_jpeg)
        .map_err(|_| anyhow::anyhow!("Decryption failed: authentication tag mismatch or corrupted data"))?;

    Ok(decrypted)
}
