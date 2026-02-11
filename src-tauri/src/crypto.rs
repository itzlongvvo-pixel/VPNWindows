/*
  Nera VPN™ - Anonymous Blind Token Cryptography
  Copyright © 2025 Vio Holdings LLC. All rights reserved.
  
  This module implements RSA blind signatures for anonymous authentication.
  The blinding factor never leaves Rust memory, ensuring payment identity
  (Subscription Code) is mathematically separated from connection identity
  (Access Token).
*/

use base64::{engine::general_purpose, Engine as _};
use num_bigint::{BigUint, RandBigInt};
use rand::rngs::OsRng;
use rsa::{pkcs8::DecodePublicKey, traits::PublicKeyParts, RsaPublicKey};
use sha2::{Digest, Sha256};
use std::sync::Mutex;

// API endpoint for fetching server's RSA public key
const API_PUBLIC_KEY_URL: &str = "http://45.76.106.63:3000/api/public-key";

// Cached server public key (fetched on first use)
lazy_static::lazy_static! {
    static ref SERVER_PUBLIC_KEY_CACHE: Mutex<Option<String>> = Mutex::new(None);
}

// Thread-safe storage for blinding factor during the auth flow
lazy_static::lazy_static! {
    static ref BLINDING_FACTOR: Mutex<Option<BlindingState>> = Mutex::new(None);
}

struct BlindingState {
    factor: BigUint,
    original_token: Vec<u8>,
}

/// Fetches and caches the server's RSA public key
fn get_server_public_key() -> Result<String, String> {
    // Check cache first
    {
        let cache = SERVER_PUBLIC_KEY_CACHE.lock().map_err(|e| e.to_string())?;
        if let Some(key) = cache.as_ref() {
            return Ok(key.clone());
        }
    }
    
    // Fetch from server
    let response = reqwest::blocking::get(API_PUBLIC_KEY_URL)
        .map_err(|e| format!("Failed to fetch public key: {}", e))?;
    
    let pem = response.text()
        .map_err(|e| format!("Failed to read public key response: {}", e))?;
    
    // Validate it's a valid PEM
    if !pem.contains("-----BEGIN PUBLIC KEY-----") {
        return Err("Invalid public key format received from server".to_string());
    }
    
    // Cache the key
    {
        let mut cache = SERVER_PUBLIC_KEY_CACHE.lock().map_err(|e| e.to_string())?;
        *cache = Some(pem.clone());
    }
    
    Ok(pem)
}

/// Creates a blinded token for anonymous authentication.
/// 
/// Returns a JSON object with:
/// - blinded_token: Base64-encoded blinded message to send to server
/// - token_id: Unique identifier to reference this blinding session
/// 
/// The blinding factor is stored in Rust memory and never exposed to JS.
#[tauri::command]
pub fn create_blind_token() -> Result<serde_json::Value, String> {
    let mut rng = OsRng;
    
    // 1. Fetch and parse the server's public key (cached after first call)
    let pem = get_server_public_key()?;
    let public_key = RsaPublicKey::from_public_key_pem(&pem)
        .map_err(|e| format!("Failed to parse server public key: {}", e))?;
    
    // 2. Generate a random 256-bit token (32 bytes)
    let token: Vec<u8> = (0..32).map(|_| rand::random::<u8>()).collect();
    
    // 3. Hash the token to get the message to blind
    let mut hasher = Sha256::new();
    hasher.update(&token);
    let hashed = hasher.finalize();
    let message = BigUint::from_bytes_be(&hashed);
    
    // 4. Get RSA modulus (n) and exponent (e)
    let n = BigUint::from_bytes_be(&public_key.n().to_bytes_be());
    let e = BigUint::from_bytes_be(&public_key.e().to_bytes_be());
    
    // 5. Generate random blinding factor r (must be coprime with n)
    let r = rng.gen_biguint_below(&n);
    
    // 6. Compute blinded message: blinded = message * r^e mod n
    let r_e = r.modpow(&e, &n);
    let blinded = (&message * &r_e) % &n;
    
    // 7. Store blinding factor and original token in memory
    {
        let mut state = BLINDING_FACTOR.lock().map_err(|e| e.to_string())?;
        *state = Some(BlindingState {
            factor: r,
            original_token: token,
        });
    }
    
    // 8. Return the blinded token as base64
    let blinded_bytes = blinded.to_bytes_be();
    let blinded_b64 = general_purpose::STANDARD.encode(&blinded_bytes);
    
    Ok(serde_json::json!({
        "blinded_token": blinded_b64
    }))
}

/// Unblinds the server's signature to produce the final access token.
/// 
/// Takes the base64-encoded signed blinded token from the server.
/// Uses the stored blinding factor to unblind and produce the final token.
/// 
/// Returns the final access_token as a base64 string.
#[tauri::command]
pub fn unblind_signature(signed_blinded: String) -> Result<String, String> {
    // 1. Fetch and parse the server's public key to get n
    let pem = get_server_public_key()?;
    let public_key = RsaPublicKey::from_public_key_pem(&pem)
        .map_err(|e| format!("Failed to parse server public key: {}", e))?;
    let n = BigUint::from_bytes_be(&public_key.n().to_bytes_be());
    
    // 2. Decode the signed blinded token
    let signed_bytes = general_purpose::STANDARD
        .decode(&signed_blinded)
        .map_err(|e| format!("Failed to decode signed token: {}", e))?;
    let signed = BigUint::from_bytes_be(&signed_bytes);
    
    // 3. Retrieve and consume the blinding factor
    let state = {
        let mut guard = BLINDING_FACTOR.lock().map_err(|e| e.to_string())?;
        guard.take().ok_or("No blinding factor found. Call create_blind_token first.")?
    };
    
    // 4. Compute r^(-1) mod n (modular inverse)
    let r_inv = mod_inverse(&state.factor, &n)
        .ok_or("Failed to compute modular inverse of blinding factor")?;
    
    // 5. Unblind: signature = signed * r^(-1) mod n
    let signature = (&signed * &r_inv) % &n;
    
    // 6. Combine original token with signature to create access token
    // Format: base64(token || signature)
    let sig_bytes = signature.to_bytes_be();
    let mut access_token_data = state.original_token.clone();
    access_token_data.extend(&sig_bytes);
    
    let access_token = general_purpose::STANDARD.encode(&access_token_data);
    
    Ok(access_token)
}

/// Computes the modular multiplicative inverse using extended Euclidean algorithm.
fn mod_inverse(a: &BigUint, n: &BigUint) -> Option<BigUint> {
    use num_bigint::BigInt;
    use num_traits::{One, Zero};
    
    let a = BigInt::from(a.clone());
    let n = BigInt::from(n.clone());
    
    let mut t = BigInt::zero();
    let mut newt = BigInt::one();
    let mut r = n.clone();
    let mut newr = a;
    
    while !newr.is_zero() {
        let quotient = &r / &newr;
        
        let temp_t = t.clone();
        t = newt.clone();
        newt = temp_t - &quotient * &newt;
        
        let temp_r = r.clone();
        r = newr.clone();
        newr = temp_r - &quotient * &newr;
    }
    
    if r > BigInt::one() {
        return None; // a is not invertible
    }
    
    if t < BigInt::zero() {
        t = t + &n;
    }
    
    Some(t.to_biguint().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_blind_token_creation() {
        let result = create_blind_token();
        assert!(result.is_ok());
        
        let json = result.unwrap();
        assert!(json.get("blinded_token").is_some());
    }
}
