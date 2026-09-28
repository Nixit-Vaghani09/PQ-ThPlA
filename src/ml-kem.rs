use libcrux_ml_kem::ml_kem_768::generate_key_pair;
use libcrux_ml_kem::ml_kem_768::encapsulate;
use rand::{RngCore, rngs::OsRng};

//this is to generate the random seed and nonce
fn random_array<L: usize>() -> [u8; L] {
    assert!(L>0 , "Array length must be Positive");
    let mut seed = [0u8; L];
    OsRng.fill_bytes(&mut seed);
    seed
}
fn encapsulation(public_key: &[u8]) -> Result<(Vec<u8>,Vec<u8>),String> {
    if public_key.len()!=1184 {
        return Err("public key length must be 1184 bytes".into());
    }
   
    let (cipher_text,shared_secret) = encapsulate(public_key,random_array());
    if shared_secret.len() != 32 {
        return Err("shared secret length must be 32 bytes".into());
    }
    if cipher_text.len() != 1088 {
        return Err("cipher_text length must be 1088 bytes".into());
    }
    Ok((cipher_text,shared_secret))
    
}

fn decapsulation(private_key: &[u8] , cipher_text: &[u8]) -> Result<(Vec<u8>),String> {
    if private_key.len() != 2400 {
        return Err("Private key must be 2400 bytes".into());
    }
    if cipher_text.len() != 1088 {
        return Err("cipher text must be 1088 bytes".into());
    }
    let (shared_secret) = decapsulate(private_key,cipher_text);
    if shared_secret.len() != 32 {
        return Err("Shared secret length must be 32 bytes".into());
    }
    Ok(shared_secret)
}

