

use libcrux_ml_kem::mlkem768::generate_key_pair;
use libcrux_ml_kem::mlkem768:: {encapsulate,decapsulate};
use libcrux_ml_kem::{MlKemCiphertext, MlKemKeyPair, MlKemPrivateKey, MlKemPublicKey, MlKemSharedSecret};
use rand::random;
use rand::{RngCore, rngs::OsRng};
use sha2::{Sha256,Digest};
use aes_gcm :: {Aes256Gcm, Key , Nonce};
use aes_gcm ::aead:: {Aead,KeyInit , Error};
use crate :: channel_mlkem :: ChannelError;


use aes_gcm::aead::Error as AesError;





//this is to generate the random seed and nonce
pub fn random_array<const L: usize>() -> [u8; L] {
    assert!(L>0 , "Array length must be Positive");
    let mut seed = [0u8; L];
    OsRng.fill_bytes(&mut seed);
    seed
}

pub fn generate_keypair() ->MlKemKeyPair<2400,1184> {
    let keys= generate_key_pair(random_array());

    
    keys
}
pub fn encapsulation(public_key: &MlKemPublicKey<1184>) -> Result<(MlKemCiphertext<1088>,MlKemSharedSecret),ChannelError> {
       
   
    let (cipher_text,shared_secret) = encapsulate(public_key,random_array());
    if shared_secret.len() != 32 {
        return Err(ChannelError::EncryptionFailed(
            aes_gcm::Error,
        ));    }
    
    Ok((cipher_text,shared_secret))
    
}

pub fn decapsulation(private_key: &MlKemPrivateKey<2400> , cipher_text:&MlKemCiphertext<1088> ) -> Result<(MlKemSharedSecret),ChannelError> {
    
    
    let (shared_secret) = decapsulate(private_key,cipher_text);
    if shared_secret.len() != 32 {
        return Err(ChannelError::DecryptionFailed(
            aes_gcm::Error,
        ));    }
    Ok(shared_secret)
}

fn derived_aes_key(shared_secret: &[u8]) -> [u8;32] {
    let hash = Sha256::digest(shared_secret);
    hash[..32].try_into().expect("Failed to derive AES key")
}

pub fn aes_encrypt(key_bytes: &[u8;32], nonce: &[u8;12], plaintext: &[u8]) -> Result<Vec<u8>,Error>{
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher:Aes256Gcm = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(nonce);
    cipher.encrypt(nonce, plaintext)
}

pub fn aes_decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>,Error> {
    let cipher: Aes256Gcm = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    cipher.decrypt(nonce, ciphertext)
}

pub fn generate_nonce(counter: u64) -> [u8;12]  {
    let mut nonce = [0u8;12];
    nonce[..8].copy_from_slice(&counter.to_le_bytes());
    rand::thread_rng().fill_bytes(&mut nonce[8..]);
    nonce
}



