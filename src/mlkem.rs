use std::collections::HashSet;

use libcrux_ml_kem::mlkem768::generate_key_pair;
use libcrux_ml_kem::mlkem768:: {encapsulate,decapsulate};
use libcrux_ml_kem::{MlKemPublicKey,MlKemPrivateKey,MlKemSharedSecret,MlKemCiphertext};
use rand::{RngCore, rngs::OsRng};
use sha2::{Sha256,Digest};
use aes_gcm :: {Aes256Gcm, Key , Nonce};
use aes_gcm ::aead:: {Aead,KeyInit , Error};
use zeroize :: Zeroize;

use aes_gcm::aead::Error as AesError;

struct Channel_Context{
    key:[u8;32],
    counter: u64,
    used_Nonces: HashSet<[u8;12]>,
}

#[derive(Debug, Clone)]
struct message {
    pub nonce: [u8;12],
    pub ciphertext: Vec<u8>,
}

#[derive(Debug)]
pub enum ChannelError {
    EncryptionFailed(AesError),
    DecryptionFailed(AesError),
    NonceReuse,       
    KeyExpired,       
}

impl Channel_Context {
    fn new(key: [u8;32]) -> Self {
    Channel_Context { key, counter: 0 , used_Nonces: HashSet::new(),}
    }

    fn next_nonce(&mut self) -> Result<[u8;12],ChannelError> {
        if self.counter > 1_000_000 {
            return Err(ChannelError::KeyExpired);
        }
    let nonce = generate_nonce(self.counter);
    self.counter+=1;
    if !self.used_Nonces.insert(nonce) {
        return Err(ChannelError::NonceReuse);
    }
    Ok(nonce)
    }

    fn send_secure(&mut self, plain_text: &[u8]) -> Result<message,ChannelError> {
    let nonce = self.next_nonce()?; // generate nonce
    let cipher_text=aes_encrypt(&self.key, &nonce, plain_text).map_err(ChannelError::EncryptionFailed)?;
    Ok(message{ciphertext:cipher_text,nonce:nonce})
    }

    fn recieve_secure(&mut self,msg : &message) -> Result<Vec<u8>,ChannelError> {
    if self.used_Nonces.contains(&msg.nonce){
        return Err(ChannelError::NonceReuse);
    }
    self.used_Nonces.insert(msg.nonce);
    aes_decrypt(&self.key, &msg.nonce, &msg.ciphertext).map_err(ChannelError::DecryptionFailed)
    }

}

impl Drop for Channel_Context {
    fn drop(&mut self) {
        self.key.zeroize();
        self.counter.zeroize();
        self.used_Nonces.clear();
    }
}

impl Drop for message {
    fn drop(&mut self) {
        self.ciphertext.zeroize();
        self.nonce.zeroize();
    }
}

//this is to generate the random seed and nonce
pub fn random_array<const L: usize>() -> [u8; L] {
    assert!(L>0 , "Array length must be Positive");
    let mut seed = [0u8; L];
    OsRng.fill_bytes(&mut seed);
    seed
}
pub fn encapsulation(public_key: &MlKemPublicKey<1184>) -> Result<(MlKemCiphertext<1088>,MlKemSharedSecret),String> {
       
   
    let (cipher_text,shared_secret) = encapsulate(public_key,random_array());
    if shared_secret.len() != 32 {
        return Err("shared secret length must be 32 bytes".into());
    }
    
    Ok((cipher_text,shared_secret))
    
}

pub fn decapsulation(private_key: &MlKemPrivateKey<2400> , cipher_text:&MlKemCiphertext<1088> ) -> Result<(MlKemSharedSecret),String> {
    
    
    let (shared_secret) = decapsulate(private_key,cipher_text);
    if shared_secret.len() != 32 {
        return Err("Shared secret length must be 32 bytes".into());
    }
    Ok(shared_secret)
}

fn derived_aes_key(shared_secret: &[u8]) -> [u8;32] {
    let hash = Sha256::digest(shared_secret);
    hash[..32].try_into().expect("Failed to derive AES key")
}

fn aes_encrypt(key_bytes: &[u8;32], nonce: &[u8;12], plaintext: &[u8]) -> Result<Vec<u8>,Error>{
    let key = Key::<Aes256Gcm>::from_slice(key_bytes);
    let cipher:Aes256Gcm = Aes256Gcm::new(&key);
    let nonce = Nonce::from_slice(nonce);
    cipher.encrypt(nonce, plaintext)
}

fn aes_decrypt(key: &[u8; 32], nonce: &[u8; 12], ciphertext: &[u8]) -> Result<Vec<u8>,Error> {
    let cipher: Aes256Gcm = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    let nonce = Nonce::from_slice(nonce);
    cipher.decrypt(nonce, ciphertext)
}

fn generate_nonce(counter: u64) -> [u8;12]  {
    let mut nonce = [0u8;12];
    nonce[..8].copy_from_slice(&counter.to_le_bytes());
    rand::thread_rng().fill_bytes(&mut nonce[8..]);
    nonce
}



