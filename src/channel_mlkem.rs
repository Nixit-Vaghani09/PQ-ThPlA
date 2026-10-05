use zeroize :: Zeroize;
use sha2::{Sha256,Digest};
use aes_gcm ::aead::  Error;
use aes_gcm::aead::Error as AesError;
use std::collections::HashSet;
use crate::mlkem;
#[derive(Debug)]
pub enum ChannelError {
    EncryptionFailed(AesError),
    DecryptionFailed(AesError),
    NonceReuse,       
    KeyExpired,       
}

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


impl Channel_Context {
    fn new(key: [u8;32]) -> Self {
    Channel_Context { key, counter: 0 , used_Nonces: HashSet::new(),}
    }

    fn next_nonce(&mut self) -> Result<[u8;12],ChannelError> {
        if self.counter > 1_000_000 {
            return Err(ChannelError::KeyExpired);
        }
    let nonce = mlkem::generate_nonce(self.counter);
    self.counter+=1;
    if !self.used_Nonces.insert(nonce) {
        return Err(ChannelError::NonceReuse);
    }
    Ok(nonce)
    }

    fn send_secure(&mut self, plain_text: &[u8]) -> Result<message,ChannelError> {
    let nonce = self.next_nonce()?; // generate nonce
    let cipher_text=mlkem::aes_encrypt(&self.key, &nonce, plain_text).map_err(ChannelError::EncryptionFailed)?;
    Ok(message{ciphertext:cipher_text,nonce:nonce})
    }

    fn recieve_secure(&mut self,msg : &message) -> Result<Vec<u8>,ChannelError> {
    if self.used_Nonces.contains(&msg.nonce){
        return Err(ChannelError::NonceReuse);
    }
    self.used_Nonces.insert(msg.nonce);
    mlkem::aes_decrypt(&self.key, &msg.nonce, &msg.ciphertext).map_err(ChannelError::DecryptionFailed)
    }

    fn rotate_keys(&mut self,new_secret: &[u8]) -> Result<(),ChannelError>{
        self.key.zeroize();
        let hash = Sha256::digest(new_secret);
        let mut new_key = [0u8;32];
        
        new_key.copy_from_slice(&hash[..32]);
        self.key=new_key;
        self.counter.zeroize();
        self.counter=0;
        self.used_Nonces.clear();
        Ok(())
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
