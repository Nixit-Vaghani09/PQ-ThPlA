use crate::mlkem;
use aes_gcm::aead::Error as AesError;
use sha2::{Digest, Sha256};
use std::collections::HashSet;
use std::fmt;
use zeroize::Zeroize;

#[derive(Debug)]
pub enum ChannelError {
    EncryptionFailed(AesError),
    DecryptionFailed(AesError),
    NonceReuse,
    KeyExpired,
}

pub struct ChannelContext {
    key: [u8; 32],                // channel owns the AES key
    counter: u64,
    used_nonces: HashSet<[u8; 12]>,
}

#[derive(Debug, Clone)]
pub struct Message {
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl ChannelContext {
    /// Create a new channel context with ownership of the session key
    pub fn new(session_key: [u8; 32]) -> Self {
        ChannelContext {
            key: session_key,
            counter: 0,
            used_nonces: HashSet::new(),
        }
    }

    pub fn next_nonce(&mut self) -> Result<[u8; 12], ChannelError> {
        if self.counter > 1_000_000 {
            return Err(ChannelError::KeyExpired);
        }
        let nonce = mlkem::generate_nonce(self.counter);
        self.counter += 1;
        if !self.used_nonces.insert(nonce) {
            return Err(ChannelError::NonceReuse);
        }
        Ok(nonce)
    }

    pub fn send_secure(&mut self, plain_text: &[u8]) -> Result<Message, ChannelError> {
        let nonce = self.next_nonce()?; 
        let cipher_text = mlkem::aes_encrypt(&self.key, &nonce, plain_text)
            .map_err(ChannelError::EncryptionFailed)?;
        Ok(Message {
            ciphertext: cipher_text,
            nonce,
        })
    }

    pub fn receive_secure(&mut self, msg: &Message) -> Result<Vec<u8>, ChannelError> {
        if self.used_nonces.contains(&msg.nonce) {
            return Err(ChannelError::NonceReuse);
        }
        self.used_nonces.insert(msg.nonce);
        match mlkem::aes_decrypt(&self.key, &msg.nonce, &msg.ciphertext) {
            Ok(plaintext) => Ok(plaintext),
            Err(e) => Err(ChannelError::DecryptionFailed(e)),
        }
    }

    /// Rotate the key using a mutable reference to the new secret
    pub fn rotate_key(&mut self, new_secret: &mut [u8]) -> Result<(), ChannelError> {
        let mut new_key: [u8; 32] = Sha256::digest(&*new_secret).into();
        self.key.zeroize();
        self.key.copy_from_slice(&new_key);
        new_key.zeroize();
        new_secret.zeroize(); // wipe caller’s buffer
        self.counter = 0;
        self.used_nonces.clear();
        Ok(())
    }
}

impl fmt::Display for ChannelError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ChannelError::EncryptionFailed(e) => write!(f, "Encryption failed: {}", e),
            ChannelError::DecryptionFailed(e) => write!(f, "Decryption failed: {}", e),
            ChannelError::NonceReuse => write!(f, "Nonce reuse detected"),
            ChannelError::KeyExpired => write!(f, "Key expired"),
        }
    }
}

impl Drop for ChannelContext {
    fn drop(&mut self) {
        self.key.zeroize();       // wipe AES key
        self.counter.zeroize();
        self.used_nonces.clear();
    }
}

impl Drop for Message {
    fn drop(&mut self) {
        self.ciphertext.zeroize();
        self.nonce.zeroize();
    }
}
