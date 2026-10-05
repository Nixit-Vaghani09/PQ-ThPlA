use crate::channel::{ChannelContext, SecureMessage, ChannelError};
use crate::mlkem;
use zeroize::Zeroize;

pub struct SessionContext {
    channel: ChannelContext,
    session_id: u64,
}

impl SessionContext {
    pub fn new(initial_secret: &[u8], session_id: u64) -> Self {
        let mut ctx = ChannelContext::new(initial_secret);
        SessionContext {
            channel: ctx,
            session_id,
        }
    }

    pub fn send(&mut self, plaintext: &[u8]) -> Result<SecureMessage, ChannelError> {
        match self.channel.send_secure(plaintext) {
            Ok(msg) => Ok(msg),
            Err(ChannelError::KeyExpired) => {
                let (ciphertext, new_secret) = mlkem::encapsulate(&self.channel.public_key)
                    .map_err(|_| ChannelError::EncryptionFailed)?;
                let shared_secret = mlkem::decapsulate(&ciphertext, &self.channel.private_key)
                    .map_err(|_| ChannelError::DecryptionFailed)?;
                self.channel.rotate_keys(&shared_secret)?;
                self.channel.send_secure(plaintext)
            }
            Err(e) => Err(e),
        }
    }
    pub fn receive(&mut self, msg: &SecureMessage) -> Result<Vec<u8>, ChannelError> {
        self.channel.receive_secure(msg)
    }
    pub fn terminate(&mut self) {
        self.channel.key.zeroize();
        self.channel.counter = 0;
        self.channel.used_nonces.clear();
    }
}