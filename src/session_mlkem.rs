use core::slice;

use crate::channel_mlkem::{Channel_Context, message, ChannelError};
use crate::mlkem;
use zeroize::Zeroize;
use libcrux_ml_kem::mlkem768::{generate_key_pair };
use std::fmt;
pub struct SessionContext {
    channel: Channel_Context,
    session_id: u64,
}

impl SessionContext {
    pub fn new(initial_secret: &[u8], session_id: u64) -> Self {
        let key: [u8;32] =initial_secret.try_into().expect("slice must be 32 bytes"); 
        let mut ctx = Channel_Context::new(key);
        SessionContext {
            channel: ctx,
            session_id,
        }
    }

    pub fn send(&mut self, plaintext: &[u8]) -> Result<message, String> {
    match self.channel.send_secure(plaintext) {
        Ok(msg) => Ok(msg),
        Err(e) => {
            if e.to_string() == "KeyExpired" {
                let keys = generate_key_pair(mlkem::random_array());

                let (ciphertext, new_secret) = mlkem::encapsulation(keys.public_key())?;

                let shared_secret = mlkem::decapsulation(keys.private_key(), &ciphertext)?;

                self.channel.rotate_keys(&shared_secret)
                    .map_err(|err| err.to_string())?;

                self.channel.send_secure(plaintext)
                    .map_err(|err| err.to_string())
            } else {
                Err(e.to_string())
            }
        }
    }
}


    pub fn receive(&mut self, msg: &message) -> Result<Vec<u8>, ChannelError> {
        self.channel.receive_secure(msg)
    }
    
}