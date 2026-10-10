use crate::channel_mlkem::{ChannelContext, ChannelError, Message};

pub struct SessionContext {
    channel: ChannelContext,  // channel owns the AES key
    session_id: u64,
}

impl SessionContext {
    /// Create a new session with ownership of the session key
    pub fn new(session_key: [u8; 32], session_id: u64) -> Self {
        let ctx = ChannelContext::new(session_key);
        SessionContext {
            channel: ctx,
            session_id,
        }
    }

    /// Send a plaintext message securely
    pub fn send(&mut self, plaintext: &[u8]) -> Result<Message, ChannelError> {
        self.channel.send_secure(plaintext)
    }

    /// Receive and decrypt a message
    pub fn receive(&mut self, msg: &Message) -> Result<Vec<u8>, ChannelError> {
        self.channel.receive_secure(msg)
    }

    /// Rotate the session key using a mutable reference to the new secret
    pub fn rotate_key(&mut self, new_secret: &mut [u8]) -> Result<(), ChannelError> {
        self.channel.rotate_key(new_secret)
    }
}
