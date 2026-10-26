use crate::merkle_tree::tree::Hash;
use sha3::{Digest,Sha3_256};
use libcrux_ml_kem:: MlKemCiphertext;
#[derive(Clone,Debug)]
pub struct Challenge {
    pub server_id: u32,
    pub session_id: String,
    pub nonce: [u8;32],
}

pub struct EncryptedChallenge {
    pub kem_ciphertext: MlKemCiphertext<1088>,
    pub aes_nonce: [u8;12],
    pub encrypted_payload: Vec<u8>,
}

impl Challenge {
    pub fn new(server_id: u32,session_id: String,nonce: [u8;32]) ->Self {
        Self {
            server_id,
            session_id,
            nonce,
        }
    }
    
    pub fn hash_challenge(&self) -> Hash {
        let mut hasher = Sha3_256::new();
        hasher.update(self.server_id.to_be_bytes());
        hasher.update(self.session_id.as_bytes());
        hasher.update(self.nonce);
        hasher.finalize().into()
    }
}