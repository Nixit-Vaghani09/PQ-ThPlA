use sha3::{Digest,Sha3_256};
#[derive(Clone,Debug)]
pub struct ServerShare {
     server_id: u32,
     share: Vec<u8>,
}


impl ServerShare {
    pub fn new(server_id: u32,share: Vec<u8>,) -> Self {
        Self {
            server_id,
            share,

        }
    }

    pub fn derive_nonce(&self,session_id: &str)->[u8;32]{
        let mut hasher = Sha3_256::new();
        hasher.update(&self.share,);
        hasher.update(session_id.as_bytes());
        hasher.finalize().into()
    }
}