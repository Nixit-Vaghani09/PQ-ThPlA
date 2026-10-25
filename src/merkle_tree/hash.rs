use sha3::{Digest,Sha3_256};
type Hash = [u8;32]; 
pub fn hash_pair(first:&Hash,second:&Hash) -> Hash
{
    let mut hasher = Sha3_256::new();
    hasher.update(first);
    hasher.update(second);
    hasher.finalize().into()
}

pub fn sha3_hash(data: &[u8]) -> Vec<u8>{
    let mut hasher = Sha3_256::new();
    hasher.update(data);
    hasher.finalize().to_vec()
}

#[derive(Clone)]
pub struct ChallengeLeaf {
    pub server_id: u32,
    pub session_id: String,
    pub nonce: Vec<u8>,
    pub timestamp: u64,
}

impl ChallengeLeaf{
    pub fn hash(&self) -> Vec<u8> {
        let mut data=Vec::new();
        data.extend(self.server_id.to_be_bytes());
        data.extend(self.session_id.as_bytes());
        data.extend(&self.nonce);
        data.extend(self.timestamp.to_be_bytes());

        sha3_hash(&data)
    }
}