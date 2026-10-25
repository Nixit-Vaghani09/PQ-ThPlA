use crate::merkle_tree::tree::Hash;
use crate::merkle_tree::proof::MerkleProof;
use std::sync::Arc;

#[derive(Clone,Debug)]
pub struct AuthResponse {
    pub merkle_root:Hash,
    pub roof: MerkleProof,
    pub signature: Arc<Vec<u8>>,
}

