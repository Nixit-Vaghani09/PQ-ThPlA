use pqcrypto_sphincsplus::sphincsshake128ssimple::DetachedSignature;

use crate::merkle_tree::tree::Hash;
use crate::merkle_tree::proof::MerkleProof;
use std::sync::Arc;

#[derive(Clone)]
pub struct AuthResponse {
    pub merkle_root:Hash,
    pub proof: MerkleProof,
    pub signature: Arc<DetachedSignature>,
}

