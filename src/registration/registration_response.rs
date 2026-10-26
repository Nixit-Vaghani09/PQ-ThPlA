use crate::merkle_tree::proof::MerkleProof;
use crate::merkle_tree::tree::Hash;
use std::sync::Arc;
use pqcrypto_sphincsplus::sphincsshake128ssimple::{PublicKey,DetachedSignature};

#[derive(Clone)]
pub struct RegistrationResponse {
    pub merkle_root: Hash,
    pub proof: MerkleProof,
    pub public_key: Arc<PublicKey>,
    pub registration_signature: Arc<DetachedSignature>,
}

