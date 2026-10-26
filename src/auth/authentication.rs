use pqcrypto_sphincsplus::sphincsshake128ssimple::DetachedSignature;

use crate::merkle_tree::tree::{MerkleTree};
use crate::auth::auth_response::AuthResponse;
use std::sync::Arc;
use std::collections::HashMap;

pub fn generate_auth_responses(tree: &MerkleTree,signature:DetachedSignature ) -> HashMap<u32,AuthResponse>
{
    let mut responses = HashMap::new();
    
    let root = tree.root();
    let signature = Arc::new(signature);
    for  server_id in tree.server_positions.keys()
    {
        let proof = tree.generate_proof(*server_id).unwrap();
        responses.insert(*server_id,
        AuthResponse{
            merkle_root:root,
            proof,
            signature:Arc::clone(&signature)
        });
    }
    responses
}

