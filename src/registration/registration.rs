use crate::{merkle_tree::tree::MerkleTree, registration::registration_response::RegistrationResponse};
use pqcrypto_sphincsplus::sphincsshake128ssimple::{PublicKey,DetachedSignature};
use std::sync::Arc;
use std::collections::HashMap;
pub fn generate_registration_responses(
    tree: &MerkleTree,
    public_key: PublicKey,
    signature: DetachedSignature,

) -> HashMap<u32,RegistrationResponse>
{
    let mut responses = HashMap::new();
    let root= tree.root();
    let signature = Arc::new(signature);
    let public_key = Arc::new(public_key);

    for server_id in tree.server_positions.keys()
    {
        let proof = tree.generate_proof(*server_id).unwrap();
        responses.insert(*server_id,
        RegistrationResponse {
            merkle_root: root,
            proof,
            public_key: Arc::clone(&public_key),
            registration_signature: Arc::clone(&signature),

        });
    }
    responses
}