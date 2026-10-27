use crate::challenge::challenge::Challenge;
use crate::merkle_tree::proof::verify_proof;
use crate::registration::registration_response::RegistrationResponse;

use pqcrypto_sphincsplus::sphincsshake128ssimple::verify_detached_signature;

pub fn verify_registration_response(
    challenge: &Challenge,
    response: &RegistrationResponse,
) -> bool {
    let leaf = challenge.hash_challenge();

    let merkle_valid = verify_proof(leaf, &response.proof, response.merkle_root);

    println!(
        "[DEBUG] Server {} Merkle Valid = {}",
        challenge.server_id, merkle_valid,
    );

    if !merkle_valid {
        return false;
    }

    let signature_valid = verify_detached_signature(
        &*response.registration_signature,
        response.merkle_root.as_ref(),
        &*response.public_key,
    )
    .is_ok();

    println!(
        "[DEBUG] Server {} Signature Valid = {}",
        challenge.server_id, signature_valid,
    );

    if !signature_valid {
        return false;
    }

    true
}
