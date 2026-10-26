use crate::challenge::challenge::Challenge;
use crate::merkle_tree::proof::verify_proof;
use pqcrypto_sphincsplus::sphincsshake128ssimple::verify_detached_signature;
use crate::registration::registration_response::RegistrationResponse;
pub fn verify_registration_response(challenge: &Challenge,response: &RegistrationResponse,) -> bool {
    let leaf = challenge.hash_challenge();
    let merkle_valid = verify_proof(leaf,&response.proof,response.merkle_root,);
    if !merkle_valid {
        return false;
    }

    let signature_valid = verify_detached_signature(&*response.registration_signature,
    response.merkle_root.as_ref(),&*response.public_key).is_ok();

    signature_valid
}