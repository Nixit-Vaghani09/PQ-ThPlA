use crate::auth::auth_response::AuthResponse;
use crate::challenge::challenge::Challenge;
use crate::merkle_tree::proof::verify_proof;
use crate::slh_dsa::slhdsa::verify_message;
use pqcrypto_sphincsplus::sphincsshake128ssimple::PublicKey;

pub fn verify_auth_response(
    challenge: &Challenge,
    response: &AuthResponse,
    publicKey:&PublicKey,
) ->bool {
    let leaf = challenge.hash_challenge();
    let merkle_valid =verify_proof(leaf,&response.proof,response.merkle_root,);
    if !merkle_valid{
        return false;
    }
    let signature_valid=verify_message(&*response.signature, response.merkle_root.as_ref(), publicKey);
    if !signature_valid{
        return false;
    }
    return true;
}