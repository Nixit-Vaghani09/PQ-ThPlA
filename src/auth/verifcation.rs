use crate::auth::auth_response::AuthResponse;
use crate::challenge;
use crate::challenge::challenge::Challenge;
use crate::merkle_tree::proof::verify_proof;

pub fn verify_auth_response(
    challenge: &Challenge,
    response: &AuthResponse
) ->bool {
    let leaf = challenge.hash_challenge();
    let merkle_valid =verify_proof(leaf,&response.proof,response.merkle_root,);
    if !merkle_valid{
        return false;
    }
    true
}