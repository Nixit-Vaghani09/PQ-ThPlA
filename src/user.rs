// auth/authentication.rs

use std::collections::HashMap;
use std::sync::Arc;
use pqcrypto_sphincsplus::sphincsshake128ssimple::{
    DetachedSignature,
    SecretKey,
};

use crate::auth::auth_response::AuthResponse;
use crate::challenge::challenge::Challenge;
use crate::merkle_tree::tree::{MerkleTree,Hash};
use crate::slh_dsa::slhdsa::sign_message;

pub fn authenticate(
    challenges: Vec<Challenge>,
    secret_key: &SecretKey,
) -> Result<HashMap<u32, AuthResponse>, String>
{
    if challenges.is_empty() {
        return Err(
            "No challenges supplied"
                .to_string(),
        );
    }

    /*
        Build Merkle tree
    */
    let leaves: Vec<(u32, Hash)> =
    challenges
        .iter()
        .map(|challenge| {
            (
                challenge.server_id,
                challenge.hash_challenge(),
            )
        })
        .collect();

    let tree =
        MerkleTree::new(
            leaves,
        );

    let root =
        tree.root();

    /*
        Sign root once
    */

    let signature: DetachedSignature =
        sign_message(
            root.as_ref(),
            secret_key,
        );
    let signature =Arc::new(signature);
    /*
        Generate one response
        per server
    */

    let mut responses =
        HashMap::new();

    for challenge in &challenges {

        let proof =
            tree.generate_proof(
                challenge.server_id,
            )
            .ok_or_else(
                || {
                    format!(
                        "Proof generation failed for server {}",
                        challenge.server_id
                    )
                },
            )?;

        let response =
            AuthResponse {

                merkle_root:
                    root,

                proof,
                signature:
                    Arc::clone(&signature),
            };

        responses.insert(
            challenge.server_id,
            response,
        );
    }

    Ok(
        responses,
    )
}