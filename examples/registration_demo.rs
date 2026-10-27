// examples/registration_demo.rs
use pq_thpla::challenge::challenge::Challenge;
use pq_thpla::merkle_tree::tree::{Hash, MerkleTree};
use pq_thpla::registration::registration::generate_registration_responses;
use pq_thpla::registration::registration_request::RegistrationRequest;
use pq_thpla::registration::verification::verify_registration_response;
use pq_thpla::server::credential::StoredCredential;
use pq_thpla::server::server::{Server, VerificationPolicy};
use pq_thpla::slh_dsa::slhdsa::{generate_keys, sign_message};
use pq_thpla::threshold::shamir_setup::generate_server_shares;
use std::time::Instant;

pub fn run_registration_demo() {
    println!("\n=== PQ-ThPlA Registration Demo ===");

    // Create threshold servers

    let start = Instant::now();
    let secret = b"pq-thpla-demo-secret";

    let shares = generate_server_shares(secret, 3, 3);

    let mut servers: Vec<Server> = shares
        .into_iter()
        .enumerate()
        .map(|(i, share)| Server::new((i + 1) as u32, share))
        .collect();

    println!("[+] Created {} servers", servers.len(),);

    println!("[Time] taken for server to created: {:?}", start.elapsed());

    // Generate token credentials

    let (public_key, secret_key) = generate_keys();

    println!("[+] SLH-DSA keypair generated",);

    // Registration Request
    let start = Instant::now();
    let registration_request = RegistrationRequest {
        user_id: "alice".to_string(),

        session_id: "registration-demo".to_string(),

        registration_nonce: [7u8; 32],
    };

    println!("[+] RegistrationRequest sent",);
    println!(
        "[Time] taken for user to send a registration request: {:?}",
        start.elapsed()
    );

    // Collect challenges
    let start = Instant::now();

    let mut challenges: Vec<Challenge> = Vec::new();

    for server in &servers {
        let challenge = server
            .handle_registration_request(registration_request.clone())
            .expect("challenge generation failed");

        challenges.push(challenge);
    }

    println!("[+] {} registration challenges received", challenges.len(),);
    println!(
        "[Time] for the server to create and send challenges: {:?}",
        start.elapsed()
    );
    // Build Merkle Tree
    let start = Instant::now();
    let leaves: Vec<(u32, Hash)> = challenges
        .iter()
        .map(|challenge| (challenge.server_id, challenge.hash_challenge()))
        .collect();

    let tree = MerkleTree::new(leaves);

    println!(
        "[Time] taken for user to make the merkle tree: {:?}",
        start.elapsed()
    );

    // Sign Merkle Root
    let start = Instant::now();
    let signature = sign_message(tree.root().as_ref(), &secret_key);

    // Generate registration responses

    let responses = generate_registration_responses(&tree, public_key, signature);

    println!("[+] Registration responses generated",);

    println!(
        "[Time] taken for the token to sign message and generate registration responses: {:?}",
        start.elapsed()
    );

    // Verify responses on every server
    let start = Instant::now();
    let mut successful = 0;

    for (challenge, server) in challenges.iter().zip(servers.iter_mut()) {
        let response = responses.get(&challenge.server_id).unwrap();

        let valid = verify_registration_response(challenge, response);

        println!("Server {} verification = {}", challenge.server_id, valid,);

        if valid {
            successful += 1;

            let credential = StoredCredential {
                user_id: registration_request.user_id.clone(),

                public_key: (*response.public_key).clone(),
            };

            server.credential_store_mut().insert(credential);
        }
    }
    println!(
        "[Time] taken for server to verify the response: {:?}",
        start.elapsed()
    );

    // Registration requires n-of-n

    let registration_success =
        Server::evaluate_verification(successful, servers.len(), VerificationPolicy::FullThreshold);

    println!("\nSuccessful Verifications = {}", successful,);

    println!("Threshold Result = {}", registration_success,);

    if registration_success {
        println!("\n✅ REGISTRATION SUCCESSFUL",);
    } else {
        println!("\n❌ REGISTRATION FAILED",);
    }
}

fn main() {
    let total_start = Instant::now();
    run_registration_demo();
    println!(
        "[Time] taken for complete registration :{:?}",
        total_start.elapsed()
    );
}
