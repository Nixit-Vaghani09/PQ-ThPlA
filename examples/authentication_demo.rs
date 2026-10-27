// examples/authentication_demo.rs
use std::time::Instant;
use pq_thpla::auth::auth_request::AuthRequest;
use pq_thpla::auth::authentication::generate_auth_responses;
use pq_thpla::auth::verification::verify_auth_response;
use pq_thpla::challenge::challenge::Challenge;
use pq_thpla::merkle_tree::tree::{Hash, MerkleTree};
use pq_thpla::server::credential::StoredCredential;
use pq_thpla::server::server::{Server, VerificationPolicy};
use pq_thpla::slh_dsa::slhdsa::{generate_keys, sign_message};
use pq_thpla::threshold::shamir_setup::generate_server_shares;

pub fn run_authentication_demo() {
    println!("\n=== PQ-ThPlA Authentication Demo ===");

    /*
        Create Servers
    */

    let secret = b"pq-thpla-auth-secret";

    let start=Instant::now();

    let shares = generate_server_shares(secret, 3, 2);

    let mut servers: Vec<Server> = shares
        .into_iter()
        .enumerate()
        .map(|(i, share)| Server::new((i + 1) as u32, share))
        .collect();

    println!("[+] Created {} Servers", servers.len(),);
    println!("[Time] taken to form servers: {:?}",start.elapsed());
    /*
        Generate User Credential
    */

    let (public_key, secret_key) = generate_keys();

    println!("[+] SLH-DSA Keypair Generated",);

    /*
        Simulate Previous Registration
    */
    for server in servers.iter_mut() {
        let credential = StoredCredential {
            user_id: "alice".to_string(),

            public_key: public_key.clone(),
        };

        server.credential_store_mut().insert(credential);
    }

    println!("[+] Credential Stored On Servers",);

    /*
        Authentication Request
    */
    let start=Instant::now();
    let auth_request = AuthRequest::new("alice".to_string(), "session-001".to_string());

    println!("[+] Authentication Request Sent",);
    println!("[Time] taken to send a authentication request:{:?}",start.elapsed());

    /*
        Obtain Challenges
    */
    let start = Instant::now();
    let mut challenges: Vec<Challenge> = Vec::new();

    for server in &servers {
        let challenge = server
            .handle_authentication_request(auth_request.clone())
            .expect("challenge generation failed");

        challenges.push(challenge);
    }

    println!("[+] {} Challenges Received", challenges.len(),);
    println!("[Time] taken to recieve challenges from server: {:?}",start.elapsed());

    /*
        Build Merkle Tree
    */
    let start = Instant::now();
    let leaves: Vec<(u32, Hash)> = challenges
        .iter()
        .map(|challenge| (challenge.server_id, challenge.hash_challenge()))
        .collect();

    let tree = MerkleTree::new(leaves);

    println!("[+] Merkle Tree Built",);

    /*
        Sign Root
    */

    let signature = sign_message(tree.root().as_ref(), &secret_key);

    /*
        Generate Responses
    */

    let responses = generate_auth_responses(&tree, signature);

    println!("[+] Authentication Responses Generated",);

    println!("[Time] taken to make merkle tree and generate proofs = {:?}",start.elapsed());

    /*
        Verify Responses
    */
    let start = Instant::now();
    let mut successful = 0;

    for (challenge, _server) in challenges.iter().zip(servers.iter()) {
        let response = responses.get(&challenge.server_id).unwrap();

        let valid = verify_auth_response(challenge, response, &public_key);

        println!("Server {} Verification = {}", challenge.server_id, valid,);

        if valid {
            successful += 1;
        }
    }
    println!("[Time] taken by servers to verify the responses = {:?}",start.elapsed());
    /*
        Threshold Check
    */

    let authenticated =
        Server::evaluate_verification(successful, servers.len(), VerificationPolicy::Threshold(2));

    println!("\nSuccessful Verifications = {}", successful,);

    println!("Threshold Result = {}", authenticated,);

    if authenticated {
        println!("\n✅ ACCESS GRANTED",);
    } else {
        println!("\n❌ ACCESS DENIED",);
    }
}

fn main() {
    let total_start= Instant::now();
    run_authentication_demo();
    println!("[Time] for total authentication process = {:?}",total_start.elapsed());
}
