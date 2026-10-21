use pq_thpla::ml_kem::mlkem;
use pq_thpla::ml_kem::mlkem::generate_keypair;
use pq_thpla::ml_kem::session_mlkem::SessionContext;
use std::time::Instant;
fn handshake_demo() {
    // Bob generates ML-KEM key pair
    let total_start = Instant::now();
    let start = Instant::now();
    let keys = generate_keypair();
    let keygen_time = start.elapsed();
    println!("ML-KEM Key Generation:{:?}", keygen_time);
    // Alice encapsulates using Bob's public key

    let (ciphertext, shared_secret_alice) = mlkem::encapsulation(&keys.public_key()).unwrap();
    let encapsulation_time = start.elapsed();

    // Bob decapsulates using his private key

    let shared_secret_bob = mlkem::decapsulation(&keys.private_key(), &ciphertext).unwrap();
    let decapsulation_time = start.elapsed();

    // Keep session keys outside the contexts; each context borrows its key.
    let mut alice_session_key: [u8; 32] = shared_secret_alice.as_ref().try_into().unwrap();
    let mut bob_session_key: [u8; 32] = shared_secret_bob.as_ref().try_into().unwrap();
    let total_shared_secret_time = total_start.elapsed();
    println!(
        "time required to derive the shared secret:{:?}",
        total_shared_secret_time
    );
    let mut alice_session = SessionContext::new(alice_session_key, 1);
    let mut bob_session = SessionContext::new(bob_session_key, 2);

    // Alice sends a message
    let start = Instant::now();

    let msg = alice_session.send(b"Hello Bob!").unwrap();
    let encapsulation_time = start.elapsed();
    println!("Encapsulation time: {:?}", encapsulation_time);

    // Bob receives it
    let start = Instant::now();

    let plaintext = bob_session.receive(&msg).unwrap();
    println!("Bob received: {:?}", String::from_utf8(plaintext).unwrap());
    let decapsulation_time = start.elapsed();
    println!("Decapsulation time: {:?}", decapsulation_time);

    // Negotiate a fresh shared secret before the next session begins.
    let start = Instant::now();
    let next_keys = generate_keypair();
    let (next_ciphertext, alice_next_secret) =
        mlkem::encapsulation(next_keys.public_key()).unwrap();
    let bob_next_secret = mlkem::decapsulation(next_keys.private_key(), &next_ciphertext).unwrap();

    let mut alice_next_key: [u8; 32] = alice_next_secret.as_ref().try_into().unwrap();
    let mut bob_next_key: [u8; 32] = bob_next_secret.as_ref().try_into().unwrap();
    alice_session.rotate_key(&mut alice_next_key).unwrap();
    bob_session.rotate_key(&mut bob_next_key).unwrap();
    let new_key_gen_time = start.elapsed();
    println!(
        "Time for new ml_kem key generation is: {:?}",
        new_key_gen_time
    );
}

fn main() {
    let start = Instant::now();
    handshake_demo();
    let duration = start.elapsed();
    println!("Handshake demo took: {:?}", duration);
}
