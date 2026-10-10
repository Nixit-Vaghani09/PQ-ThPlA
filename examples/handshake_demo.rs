use pq_thpla::mlkem;
use pq_thpla::mlkem::generate_keypair;
use pq_thpla::session_mlkem::SessionContext;

fn handshake_demo() {
    // Bob generates ML-KEM key pair
    let keys = generate_keypair();

    // Alice encapsulates using Bob's public key
    let (ciphertext, shared_secret_alice) = mlkem::encapsulation(&keys.public_key()).unwrap();

    // Bob decapsulates using his private key
    let shared_secret_bob = mlkem::decapsulation(&keys.private_key(), &ciphertext).unwrap();

    // Keep session keys outside the contexts; each context borrows its key.
    let mut alice_session_key: [u8; 32] = shared_secret_alice.as_ref().try_into().unwrap();
    let mut bob_session_key: [u8; 32] = shared_secret_bob.as_ref().try_into().unwrap();
    let mut alice_session = SessionContext::new( alice_session_key, 1);
    let mut bob_session = SessionContext::new( bob_session_key, 2);

    // Alice sends a message
    let msg = alice_session.send(b"Hello Bob!").unwrap();

    // Bob receives it
    let plaintext = bob_session.receive(&msg).unwrap();
    println!("Bob received: {:?}", String::from_utf8(plaintext).unwrap());

    // Negotiate a fresh shared secret before the next session begins.
    let next_keys = generate_keypair();
    let (next_ciphertext, alice_next_secret) =
        mlkem::encapsulation(next_keys.public_key()).unwrap();
    let bob_next_secret = mlkem::decapsulation(next_keys.private_key(), &next_ciphertext).unwrap();
    let mut alice_next_key: [u8; 32] = alice_next_secret.as_ref().try_into().unwrap();
    let mut bob_next_key: [u8; 32]   = bob_next_secret.as_ref().try_into().unwrap();
    alice_session.rotate_key(&mut alice_next_key).unwrap();
    bob_session.rotate_key(&mut bob_next_key).unwrap();
    let msg2 = alice_session.send(b"Rotated Hello!").unwrap();
    let plaintext2 = bob_session.receive(&msg2).unwrap();
    println!("Bob received after rotation: {:?}", String::from_utf8(plaintext2).unwrap())
}

fn main() {
    handshake_demo();
}
