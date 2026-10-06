use libcrux_ml_kem::mlkem768::{generate_key_pair };
use pq_thpla::mlkem::{self, random_array};
use pq_thpla::channel_mlkem::{ChannelError,message};
use pq_thpla::session_mlkem::{SessionContext};


fn handshake_demo() {
    // Bob generates ML-KEM key pair
    let keys = generate_key_pair(random_array());

    // Alice encapsulates using Bob's public key
    let (ciphertext, shared_secret_alice) = mlkem::encapsulation(&keys.public_key()).unwrap();

    // Bob decapsulates using his private key
    let shared_secret_bob = mlkem::decapsulation( &keys.private_key(),&ciphertext).unwrap();

    // Both derive AES keys from shared secret
    let mut alice_session = SessionContext::new(&shared_secret_alice, 1);
    let mut bob_session   = SessionContext::new(&shared_secret_bob, 2);

    // Alice sends a message
    let msg = alice_session.send(b"Hello Bob!").unwrap();

    // Bob receives it
    let plaintext = bob_session.receive(&msg).unwrap();
    println!("Bob received: {:?}", String::from_utf8(plaintext).unwrap());
}
