use libcrux_ml_kem::ml_kem_768::generate_key_pair;
use libcrux_ml_kem::ml_kem_768::encapsulate;
use rand::{RngCore, rngs::OsRng};

//this is to generate the random seed and nonce
fn random_array<L: usize>() -> ([u8; L]) {
    assert!(L>0 , "Array length must be Positive");
    let mut seed = [u8; L];
    OsRng.fill_bytes(&mut seed);
    seed
}
fn encapsulation(public_key: &[u8]) -> (Vec<u8>,Vec<u8>) {
    assert!(public_key.is_empty(),"Public key cannot be empty");
    assert_eq!(public_key.len(),1184,"public key length must be 1184 bytes");
    let (cipher_text,shared_secret) = encapsulate(public_key,random_array());
    assert_eq!(shared_secret.len(),32,"Shared secret length must be 32 bytes");
    assert_eq!(cipher_text.len(),1088,"cipher text length doesnt matches");
    (cipher_text,shared_secret)
    
}

fn decapsulation(private_key: &[u8] , cipher_text: &[u8]) -> (Vec<u8>) {
    assert!(private_key.is_empty(),"Private key cannot be empty");
    assert_eq!(private_key.len(),2400,"private key length must be 2400 bytes");
    assert!(cipher_text.is_empty(),"cipher text cannot be empty");
    let (shared_secret) = decapsulate(private_key,cipher_text);
    assert_eq!(shared_secret.len(),32,"Shared secret length must be 32 bytes");
    shared_secret
}
fn main() {
    let bob_key = generate_key_pair(random_array());

}
