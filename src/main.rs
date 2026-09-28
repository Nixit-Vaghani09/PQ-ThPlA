use libcrux_ml_kem::mlkem768::{generate_key_pair , encapsulate , decapsulate};
use rand::{rngs::OsRng, RngCore};

fn random_array<const L: usize>() -> [u8;L]{
    let mut seed = [0u8;L];
    OsRng.fill_bytes(&mut seed);
    seed
}
fn main() {
    let key_pair: libcrux_ml_kem::MlKemKeyPair<2400, 1184> = generate_key_pair(random_array());
    let (ciphertext, shared_secret_enc) = encapsulate(key_pair.public_key(),random_array());
    let shared_secret_dec = decapsulate(key_pair.private_key(),&ciphertext);
    assert_eq!(shared_secret_enc,shared_secret_dec);
    println!("Shared secret established!");
}