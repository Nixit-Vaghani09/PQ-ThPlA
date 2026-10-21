use std::time::Instant;

use p256::{
    PublicKey,
    ecdh::EphemeralSecret,
};

use rand_core::OsRng;

fn ecdh_demo() {

    // ----------------
    // Key Generation
    // ----------------

    let start =
        Instant::now();

    let alice_secret =
        EphemeralSecret::random(
            &mut OsRng
        );

    let alice_public =
        PublicKey::from(
            &alice_secret
        );

    let bob_secret =
        EphemeralSecret::random(
            &mut OsRng
        );

    let bob_public =
        PublicKey::from(
            &bob_secret
        );

    println!(
        "ECDH KeyGen: {:?}",
        start.elapsed()
    );

    // ----------------
    // Shared Secret
    // ----------------

    let start =
        Instant::now();

    let alice_shared =
        alice_secret
            .diffie_hellman(
                &bob_public
            );

    let bob_shared =
        bob_secret
            .diffie_hellman(
                &alice_public
            );

    println!(
        "ECDH Shared Secret: {:?}",
        start.elapsed()
    );

    // ----------------
    // Verify Secret
    // ----------------

    let start =
        Instant::now();

    assert_eq!(
        alice_shared.raw_secret_bytes(),
        bob_shared.raw_secret_bytes()
    );

    println!(
        "Secret Verification: {:?}",
        start.elapsed()
    );
}

fn main() {

    let total =
        Instant::now();

    ecdh_demo();

    println!(
        "Total ECDH Time: {:?}",
        total.elapsed()
    );
}