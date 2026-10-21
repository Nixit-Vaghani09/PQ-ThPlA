use p256::{
    PublicKey,
    ecdh::EphemeralSecret,
};
use rand_core::OsRng;
use std::time::Instant;

use pq_thpla::ml_kem::session_mlkem::SessionContext;

fn ecdh_demo() {

    // =========================
    // Key Generation
    // =========================

    let start = Instant::now();

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
        "ECDH Key Generation: {:?}",
        start.elapsed()
    );

    // =========================
    // Shared Secret
    // =========================

    let start = Instant::now();

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

    assert_eq!(
        alice_shared.raw_secret_bytes(),
        bob_shared.raw_secret_bytes()
    );

    // =========================
    // Session Creation
    // =========================

    let start = Instant::now();

    let alice_session_key: [u8;32] =
        alice_shared
            .raw_secret_bytes()
            .as_slice()
            .try_into()
            .unwrap();

    let bob_session_key: [u8;32] =
        bob_shared
            .raw_secret_bytes()
            .as_slice()
            .try_into()
            .unwrap();

    let mut alice_session =
        SessionContext::new(
            alice_session_key,
            1,
        );

    let mut bob_session =
        SessionContext::new(
            bob_session_key,
            2,
        );

    println!(
        "Session Creation: {:?}",
        start.elapsed()
    );

    // =========================
    // Send Message
    // =========================

    let start = Instant::now();

    let msg =
        alice_session
            .send(
                b"Hello Bob!"
            )
            .unwrap();

    println!(
        "Send Message: {:?}",
        start.elapsed()
    );

    // =========================
    // Receive Message
    // =========================

    let start = Instant::now();

    let plaintext =
        bob_session
            .receive(&msg)
            .unwrap();

    println!(
        "Receive Message: {:?}",
        start.elapsed()
    );

    println!(
        "Bob received: {}",
        String::from_utf8_lossy(
            &plaintext
        )
    );

    // =========================
    // Rotate Secret
    // =========================

    let start = Instant::now();

    let rotate_alice =
        EphemeralSecret::random(
            &mut OsRng
        );

    let rotate_bob =
        EphemeralSecret::random(
            &mut OsRng
        );

    let rotate_alice_pub =
        PublicKey::from(
            &rotate_alice
        );

    let rotate_bob_pub =
        PublicKey::from(
            &rotate_bob
        );

    let mut alice_new_secret =
        rotate_alice
            .diffie_hellman(
                &rotate_bob_pub
            )
            .raw_secret_bytes()
            .to_vec();

    let mut bob_new_secret =
        rotate_bob
            .diffie_hellman(
                &rotate_alice_pub
            )
            .raw_secret_bytes()
            .to_vec();

    alice_session
        .rotate_key(
            &mut alice_new_secret
        )
        .unwrap();

    bob_session
        .rotate_key(
            &mut bob_new_secret
        )
        .unwrap();

    println!(
        "Rotate Secret: {:?}",
        start.elapsed()
    );

    // =========================
    // Send Again
    // =========================

    let start = Instant::now();

    let msg2 =
        alice_session
            .send(
                b"Rotated Hello!"
            )
            .unwrap();

    println!(
        "Send After Rotation: {:?}",
        start.elapsed()
    );

    // =========================
    // Receive Again
    // =========================

    let start = Instant::now();

    let plaintext2 =
        bob_session
            .receive(
                &msg2
            )
            .unwrap();

    println!(
        "Receive After Rotation: {:?}",
        start.elapsed()
    );

    println!(
        "Bob received after rotation: {}",
        String::from_utf8_lossy(
            &plaintext2
        )
    );
}

fn main() {

    let total =
        Instant::now();

    ecdh_demo();

    println!(
        "Total ECDH Demo: {:?}",
        total.elapsed()
    );
}