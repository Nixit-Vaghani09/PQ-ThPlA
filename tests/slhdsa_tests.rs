use pq_thpla::slh_dsa::slhdsa::{generate_keys, sign_message, verify_message};

#[test]
fn test_generate_keys() {
    let (_pk, _sk) = generate_keys();
    assert!(true);
}

#[test]
fn test_sign_verify() {
    let (pk, sk) = generate_keys();

    let message = b"hello";

    let signature = sign_message(message, &sk);

    assert!(verify_message(&signature, message, &pk,));
}

#[test]
fn test_wrong_public_key() {
    let (_pk1, sk1) = generate_keys();

    let (pk2, _sk2) = generate_keys();

    let message = b"authentication_nonce";

    let signature = sign_message(message, &sk1);

    assert!(!verify_message(&signature, message, &pk2,));
}

#[test]
fn test_different_nonce_signatures() {
    let (pk, sk) = generate_keys();

    let sig1 = sign_message(b"nonce1", &sk);

    let sig2 = sign_message(b"nonce2", &sk);

    assert!(verify_message(&sig1, b"nonce1", &pk,));

    assert!(verify_message(&sig2, b"nonce2", &pk,));

    assert!(!verify_message(&sig1, b"nonce2", &pk,));
}

#[test]
fn test_tampered_message_fails() {
    let (pk, sk) = generate_keys();

    let signature = sign_message(b"nonce123", &sk);

    assert!(!verify_message(&signature, b"different_nonce", &pk,));
}

#[test]
fn test_wrong_signature_fails() {
    let (pk1, _sk1) = generate_keys();

    let (_pk2, sk2) = generate_keys();

    let signature = sign_message(b"nonce", &sk2);

    assert!(!verify_message(&signature, b"nonce", &pk1,));
}
