use pq_thpla::slh_dsa::slhdsa::{sign_nonce,generate_keys,verify_Message};
use pqcrypto_sphincsplus::sphincsshake128ssimple::{PublicKey,SecretKey};

#[test]
fn test_generate_keys(){
    let (_pk,_sk)=generate_keys();
    assert!(true);
}

#[test]
fn test_sign_verify() {
    let (pk,sk) = generate_keys();
    let nonce = b"hello";
    let signed = sign_nonce(nonce,&sk);
    let verified = verify_Message(&signed,&pk);
    assert!(verified.is_some());
    let recovered = verified.unwrap();
    assert_eq!(recovered.as_slice(),nonce);
}

#[test]
fn test_wrong_public_key() {
    let (_pk1, sk1) = generate_keys();
    let (pk2, _sk2) = generate_keys();

    let nonce = b"authentication_nonce";

    let signed = sign_nonce(nonce, &sk1);

    let result = verify_Message(&signed, &pk2);

    assert!(result.is_none());
}

#[test]
fn test_different_nonce_signatures() {
    let (_pk, sk) = generate_keys();

    let sig1 = sign_nonce(b"nonce1", &sk);
    let sig2 = sign_nonce(b"nonce2", &sk);

    let recovered1 = verify_Message(&sig1,&_pk).unwrap();
    let recovered2=verify_Message(&sig2,&_pk).unwrap();

    assert_ne!(recovered1,recovered2);
}

#[test]
fn test_signature_recovers_message() {
    let (pk,sk) = generate_keys();
    let nonce = b"nonce123";
    let signed = sign_nonce(nonce,&sk);
    let recovered = verify_Message(&signed,&pk).unwrap();
    assert_eq!(recovered,nonce);
}