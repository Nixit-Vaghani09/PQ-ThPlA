use pq_thpla::ml_kem::session_mlkem::{SessionContext};
use pq_thpla::ml_kem::channel_mlkem::{ChannelError, Message};
use pq_thpla::ml_kem::mlkem::random_array;

#[test]
fn test_session_initialization() {
    let session_key = random_array::<32>();
    let session_id = 42;
    let _session = SessionContext::new(session_key, session_id);
    // If no panic, initialization works
}

#[test]
fn test_session_send_and_receive() {
    let session_key = random_array::<32>();
    let mut session = SessionContext::new(session_key, 1);

    let msg = session.send(b"hello session").unwrap();
    let plaintext = session.receive(&msg).unwrap();

    assert_eq!(plaintext, b"hello session");
}

#[test]
fn test_session_nonce_reuse_detection() {
    let session_key = random_array::<32>();
    let mut session = SessionContext::new(session_key, 2);

    let msg = session.send(b"first").unwrap();

    // First receive works
    let plaintext = session.receive(&msg).unwrap();
    assert_eq!(plaintext, b"first");

    // Second receive with same nonce should trigger NonceReuse
    let result = session.receive(&msg);
    assert!(matches!(result, Err(ChannelError::NonceReuse)));
}

#[test]
fn test_session_rotate_key_changes_behavior() {
    let session_key = random_array::<32>();
    let mut session = SessionContext::new(session_key, 3);

    // Encrypt with original key
    let msg1 = session.send(b"before rotation").unwrap();
    let plain1 = session.receive(&msg1).unwrap();
    assert_eq!(plain1, b"before rotation");

    // Rotate to new secret
    let mut next_secret = random_array::<32>();
    session.rotate_key(&mut next_secret).unwrap();

    // Encrypt with new key
    let msg2 = session.send(b"after rotation").unwrap();
    let plain2 = session.receive(&msg2).unwrap();
    assert_eq!(plain2, b"after rotation");

    // Old ciphertext should fail after rotation
    let result = session.receive(&msg1);
    assert!(matches!(result, Err(ChannelError::DecryptionFailed(_))));
}

#[test]
fn test_session_key_expired_error() {
    let session_key = random_array::<32>();
    let mut session = SessionContext::new(session_key, 4);

    // Drive send counter up to expiry threshold
    for _ in 0..1_000_000 {
        let _ = session.next_send_nonce().unwrap();
    }
    let send_result = session.next_send_nonce();
    assert!(matches!(send_result, Err(ChannelError::KeyExpired)));

    // Drive receive counter up to expiry threshold
    for _ in 0..1_000_000 {
        let _ = session.next_receive_nonce().unwrap();
    }
    let receive_result = session.next_receive_nonce();
    assert!(matches!(receive_result, Err(ChannelError::KeyExpired)));
}

#[test]
fn test_session_decryption_failed_error() {
    let session_key = random_array::<32>();
    let mut session = SessionContext::new(session_key, 5);

    let msg = session.send(b"valid").unwrap();

    let mut tampered_msg = msg.clone();
    let len = tampered_msg.ciphertext.len();
    tampered_msg.ciphertext[len - 1] ^= 0xFF; // flip a bit

    let result = session.receive(&tampered_msg);
    assert!(matches!(result, Err(ChannelError::DecryptionFailed(_))));
}
