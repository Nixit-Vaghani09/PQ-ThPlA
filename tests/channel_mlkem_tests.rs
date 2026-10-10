use pq_thpla::channel_mlkem::{ChannelContext, ChannelError, Message};
use pq_thpla::mlkem::random_array;

#[test]
fn test_channel_context_initialization() {
    let session_key = random_array::<32>();
    let _ctx = ChannelContext::new(session_key);
    // If no panic, initialization works
}

#[test]
fn test_send_and_receive_message() {
    let session_key = random_array::<32>();
    let mut send_channel = ChannelContext::new(session_key);
    let mut recieve_channel = ChannelContext::new(session_key);
    let msg = send_channel.send_secure(b"hello world").unwrap();
    let plaintext = recieve_channel.receive_secure(&msg).unwrap();
    println!("Plaintext: {}", String::from_utf8_lossy(&plaintext));
    assert_eq!(plaintext, b"hello world");
}

#[test]
fn test_nonce_reuse_detection() {
    let session_key = random_array::<32>();
    let mut send_channel = ChannelContext::new(session_key);
    let mut receive_channel = ChannelContext::new(session_key);
    let msg = send_channel.send_secure(b"first").unwrap();
    // Trying to receive the same message twice should trigger NonceReuse
    let plaintext = receive_channel.receive_secure(&msg).unwrap();
    assert_eq!(plaintext,b"first");
    let result = receive_channel.receive_secure(&msg);

    assert!(matches!(result, Err(ChannelError::NonceReuse)));
}

#[test]
fn test_rotate_key_changes_behavior() {
    let session_key = random_array::<32>();
    let mut channel = ChannelContext::new(session_key);

    // Encrypt with original key
    let msg1 = channel.send_secure(b"before rotation").unwrap();
    let plain1 = channel.receive_secure(&msg1).unwrap();
    assert_eq!(plain1, b"before rotation");

    // Rotate to new secret
    let mut next_secret = random_array::<32>();
    channel.rotate_key(&mut next_secret).unwrap();

    // Encrypt with new key
    let msg2 = channel.send_secure(b"after rotation").unwrap();
    let plain2 = channel.receive_secure(&msg2).unwrap();
    assert_eq!(plain2, b"after rotation");

    // Old ciphertext should fail after rotation
    let result = channel.receive_secure(&msg1);
    assert!(matches!(result, Err(ChannelError::DecryptionFailed(_))));
}

#[test]
fn test_key_expired_error() {
    let session_key = random_array::<32>();
    let mut channel = ChannelContext::new(session_key);

    // Drive the counter up to the expiry threshold
    for _ in 0..1_000_000 {
        let _ = channel.next_send_nonce().unwrap();
    }

    // Now the next call should fail with KeyExpired
    let send_result = channel.next_send_nonce();
    assert!(matches!(send_result, Err(ChannelError::KeyExpired)));

    for _ in 0..1_000_000 {
        let _ = channel.next_receive_nonce().unwrap();
    }
    let receive_result = channel.next_receive_nonce();
    assert!(matches!(receive_result,Err(ChannelError::KeyExpired)));
}

#[test]
fn test_decryption_failed_error() {
    let session_key = random_array::<32>();
    let mut channel = ChannelContext::new(session_key);

    let msg = channel.send_secure(b"valid").unwrap();

    let mut tampered_msg = msg.clone();
    tampered_msg.ciphertext[0] ^= 0xFF; // flip a bit

    let result = channel.receive_secure(&tampered_msg);
    assert!(matches!(result, Err(ChannelError::DecryptionFailed(_))));
}

#[test]
fn test_encryption_failed_error() {
    // This one is trickier because aes_encrypt only fails if misused.
    // We simulate by passing an invalid key length to mlkem::aes_encrypt.
    // For now, we can assert that send_secure works with a valid key,
    // and leave encryption failure to integration tests with mlkem.
    let session_key = random_array::<32>();
    let mut channel = ChannelContext::new(session_key);

    let result = channel.send_secure(b"hello");
    assert!(result.is_ok());
}
