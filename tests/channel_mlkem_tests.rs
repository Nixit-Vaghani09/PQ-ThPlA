use pq_thpla::channel_mlkem::{ChannelContext, ChannelError, Message};
use pq_thpla::mlkem::random_array;

#[test]
fn test_channel_context_initialization() {
    
    let session_key = random_array::<32>();
    let _ctx = ChannelContext::new(session_key);
    
}

#[test]
fn test_rotate_key_changes_encryption_behavior() {
    let session_key = random_array::<32>();
    let mut channel = ChannelContext::new(session_key);

    
    let msg1 = channel.send_secure(b"hello").unwrap();
    let plain1 = channel.receive_secure(&msg1).unwrap();
    assert_eq!(plain1, b"hello");

    
    let mut next_secret = random_array::<32>();
    channel.rotate_key(&mut next_secret).unwrap();

    
    let msg2 = channel.send_secure(b"world").unwrap();
    let plain2 = channel.receive_secure(&msg2).unwrap();
    assert_eq!(plain2, b"world");

    
    let result = channel.receive_secure(&msg1);
    assert!(matches!(result, Err(ChannelError::DecryptionFailed(_))));
}
