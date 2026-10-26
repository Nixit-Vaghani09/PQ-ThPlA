use crate::ml_kem::mlkem:: encapsulation;
use crate::ml_kem::channel_mlkem::ChannelError;
use crate::ml_kem::session_mlkem::SessionContext;

use libcrux_ml_kem::{MlKemCiphertext, MlKemPublicKey};

pub fn create_client_session(
    public_key: &MlKemPublicKey<1184>,
    session_id: u64,
) -> Result<(SessionContext, MlKemCiphertext<1088>), ChannelError> {
    let (ciphertext, shared_secret) = encapsulation(public_key)?;

    let mut session_key = [0u8; 32];

    session_key.copy_from_slice(shared_secret.as_ref());

    let session = SessionContext::new(session_key, session_id);

    Ok((session, ciphertext))
}
