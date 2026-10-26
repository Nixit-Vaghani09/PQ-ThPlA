// src/server/server.rs
use std::collections::HashMap;
use rand::rngs::OsRng;
use sha3::{Digest, Sha3_256};
use libcrux_ml_kem::{MlKemCiphertext, MlKemPrivateKey};
use crate::auth::auth_request::AuthRequest;
use crate::challenge::challenge::Challenge;
use crate::server::credential_store::CredentialStore;
use crate::threshold::server_share::ServerShare;
use crate::ml_kem::session_mlkem::SessionContext;
use crate::ml_kem::mlkem::decapsulation;
use crate::ml_kem::channel_mlkem::ChannelError;




pub struct Server {

    server_id: u32,

    secret_share: ServerShare,

    credential_store: CredentialStore,

    active_sessions: HashMap<String,SessionContext>,
}


impl Server {

    pub fn new(
        server_id: u32,
        secret_share: ServerShare,
    ) -> Self {

        Self {
            server_id,
            secret_share,
            credential_store: CredentialStore::new(),
            active_sessions:HashMap::new(),
        }
    }

    pub fn server_id(
        &self,
    ) -> u32 {

        self.server_id
    }
    fn secret_share(&self) -> &ServerShare{
        &self.secret_share
    }

    pub fn credential_store(
        &self,
    ) -> &CredentialStore {

        &self.credential_store
    }

    pub fn credential_store_mut(
        &mut self,
    ) -> &mut CredentialStore {

        &mut self.credential_store
    }

        pub fn generate_challenge(
        &self,
        session_id:String,
    ) -> Challenge {
        let mut nonce= [0u8;32];
        OsRng.fill_bytes(&mut nonce);
        Challenge::new(self.server_id,session_id,nonce)
    }

    pub fn create_server_session(
    private_key: &MlKemPrivateKey<2400>,
    ciphertext: &MlKemCiphertext<1088>,
    session_id: u64,
) -> Result<
    SessionContext,
    ChannelError,
> {

    let shared_secret =
        decapsulation(
            private_key,
            ciphertext,
        )?;

    let mut session_key =
        [0u8; 32];

    session_key.copy_from_slice(
        shared_secret.as_ref(),
    );

    Ok(
        SessionContext::new(
            session_key,
            session_id,
        )
    )
}
}