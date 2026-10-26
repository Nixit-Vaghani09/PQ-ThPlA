// src/server/server.rs
use sha3::{Digest, Sha3_256};
use crate::auth::auth_request::AuthRequest;
use crate::challenge::challenge::Challenge;
use crate::server::credential_store::CredentialStore;
use crate::threshold::server_share::ServerShare;

pub struct Server {

    server_id: u32,

    secret_share: ServerShare,

    credential_store: CredentialStore,
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
        request: &AuthRequest,
    ) -> Challenge {

        

        let nonce = self.secret_share.derive_nonce(&session_id);
        Challenge::new(self.server_id,session_id,nonce)
    }
}