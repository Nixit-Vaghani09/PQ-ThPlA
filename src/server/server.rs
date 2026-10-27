// src/server/server.rs
use std::collections::HashMap;
use rand::RngCore;
use rand::rngs::OsRng;
use sha3::{Digest, Sha3_256};
use libcrux_ml_kem::{MlKemCiphertext, MlKemPrivateKey};
use crate::auth::auth_request::AuthRequest;
use crate::registration::registration_request::RegistrationRequest;
use crate::challenge::challenge::Challenge;
use crate::server::credential_store::CredentialStore;
use crate::threshold::server_share::ServerShare;
use crate::ml_kem::session_mlkem::SessionContext;
use crate::ml_kem::mlkem::decapsulation;
use crate::ml_kem::channel_mlkem::ChannelError;


#[derive(Debug)]
pub enum AuthenticationError {
    UserNotFound,
}

#[derive(Debug)]
pub enum RegistrationError {
    UserAlreadyRegistered,
}
pub enum VerificationPolicy {
    FullThreshold,
    Threshold(usize),
}

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

        pub fn generate_authentication_challenge(
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

pub fn handle_authentication_request(
    &self,
    request: AuthRequest,
) -> Result<Challenge, AuthenticationError>
{
    /*
        Check user exists
    */

    if !self
        .credential_store
        .contains(
            &request.user_id,
        )
    {
        return Err(
            AuthenticationError::UserNotFound
        );
    }

    /*
        Generate challenge
    */

    let challenge =
        self.generate_authentication_challenge(
            request.session_id.clone(),
        );

    Ok(
        challenge,
    )
}

pub fn generate_registration_challenge(
    &self,
    session_id: String,
) -> Challenge {
    let mut nonce = [0u8; 32];

    OsRng.fill_bytes(&mut nonce);

    Challenge::new(
        self.server_id,
        session_id,
        nonce,
    )
}

pub fn handle_registration_request(
    &self,
    request: RegistrationRequest,
) -> Result<Challenge, RegistrationError>
{
    if self
        .credential_store
        .contains(
            &request.user_id,
        )
    {
        return Err(
            RegistrationError::UserAlreadyRegistered,
        );
    }

    let challenge =
        self.generate_registration_challenge(
            request.session_id.clone(),
        );

    Ok(
        challenge,
    )
}

pub fn evaluate_verification(
    successful: usize,
    total_servers: usize,
    policy: VerificationPolicy,
) -> bool
{
    match policy {

        VerificationPolicy::FullThreshold =>
            successful == total_servers,

        VerificationPolicy::Threshold(t) =>
            successful >= t,
    }
}
}