#[derive(Clone, Debug)]
pub struct RegistrationRequest {
    pub user_id: String,
    pub registration_nonce: [u8; 32],
}