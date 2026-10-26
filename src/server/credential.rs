use pqcrypto_sphincsplus::sphincsshake128ssimple::PublicKey;

pub struct StoredCredential {
    pub user_id: String,
    pub credential_id: String,
    pub public_key: PublicKey,
}