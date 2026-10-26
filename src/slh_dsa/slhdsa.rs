use pqcrypto_sphincsplus::sphincsshake128ssimple::{
    keypair,
    detached_sign,
    verify_detached_signature,
    DetachedSignature,
    PublicKey,
    SecretKey,
};

pub fn generate_keys() -> (PublicKey, SecretKey) {

    let (pk, sk) = keypair();

    (pk, sk)
}

pub fn sign_message(
    message: &[u8],
    sk: &SecretKey,
) -> DetachedSignature {

    detached_sign(
        message,
        sk,
    )
}

pub fn verify_message(
    signature: &DetachedSignature,
    message: &[u8],
    pk: &PublicKey,
) -> bool {

    verify_detached_signature(
        signature,
        message,
        pk,
    )
    .is_ok()
}