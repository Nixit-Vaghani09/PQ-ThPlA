use pqcrypto_sphincsplus::sphincsshake128ssimple::{keypair,sign,PublicKey,SecretKey,open,SignedMessage};

pub fn generate_keys() -> (PublicKey,SecretKey){
    let (pk,sk) = keypair();
    (pk,sk)
}

pub fn sign_nonce(nonce: &[u8] , sk: &SecretKey) -> SignedMessage{
    let signed: SignedMessage = sign(nonce,sk);
    signed
}

pub fn verify_Message(signed: &SignedMessage, pk: &PublicKey) -> Option<Vec<u8>>{
    match open(&signed, &pk){
        Ok(msg) => Some(msg),
        Err(_) => None,
    }
}

