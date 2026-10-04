use libcrux_ml_kem::mlkem768::generate_key_pair;
use libcrux_ml_kem::mlkem768:: {encapsulate,decapsulate};
use libcrux_ml_kem::{MlKemPublicKey,MlKemPrivateKey,MlKemSharedSecret,MlKemCiphertext};
use rand::{RngCore, rngs::OsRng};
use sha2::{Sha256,Digest};

//this is to generate the random seed and nonce
pub fn random_array<const L: usize>() -> [u8; L] {
    assert!(L>0 , "Array length must be Positive");
    let mut seed = [0u8; L];
    OsRng.fill_bytes(&mut seed);
    seed
}
pub fn encapsulation(public_key: &MlKemPublicKey<1184>) -> Result<(MlKemCiphertext<1088>,MlKemSharedSecret),String> {
       
   
    let (cipher_text,shared_secret) = encapsulate(public_key,random_array());
    if shared_secret.len() != 32 {
        return Err("shared secret length must be 32 bytes".into());
    }
    
    Ok((cipher_text,shared_secret))
    
}

pub fn decapsulation(private_key: &MlKemPrivateKey<2400> , cipher_text:&MlKemCiphertext<1088> ) -> Result<(MlKemSharedSecret),String> {
    
    
    let (shared_secret) = decapsulate(private_key,cipher_text);
    if shared_secret.len() != 32 {
        return Err("Shared secret length must be 32 bytes".into());
    }
    Ok(shared_secret)
}

