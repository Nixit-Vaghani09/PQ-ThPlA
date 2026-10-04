use std::ops::RangeInclusive;

use libcrux_ml_kem::mlkem768::{generate_key_pair };
use libcrux_ml_kem::MlKemCiphertext;
use pq_thpla::mlkem::*;

#[test]
fn test_encapsulation_decapsulation() {
    let keys = generate_key_pair(random_array());
    let (cipher_text, ss_alice) = encapsulation(keys.public_key()).unwrap();
    let ss_bob = decapsulation(keys.private_key(), &cipher_text).unwrap();
    assert_eq!(ss_alice, ss_bob);
}

#[test]
fn test_randomarray_produces_correctlength() {
    let rand_array = random_array::<32>();
    assert_eq!(rand_array.len(), 32);
}
#[test]
fn test_randomarray_notequallength() {
    let array_1 = random_array::<32>();
    let array_2 = random_array::<32>();
    assert_ne!(
        array_1, array_2,
        "it should produce different output random"
    );
}

#[test]
fn test_randomarray_rangeofvalue() {
    let arr = random_array::<32>();
    for &byte in arr.iter() {
        assert!(byte <= 255);
    }
}

#[test]
fn test_encapsulation_withwrongkey() {
    let keys1 = generate_key_pair(random_array());
    let keys2 = generate_key_pair(random_array());
    let (cipher_text, ss_alice) = encapsulation(keys1.public_key()).unwrap();
    let ss_bob = decapsulation(keys2.private_key(), &cipher_text).unwrap();
    assert_ne!(ss_alice, ss_bob);
}

#[test]
fn test_decapsulation_fails_wrongcipher() {
    let keys = generate_key_pair(random_array());
    let (mut ciphertext, ss_alice) = encapsulation(keys.public_key()).unwrap();

    
    let mut ct_bytes: [u8; 1088] = ciphertext.as_ref().try_into().unwrap();
    ct_bytes[0] ^= 0xFF; // flip one byte
    let corrupted_ct =  MlKemCiphertext::<1088>::from(ct_bytes);
   
    let ss_bob = decapsulation(keys.private_key(), &corrupted_ct).unwrap();
    assert_ne!(ss_alice, ss_bob, "Corrupted ciphertext must not yield the same secret");
}

#[test]
fn test_invalid_ciphertext_length() {
    // Wrong length: only 100 bytes instead of 1088
    let bad_bytes: Vec<u8> = vec![0u8; 100];

    // Try to convert slice into fixed array
    let result: Result<[u8; 1088], _> = bad_bytes.as_slice().try_into();

    // This must fail
    assert!(result.is_err(), "Invalid ciphertext length must be rejected");

    // If you want to go further: ensure you cannot build MlKemCiphertext
    if let Ok(arr) = result {
        // This block should never run
        let ct = MlKemCiphertext::<1088>::from(arr);
        panic!("Should not construct MlKemCiphertext from invalid length");
    }
}


