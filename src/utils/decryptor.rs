use aes::Aes128;
use cipher::{BlockDecrypt, BlockDecryptMut, KeyIvInit, block_padding::Pkcs7};
use hex_literal::hex;
use std::error::Error;

type Aes128CbcDec = cbc::Decryptor<Aes128>;

const KEY: [u8; 16] = [
    0xfd, 0x46, 0x4d, 0x69, 0x5e, 0x69, 0xa3, 0x9a, 0x10, 0xe3, 0x19, 0xa7, 0xac, 0xe8, 0xb7, 0xfa,
];



pub fn decrypt_file(raw: &[u8], iv: &[u8]) -> Vec<u8> {
    // Initialize the cipher
    let cipher = Aes128CbcDec::new_from_slices(&KEY, iv).expect("");

    // Create a buffer to hold the decrypted data
    let mut buffer = raw.to_vec();

    // Decrypt the data in-place
    cipher.decrypt_padded_mut::<Pkcs7>(&mut buffer);

    buffer
}