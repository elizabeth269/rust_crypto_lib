use crate::ring;

use ring::aead::{aead, Aad, BoundKey, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::error::Unspecified;
use ring::rand::{SecureRandom, SystemRandom};

fn main() {
    // 32-byte key for AES-256
    let key = b"an example very very secret key."; // 32 bytes
    let cipher = Aes256Gcm::new_from_slice(key).unwrap();

    // 12-byte unique nonce for each encryption
    let nonce = Nonce::from_slice(b"unique nonce"); // 12 bytes; unique per message

    // Encrypting
    let plaintext = b"plaintext message";
    let ciphertext = cipher
        .encrypt(nonce, plaintext.as_ref())
        .expect("encryption failure!");

    // Decrypting
    let decrypted_plaintext = cipher
        .decrypt(nonce, ciphertext.as_ref())
        .expect("decryption failure!");
    assert_eq!(&decrypted_plaintext, plaintext);
}
