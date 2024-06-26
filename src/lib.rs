extern crate ring;
use ring::aead::{aead, Aad, BoundKey, LessSafeKey, Nonce, UnboundKey, AES_256_GCM, NONCE_LEN};
use ring::error::Unspecified;
use ring::rand::{SecureRandom, SystemRandom};

pub fn encrypt_aes_256_gcm(
    key: &[u8],
    plaintext: &[u8],
) -> Result<(Vec<u8>, Vec<u8>), Unspecified> {
    let key = UnboundKey::new(&AES_256_GCM, key)?;
    let nonce = {
        let mut nonce = vec![0u8; NONCE_LEN];
        SystemRandom::new().fill(&mut nonce)?;
        nonce
    };

    let nonce = Nonce::assume_unique_for_key(&nonce);
    let aad = Aad::empty();
    let mut in_out = plaintext.to_vec();

    let key = LessSafeKey::new(key);
    key.seal_in_place_append_tag(nonce, aad, &mut in_out)?;

    Ok((in_out, nonce.as_ref().to_vec()))
}

pub fn decrypt_aes_256_gcm(
    key: &[u8],
    nonce: &[u8],
    ciphertext: &[u8],
) -> Result<Vec<u8>, Unspecified> {
    let key = UnboundKey::new(&AES_256_GCM, key)?;
    let nonce = Nonce::try_assume_unique_for_key(nonce)?;
    let aad = Aad::empty();
    let mut in_out = ciphertext.to_vec();

    let key = LessSafeKey::new(key);
    key.open_in_place(nonce, aad, &mut in_out)?;

    let plaintext = in_out.split_off(in_out.len() - AES_256_GCM.tag_len());
    Ok(plaintext)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_256_gcm_encryption_decryption() {
        let key = b"an example very very secret key."; // 32 bytes
        let plaintext = b"hello world";

        let (ciphertext, nonce) = encrypt_aes_256_gcm(key, plaintext).expect("encryption failed");
        let decrypted_plaintext =
            decrypt_aes_256_gcm(key, &nonce, &ciphertext).expect("decryption failed");

        assert_eq!(plaintext.to_vec(), decrypted_plaintext);
    }
}
