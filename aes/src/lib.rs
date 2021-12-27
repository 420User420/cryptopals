use std::fmt;
// use openssl::symm;
type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_aes_block() -> Result<()> {
        let plain = b"yellow submarine";
        let key = b"YELLOW SUBMARINE";

        let cipher = encrypt_aes_128_block(plain, key)?;
        let clear = decrypt_aes_128_block(&cipher, key)?;

        assert_eq!(clear, plain);

        Ok(())
    }

    #[test]
    fn test_ecb() -> Result<()> {
        let plain = b"This works whatever the plaintext is !!!";
        let key = b"YELLOW SUBMARINE";

        let mut padded = plain.to_vec();
        padding_pkcs7(&mut padded, 16)?;

        let cipher = encrypt_aes_128_ecb(plain, key)?;
        let clear = decrypt_aes_128_ecb(&cipher, key)?;

        assert_eq!(clear, padded);

        Ok(())
    }

    #[test]
    fn test_cbc() -> Result<()> {
        let plain = b"This works whatever the plaintext is !!!";
        let key = b"YELLOW SUBMARINE";
        let iv = b"ABCDEF GHIJKLMNO";

        let mut padded_in = plain.to_vec();
        padding_pkcs7(&mut padded_in, 16)?;

        let cipher = encrypt_aes_128_cbc(plain, key, iv)?;
        let clear = decrypt_aes_128_cbc(&cipher, key, iv)?;

        assert_eq!(padded_in, clear);

        Ok(())
    }
}

pub enum MODE {
    ECB,
    CBC,
}

impl PartialEq for MODE {
    fn eq(&self, other: &Self) -> bool {
        match (self, other) {
            (MODE::ECB, MODE::ECB) => true,
            (MODE::CBC, MODE::CBC) => true,
            _ => false,
        }
    }
}

impl fmt::Debug for MODE {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MODE::CBC => write!(f, "CBC Mode"),
            MODE::ECB => write!(f, "ECB Mode"),
        }
    }
}

impl fmt::Display for MODE {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            MODE::CBC => write!(f, "CBC Mode"),
            MODE::ECB => write!(f, "ECB Mode"),
        }
    }
}

fn do_xor(left: &[u8], right: &[u8]) -> Result<Vec<u8>> {
    if left.len() != right.len() {
        panic!("Not same length {} - {}", left.len(), right.len());
    }

    let mut out_bytes: Vec<u8> = Vec::with_capacity(left.len());

    for i in 0..left.len() {
        out_bytes.push(left[i] ^ right[i]);
    }

    Ok(out_bytes)
}

pub fn padding_pkcs7(input: &mut Vec<u8>, block_size: usize) -> Result<()> {
    if (input.len() % block_size) == 0 {
        return Ok(());
    }

    let pad_value = (block_size - (input.len() % block_size)) as u8;

    for _ in 0..pad_value {
        input.push(pad_value);
    }

    Ok(())
}

pub fn decrypt_aes_128_block(input: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if input.len() != 16 {
        panic!("Input length should be 16, is {}.", input.len());
    }

    let padding = encrypt_aes_128_block(&[16u8; 16], key)?;
    let mut vec_input = input.to_vec();
    vec_input.extend_from_slice(&padding);
    let out = openssl::symm::decrypt(openssl::symm::Cipher::aes_128_ecb(), key, None, &vec_input)?;

    // out.truncate(16);

    Ok(out)
}

pub fn decrypt_aes_128_ecb(input: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if input.len() % 16 != 0 {
        panic!(
            "Cipher length should be a multiple of 16, is {}.",
            input.len()
        );
    }

    let mut out = Vec::new();

    for block in input.to_vec().chunks(16) {
        out.extend_from_slice(&decrypt_aes_128_block(block, key)?);
    }

    Ok(out)
}

pub fn encrypt_aes_128_block(input: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    if input.len() != 16 {
        panic!("Input length should be 16, is {}.", input.len());
    }

    let mut out = openssl::symm::encrypt(openssl::symm::Cipher::aes_128_ecb(), key, None, input)?;

    out.truncate(16);

    Ok(out)
}

pub fn encrypt_aes_128_ecb(input: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let mut vec_input = input.to_vec();
    padding_pkcs7(&mut vec_input, 16)?;
    let mut out = Vec::new();

    for block in vec_input.chunks(16) {
        out.extend_from_slice(&encrypt_aes_128_block(block, key)?);
    }

    Ok(out)
}

pub fn encrypt_aes_128_cbc(input: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    if iv.len() != 16 {
        panic!("Invalid IV size, should be 16, is {}.", iv.len());
    }

    let mut vec_input = input.to_vec();
    padding_pkcs7(&mut vec_input, 16)?;
    let mut cipher = Vec::new();
    let mut previous = iv.to_vec();
    let mut current;

    println!("vec_input len: {}", vec_input.len());

    for block in vec_input.chunks(16) {
        current = encrypt_aes_128_ecb(&do_xor(&previous, block)?, key)?;
        cipher.extend_from_slice(&current);

        previous = current;
    }

    Ok(cipher)
}

pub fn decrypt_aes_128_cbc(input: &[u8], key: &[u8], iv: &[u8]) -> Result<Vec<u8>> {
    if iv.len() != 16 {
        panic!("Invalid IV size, should be 16, is {}.", iv.len());
    }

    if input.len() % 16 != 0 {
        panic!(
            "Invalid cipher size, should be multiple of 16, is {}.",
            input.len()
        );
    }

    let mut clear = Vec::new();
    let mut current;
    let mut previous = iv.to_vec();

    for block in input.to_vec().chunks(16) {
        current = do_xor(&previous, &decrypt_aes_128_ecb(block, key)?)?;
        clear.extend_from_slice(&current);

        previous = block.to_vec();
    }

    Ok(clear)
}
