extern crate aes;
extern crate aes_oracle;
extern crate hex;

use crate::set1::detect_ecb;
use aes_oracle::*;
use std::io::{Read, Write};
use std::{thread, time};

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge09() -> Result<()> {
        let mut input: Vec<u8> = vec![0, 1, 2, 3, 4];
        aes::padding_pkcs7(&mut input, 8)?;

        assert_eq!([0, 1, 2, 3, 4, 3, 3, 3].as_ref(), input);

        Ok(())
    }

    #[test]
    fn test_challenge10() -> Result<()> {
        Ok(())
    }

    #[test]
    fn test_challenge11() -> Result<()> {
        for _ in 0..500 {
            let oracle = aes_oracle::new(None, None);
            let mode = detect_encryption_mode(&oracle)?;

            assert_eq!(oracle.mode, mode);
        }

        Ok(())
    }
}

pub fn challenge09() -> Result<String> {
    let mut input = b"YELLOW SUBMARINE".to_vec();

    aes::padding_pkcs7(&mut input, 20)?;

    Ok(String::from_utf8(input)?)
}

pub fn challenge10() -> Result<String> {
    let key = b"YELLOW SUBMARINE";
    let input = base64::file_to_vec_u8("data/set_2_challenge_10.txt")?;
    let iv = [0u8; 16];

    let clear = aes::decrypt_aes_128_cbc(&input, key, &iv)?;

    Ok(String::from_utf8(clear)?)
}

pub fn challenge11() -> Result<aes::MODE> {
    let oracle = aes_oracle::new(None, None);
    let mode = detect_encryption_mode(&oracle)?;

    println!("---- [START] Challenge 12 ----");
    println!("Oracle:\n{}", oracle);
    println!("Detected: {}", mode);
    println!("---- [END] Challenge 12 ----");

    Ok(mode)
}

pub fn detect_encryption_mode(oracle: &aes_oracle::AES_Oracle) -> Result<aes::MODE> {
    let input = [0u8; 48];

    let cipher = oracle.encrypt(&input)?;

    match crate::set1::detect_ecb(&cipher) {
        true => Ok(aes::MODE::ECB),
        false => Ok(aes::MODE::CBC),
    }
}

pub fn challenge12() -> Result<()> {
    let suffix = base64::string_to_vec_u8("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")?;

    let oracle = aes_oracle::new(Some(aes::MODE::ECB), Some(&suffix));

    println!("---- [START] Challenge 12 ----");
    println!("Oracle:\n{}", oracle);

    let block_size = detect_blocksize(&oracle)?;
    println!("Detected block size: {}", block_size);

    // Craft and cipher a 3 times the block size same bytes payload and use it to detect ECB
    let ecb_payload = vec![0u8; 3 * block_size];
    match crate::set1::detect_ecb(&oracle.encrypt(&ecb_payload)?) {
        true => {
            println!("Oracle is in ECB mode.");
        }
        false => panic!("Oracle should be ECB and was not detected as such."),
    }

    let mut plaintext: Vec<u8> = Vec::new();

    let dict = build_dict(&plaintext, &oracle, block_size)?;
    let payload = vec![0u8; block_size - 1];
    let c = oracle.encrypt(&payload)?[0..block_size].to_vec();
    let first_byte = find_char_in_dict(&dict, &c)?;

    println!("First byte: {} - {}", first_byte as char, first_byte);

    while plaintext.len() < suffix.len() {
        // Build the guessing dictionary
        let dict = build_dict(&plaintext, &oracle, block_size)?;
        // Build the payload
        let payload = vec![0u8; (block_size - plaintext.len() % block_size - 1)];
        // Get the first block out of the cipher
        let start = plaintext.len() / block_size * block_size;
        let block = &oracle.encrypt(&payload)?[start..start + block_size];
        // Add found byte to plaintext
        let found_char = find_char_in_dict(&dict, &block)?;
        plaintext.push(found_char);
        // Print
        print!("{}", found_char as char);
        std::io::stdout().flush().expect("some error message");
        thread::sleep(time::Duration::from_millis(10));
    }

    println!();
    println!("---- [END] Challenge 12 ----");

    Ok(())
}

pub fn find_char_in_dict(dict: &Vec<Vec<u8>>, block: &[u8]) -> Result<u8> {
    // Run through the guessing dict and find which byte it was
    for i in 0..256 {
        let mut good = true;
        for (j, byte) in block.iter().enumerate() {
            if *byte != dict[i][j] {
                good = false;
                break;
            }
        }
        if good == true {
            return Ok(i as u8);
        }
    }

    panic!("Could not find next byte.")
}

pub fn build_dict(known: &Vec<u8>, oracle: &AES_Oracle, block_size: usize) -> Result<Vec<Vec<u8>>> {
    let mut out = vec![Vec::new(); 256];
    let mut block = vec![0u8; block_size];

    block.extend_from_slice(known);
    block.push(0u8);
    block = block.iter().cloned().rev().take(block_size).rev().collect();

    for i in 0..256 {
        block[block_size - 1] = i as u8;
        out[i] = oracle.encrypt(&block)?[0..block_size].to_vec();
    }

    Ok(out)
}

pub fn detect_blocksize(oracle: &aes_oracle::AES_Oracle) -> Result<usize> {
    let mut payload = Vec::new();

    // Get the size of the initial cipher
    let zero_len = oracle.encrypt(&payload)?.len();
    /*
    xxxx xxxx x___      -> 12
    --------------
    xxxx xxxx xa__      -> 12
    xxxx xxxx xaa_      -> 12
    xxxx xxxx xaaa      -> 12
    xxxx xxxx xaaa a___ -> 16
    --------------
    Block size: 16 - 12 = 4
     */
    loop {
        // Then, cipher after adding bytes until the size of the cipher is
        // is different than the initial cipher's length, it means that we reached
        // the padding size and hence that we can guess the block size.
        payload.push(0u8);
        let len = oracle.encrypt(&payload)?.len();

        if len != zero_len {
            return Ok(len - zero_len);
        }
    }
}
