extern crate aes;
extern crate aes_oracle;
extern crate cookie_oracle;

extern crate hex;

use aes_oracle::*;
use rust_cryptopals::*;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

pub fn challenge09() -> Result<()> {
    let mut input = b"YELLOW SUBMARINE".to_vec();

    aes::padding_pkcs7(&mut input, 20)?;

    println!("Challenge 09: {:?}", String::from_utf8(input)?);

    Ok(())
}

pub fn challenge10() -> Result<()> {
    let key = b"YELLOW SUBMARINE";
    let input = base64::file_to_vec_u8("data/set_2_challenge_10.txt")?;
    let iv = [0u8; 16];

    let clear = aes::decrypt_aes_128_cbc(&input, key, &iv)?;

    println!("---- [START] Challenge 10 ----");
    println!(
        "Answer of Set 2 Challenge 10: {}...",
        String::from_utf8(clear.as_slice()[0..20].to_vec())?
    );
    println!("---- [END] Challenge 10 ----");

    Ok(())
}

pub fn challenge11() -> Result<()> {
    let oracle = aes_oracle::new(None, None);

    let mode = detect_encryption_mode(&oracle)?;

    println!("---- [START] Challenge 11 ----");
    println!("Oracle:\n{}", oracle);
    println!("Detected: {}", mode);
    println!("---- [END] Challenge 11 ----");

    Ok(())
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
    match detect_ecb(&oracle.encrypt(&ecb_payload)?) {
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
        let payload = vec![0u8; block_size - plaintext.len() % block_size - 1];
        // Get the first block out of the cipher
        let start = plaintext.len() / block_size * block_size;
        let block = &oracle.encrypt(&payload)?[start..start + block_size];
        // Add found byte to plaintext
        let found_char = find_char_in_dict(&dict, &block)?;
        plaintext.push(found_char);
    }

    println!(
        "Answer of Set 2 Challenge 12: {}...",
        String::from_utf8(plaintext.as_slice()[0..20].to_vec())?
    );
    println!("---- [END] Challenge 12 ----");

    Ok(())
}

pub fn challenge13() -> Result<()> {
    let oracle = cookie_oracle::ProfileOracle::new();

    Ok(())
}
