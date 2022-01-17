extern crate aes;
extern crate aes_oracle;
extern crate cookie_oracle;

extern crate hex;

use aes::padding_pkcs7;
use oracle::Oracle;
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

    let plaintext = recover_ecb_suffix(&oracle)?;

    println!(
        "Answer of Set 2 Challenge 12: {}...",
        String::from_utf8(plaintext.as_slice()[0..20].to_vec())?
    );
    println!("---- [END] Challenge 12 ----");

    Ok(())
}

pub fn challenge13() -> Result<()> {
    let oracle = cookie_oracle::ProfileOracle::new();

    println!("---- [START] Challenge 13 ----");

    let block_size = detect_blocksize(&oracle)?;
    println!("Detected block size: {}", block_size);

    let prefix_len = detect_prefix_len(&oracle)?;
    println!("Prefix length: {}", prefix_len);

    let (nb_prefix_blocks, nb_prefix_padding) = aes::blocks_and_padding(prefix_len, block_size);
    let mut target = b"admin".to_vec();
    padding_pkcs7(&mut target, block_size)?;
    println!("Padded target: {:?}", target);
    let mut payload = vec![0; nb_prefix_padding];
    payload.extend_from_slice(&target);

    let target_last_block = &oracle
        .encrypt(&payload)?
        .split_off(nb_prefix_blocks * block_size)[0..block_size];

    let presuflen = detect_prefix_plus_suffix_len(&oracle)?;
    println!("Prefix + suffix len: {}", presuflen);
    let (chunks_count, fill_len) = aes::blocks_and_padding(presuflen, block_size);
    let mut forged_profile = oracle.encrypt(&vec![0; fill_len + "user".len()])?;

    println!(
        "Should be equal: {} == {}",
        (chunks_count + 1) * block_size,
        forged_profile.len()
    );

    forged_profile[chunks_count * block_size..].copy_from_slice(target_last_block);

    let ex_cipher = &oracle.encrypt(b"user420@example.com")?;
    let ex_profile = &oracle.profile_from_encrypted(&ex_cipher)?;

    println!("Example profile:\n{}", ex_profile);

    let dprofile = oracle.profile_from_encrypted(&forged_profile)?;

    println!("Forged profile: {}", dprofile);
    println!("Forged is admin: {}", dprofile.is_admin());

    println!("---- [END] Challenge 13 ----");
    Ok(())
}
