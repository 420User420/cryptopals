extern crate aes_oracle;
extern crate base64;
extern crate cookie_oracle;

use aes_oracle::*;
use cookie_oracle::*;
use std::fs;
use std::str;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

pub fn do_xor(left: Vec<u8>, right: Vec<u8>) -> Result<Vec<u8>> {
    if right.len() != right.len() {
        panic!("Not same length {} - {}", left.len(), right.len());
    }

    let mut out_bytes: Vec<u8> = Vec::with_capacity(left.len());

    for i in 0..left.len() {
        out_bytes.push(left[i] ^ right[i]);
    }

    Ok(out_bytes)
}

pub fn do_single_xor(input: &Vec<u8>, k: u8) -> Result<Vec<u8>> {
    Ok(input.iter().map(|b| *b ^ k).collect())
}

pub fn crack_single_xor(input: &Vec<u8>, dict: &[f32; 256]) -> Result<(u8, f32)> {
    let mut max_score: f32 = 0.0f32;
    let mut key = 0u8;

    for k in 0..=255 {
        let xored = do_single_xor(input, k)?;
        let score = xored.iter().map(|b| dict[*b as usize]).sum();

        if score > max_score {
            max_score = score;
            key = k;
        }
    }

    Ok((key, max_score))
}

pub fn build_charstat_dict(path: &str) -> Result<[f32; 256]> {
    let file = fs::read_to_string(path)?;
    let mut out_dict = [0.0f32; 256];

    for c in file.bytes() {
        out_dict[c as usize] += 1.0f32;
    }

    for e in &mut out_dict {
        *e /= file.len() as f32;
    }

    Ok(out_dict)
}

pub fn do_vigenere(input: &Vec<u8>, key: &Vec<u8>) -> Result<Vec<u8>> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len());

    for i in 0..input.len() {
        out.push(input[i] ^ key[i % key.len()]);
    }

    Ok(out)
}

pub fn crack_vigenere(input: &[u8]) -> Result<Vec<u8>> {
    let dict = build_charstat_dict("./data/pride_and_prejudice.txt")?;
    let key_size = guess_key_size(&input)?;

    println!("Probable key size: {}", key_size);

    let mut vectors: Vec<Vec<u8>> = (0..key_size).map(|_| Vec::new()).collect();

    for chunk in input.chunks(key_size) {
        for (i, byte) in chunk.iter().enumerate() {
            vectors[i].push(*byte);
        }
    }

    let mut key = Vec::with_capacity(key_size);
    for vector in vectors {
        let (k, _) = crack_single_xor(&vector, &dict)?;
        key.push(k);
    }

    Ok(key)
}

pub fn guess_key_size(input: &[u8]) -> Result<usize> {
    let mut min_distance = f32::MAX;
    let mut best_key_size: usize = 0;

    for key_size in 2..40 {
        let chunks: Vec<&[u8]> = input.chunks(key_size).take(4).collect();

        let mut distance = 0.0f32;

        for i in 0..4 {
            for j in i..4 {
                distance += hamming_distance(chunks[i], chunks[j])? as f32;
            }
        }

        distance /= key_size as f32;

        if distance < min_distance {
            min_distance = distance;
            best_key_size = key_size;
        }
    }

    println!(
        "Guessed key size {} with min distance {}",
        best_key_size, min_distance
    );

    Ok(best_key_size)
}

pub fn hamming_distance(left: &[u8], right: &[u8]) -> Result<u32> {
    if left.len() != right.len() {
        panic!("Not same length: {} - {}", left.len(), right.len())
    }

    Ok((0..left.len())
        .map(|i| (left[i] ^ right[i]).count_ones())
        .sum())
}

pub fn decrypt_AES_128_ECB(input: &[u8], key: &[u8]) -> Result<Vec<u8>> {
    let cipher = openssl::symm::Cipher::aes_128_ecb();

    let out = openssl::symm::decrypt(cipher, key, None, input)?;

    Ok(out)
}

pub fn detect_ecb(input: &Vec<u8>) -> bool {
    let mut chunks: Vec<_> = input.chunks(16).collect();
    let len = chunks.len();
    chunks.sort();
    chunks.dedup();

    chunks.len() != len
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

pub fn detect_encryption_mode(oracle: &aes_oracle::AES_Oracle) -> Result<aes::MODE> {
    let input = [0u8; 48];

    let cipher = oracle.encrypt(&input)?;

    match detect_ecb(&cipher) {
        true => Ok(aes::MODE::ECB),
        false => Ok(aes::MODE::CBC),
    }
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

pub fn break_profile_oracle(oracle: &ProfileOracle) -> Result<String> {
    /*
     * aaaa aaaa aaaa aaaa
     * a@a.com&uid=1234
     *
     */

    let profile = oracle.profile_for("foo@bar.com");

    Ok(String::new())
}
