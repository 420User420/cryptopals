extern crate base64;

use crate::cryptopals::*;

use std::fs::File;
use std::io::{prelude::*, BufReader};
use std::str;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

pub fn challenge1(input: &String) -> Result<String> {
    return base64::vec_u8_to_string(hex::string_to_vec_u8(input)?);
}

pub fn challenge2(left: &String, right: &String) -> Result<String> {
    let left_bytes = hex::string_to_vec_u8(left)?;
    let right_bytes = hex::string_to_vec_u8(right)?;

    if right_bytes.len() != right_bytes.len() {
        panic!(
            "Not same length {} - {}",
            left_bytes.len(),
            right_bytes.len()
        );
    }

    let out_bytes = do_xor(left_bytes, right_bytes)?;

    Ok(hex::vec_u8_to_string(out_bytes))
}

pub fn challenge3(input: &str) -> Result<String> {
    // let dict = build_charstat_dict("data/pride_and_prejudice.txt")?;
    let dict = build_charstat_dict("data/alice_wonderlands.txt")?;
    let (key, _) = crack_single_xor(&hex::string_to_vec_u8(input)?, &dict)?;

    /*
        let bonus = "ETAOIN SHRDLU".as_bytes().to_vec();
        let bonus_clear = do_single_xor(&bonus, key)?;
        println!("Bonus of Set1 challenge3: {}", str::from_utf8(&bonus_clear)?);
    */

    Ok(String::from_utf8(do_single_xor(
        &hex::string_to_vec_u8(input)?,
        key,
    )?)?)
}

pub fn challenge4(path: &str) -> Result<(usize, String, u8)> {
    let mut max_score = 0.0f32;
    let mut max_key = 0u8;
    let mut xored_line_number = 0;
    let mut xored_line = String::new();

    let file = File::open(path)?;
    let dict = build_charstat_dict("./data/alice_wonderlands.txt")?;
    let reader = BufReader::new(file);

    for (line_number, line) in reader.lines().enumerate() {
        let as_bytes = hex::string_to_vec_u8(&line.as_ref().unwrap())?;
        let (key, score) = crack_single_xor(&as_bytes, &dict)?;
        if score > max_score {
            max_score = score;
            xored_line = line.unwrap();
            max_key = key;
            xored_line_number = line_number;
        }
    }

    Ok((xored_line_number, xored_line, max_key))
}

pub fn challenge5(input: &Vec<u8>, key: &Vec<u8>) -> Result<String> {
    Ok(hex::vec_u8_to_string(do_vigenere(input, key)?))
}

pub fn challenge6() -> Result<()> {
    let input = base64::file_to_vec_u8("./data/set_1_challenge_6.txt")?;
    let key = crack_vigenere(&input)?;
    let plain = do_vigenere(&input, &key)?;

    println!("Key: {}", str::from_utf8(&key).to_owned()?.to_string());
    println!(
        "Decrypted: {}",
        str::from_utf8(&plain).to_owned()?.to_string()
    );

    Ok(())
}

pub fn challenge7() -> Result<String> {
    let input = base64::file_to_vec_u8("data/set_1_challenge_7.txt")?;
    let key = b"YELLOW SUBMARINE";

    let out = decrypt_AES_128_ECB(&input, key)?;

    Ok(str::from_utf8(&out).to_owned()?.to_string())
}

pub fn challenge8() -> Result<()> {
    let file = File::open("data/set_1_challenge_8.txt")?;
    let reader = BufReader::new(file);

    for (line_number, line) in reader.lines().map(|line| line.unwrap()).enumerate() {
        let as_bytes = hex::string_to_vec_u8(&line)?;
        if detect_ecb(&as_bytes) == true {
            println!(
                "Line #{} contains duplicate blocks: {}",
                line_number + 1,
                line
            );
        }
    }

    Ok(())
}

/*
    Line #133
d880619740a8a19b7840a8a31c810a3d
08649af70dc06f4fd5d2d69c744cd283 <
e2dd052f6b641dbf9d11b0348542bb57
08649af70dc06f4fd5d2d69c744cd283 <
9475c9dfdbc1d46597949d9c7e82bf5a
08649af70dc06f4fd5d2d69c744cd283 <
97a93eab8d6aecd566489154789a6b03
08649af70dc06f4fd5d2d69c744cd283 <
d403180c98c8f6db1f2a3f9c4040deb0
ab51b29933f2c123c58386b06fba186a
 */
