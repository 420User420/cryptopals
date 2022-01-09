extern crate base64;

use rust_cryptopals::*;
use std::fs::File;
use std::io::{prelude::*, BufReader};
use std::str;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

pub fn challenge1() -> Result<()> {
    let input = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    println!(
        "Answer of Set1 Challenge1: {}",
        base64::vec_u8_to_string(hex::string_to_vec_u8(input)?)?
    );

    Ok(())
}

pub fn challenge2() -> Result<()> {
    let left = "1c0111001f010100061a024b53535009181c";
    let right = "686974207468652062756c6c277320657965";
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

    println!(
        "Answer of Set1 challenge2: {}",
        hex::vec_u8_to_string(out_bytes)
    );

    Ok(())
}

pub fn challenge3() -> Result<()> {
    let input = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";

    // let dict = build_charstat_dict("data/pride_and_prejudice.txt")?;
    let dict = build_charstat_dict("data/alice_wonderlands.txt")?;
    let (key, _) = crack_single_xor(&hex::string_to_vec_u8(input)?, &dict)?;

    println!(
        "Answer of Set1 challenge3: {}",
        String::from_utf8(do_single_xor(&hex::string_to_vec_u8(input)?, key,)?)?
    );

    Ok(())
}

pub fn challenge4() -> Result<()> {
    let path = "data/set_1_challenge_4.txt";
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

    println!("XORed line number: {}", xored_line_number);
    println!("XORed line raw: {}", xored_line);
    println!("Max scored key: {}", max_key);
    println!(
        "Decoded line: {}",
        String::from_utf8(do_single_xor(
            &hex::string_to_vec_u8(&xored_line)?,
            max_key
        )?)?
    );

    Ok(())
}

pub fn challenge5() -> Result<()> {
    let input = "Burning 'em, if you ain't quick and nimble I go crazy when I hear a cymbal";
    let key = "ICE";

    println!(
        "Answer of Set1 challenge5: {}",
        hex::vec_u8_to_string(do_vigenere(
            &input.as_bytes().to_vec(),
            &key.as_bytes().to_vec()
        )?)
    );

    Ok(())
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

pub fn challenge7() -> Result<()> {
    let input = base64::file_to_vec_u8("data/set_1_challenge_7.txt")?;
    let key = b"YELLOW SUBMARINE";

    let out = decrypt_aes_128_ecb(&input, key)?;

    println!(
        "Answer of Set 1 Challenge 7: {}",
        str::from_utf8(&out).to_owned()?.to_string()
    );

    Ok(())
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
