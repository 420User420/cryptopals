extern crate aes;
extern crate aes_oracle;
extern crate hex;

use crate::set1::detect_ecb;
use aes_oracle::*;
use rand::Rng;
use std::borrow::Cow;
use std::fmt;
use std::io::{Read, Write};
use std::{thread, time};
use url::Url;

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
        let payload = vec![0u8; block_size - plaintext.len() % block_size - 1];
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

fn detect_blocksize(oracle: &aes_oracle::AES_Oracle) -> Result<usize> {
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

pub fn challenge13() -> Result<()> {
    let profile = profile_for("foo@bar.com")?;

    println!("Profile: {}", profile.encode()?);
    println!("Profile admin: {}", profile.is_admin());
    println!("Profile enc: {}", profile.encrypt()?);

    let profile1 = Profile::from_encoded(&profile.encode()?)?;

    println!("Profile1: {}", profile1.encode()?);
    println!("Profile1 admin: {}", profile1.is_admin());

    Ok(())
}

#[derive(PartialEq)]
enum Role {
    User,
    Admin,
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            Role::User => write!(f, "user"),
            Role::Admin => write!(f, "admin"),
        }
    }
}

impl Role {
    pub fn from_string(s: &str) -> Result<Role> {
        match s {
            "admin" => Ok(Role::Admin),
            "user" => Ok(Role::User),
            _ => panic!("Invalid role string: {}", s),
        }
    }
}

struct Profile {
    email: String,
    uid: u32,
    role: Role,
    key: Option<[u8; 16]>,
}

impl Profile {
    fn encode(&self) -> Result<String> {
        Ok(format!(
            "email={}&uid={}&role={}",
            self.email, self.uid, self.role
        ))
    }

    pub fn is_admin(&self) -> bool {
        self.role == Role::Admin
    }

    pub fn from_encoded(encoded: &str) -> Result<Profile> {
        let url_obj = Url::parse(&format!("https://example.com/?{}", encoded))?;
        let mut pairs = url_obj.query_pairs();
        let mut email = String::new();
        let mut uid = 0u32;
        let mut role = Role::User;

        for (k, v) in pairs {
            match k {
                Cow::Borrowed("email") => email = v.into_owned(),
                Cow::Borrowed("uid") => uid = v.into_owned().parse::<u32>()?,
                Cow::Borrowed("role") => role = Role::from_string(v.as_ref())?,
                _ => panic!("Invalid key found in encoded profile: {}", k),
            }
        }

        Ok(Profile {
            email,
            uid,
            role,
            key: None,
        })
    }

    fn encrypt(&self) -> Result<String> {
        if self.key.is_none() {
            panic!("Cannot encrypt profile because it has no key.")
        }

        Ok(hex::vec_u8_to_string(aes::encrypt_aes_128_ecb(
            &self.encode()?.as_bytes(),
            &self.key.unwrap(),
        )?))
    }
}

fn profile_for(email: &str) -> Result<Profile> {
    let mut rng = rand::thread_rng();
    let mut key = [0u8; 16];
    for i in 0..16 {
        key[i] = rng.gen();
    }
    let uid = rng.gen();
    Ok(Profile {
        email: email.to_string().replace("&", "").replace("=", ""),
        uid,
        role: Role::User,
        key: Some(key),
    })
}
