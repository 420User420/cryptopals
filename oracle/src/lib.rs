extern crate aes;
extern crate base64;
extern crate hex;

use aes::padding_pkcs7;
use rand::Rng;
use std::fmt;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

pub trait Oracle {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn decrypt(&self, _data: &[u8]) -> Result<Vec<u8>> {
        Ok(Vec::new())
    }
}

pub struct AesOracle {
    pub mode: aes::MODE,
    key: [u8; 16],
    iv: Option<[u8; 16]>,
    suffix: Option<Vec<u8>>,
    prefix: Option<Vec<u8>>,
}

impl AesOracle {
    pub fn new(fixed_mode: Option<aes::MODE>) -> AesOracle {
        let mut rng = rand::thread_rng();

        let mode: aes::MODE;
        let mut key = [0u8; 16];
        let iv: Option<[u8; 16]>;

        for i in 0..16 {
            key[i] = rng.gen();
        }

        // If given a mode, set it, otherwise randomly choose it.
        if fixed_mode.is_none() {
            match rng.gen_range(0..2) {
                0u32 => mode = aes::MODE::ECB,
                1u32 => mode = aes::MODE::CBC,
                _ => panic!("Expected random value to be either 0 or 1."),
            }
        } else {
            mode = fixed_mode.unwrap();
        }

        // If we are in CBC, generate a random 16 bytes IV
        match mode {
            aes::MODE::ECB => iv = None,
            aes::MODE::CBC => {
                let mut val = [0u8; 16];
                for i in 0..16 {
                    val[i] = rng.gen();
                }
                iv = Some(val);
            }
        }

        AesOracle {
            key,
            iv,
            mode,
            prefix: None,
            suffix: None,
        }
    }
}

impl Oracle for AesOracle {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        let mut true_data = Vec::new();
        match &self.prefix {
            Some(b) => {
                true_data.extend(b);
            }
            None => {}
        }

        true_data.extend_from_slice(data);

        match &self.suffix {
            Some(b) => {
                true_data.extend(b);
            }
            None => {}
        }

        match self.mode {
            aes::MODE::ECB => return aes::encrypt_aes_128_ecb(&true_data, &self.key),
            aes::MODE::CBC => {
                return aes::encrypt_aes_128_cbc(&true_data, &self.key, &self.iv.unwrap())
            }
        }
    }

    fn decrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self.mode {
            aes::MODE::ECB => aes::decrypt_aes_128_ecb(data, &self.key),
            aes::MODE::CBC => aes::decrypt_aes_128_cbc(data, &self.key, &self.iv.unwrap()),
        }
    }
}

impl fmt::Display for AesOracle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.mode {
            aes::MODE::ECB => write!(
                f,
                "KEY: {}\nMODE: {}",
                hex::vec_u8_to_string(self.key.to_vec()),
                self.mode,
            ),
            aes::MODE::CBC => write!(
                f,
                "KEY: {}\nIV: {}\nMODE: {}",
                hex::vec_u8_to_string(self.key.to_vec()),
                hex::vec_u8_to_string(self.iv.unwrap().to_vec()),
                self.mode,
            ),
        }
    }
}

/// Suffix only oracle
pub struct OracleChallenge12 {
    aes_oracle: AesOracle,
}

impl OracleChallenge12 {
    pub fn new() -> Result<Self> {
        let suffix = base64::string_to_vec_u8(
            "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\
YnkK",
        )?;

        let mut aes_oracle = AesOracle::new(Some(aes::MODE::ECB));
        aes_oracle.suffix = Some(suffix);

        Ok(OracleChallenge12 { aes_oracle })
    }
}

impl Oracle for OracleChallenge12 {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.aes_oracle.encrypt(data)
    }
}

/// Cookie Oracle
/// TODO: Somehow implement the parsing/encoding of the Profile object
pub struct OracleChallenge13 {
    aes_oracle: AesOracle,
}

impl OracleChallenge13 {
    pub fn new() -> Result<Self> {
        // Generate the prefix
        let prefix = Some(b"email=".to_vec());

        // Generate the suffix
        let mut rng = rand::thread_rng();
        let uid = rng.gen::<u32>();
        let suffix = Some(format!("&uid={}&role=user", uid).as_bytes().to_vec());

        // Generate the AES Oracle
        let mut aes_oracle = AesOracle::new(Some(aes::MODE::ECB));

        // Set the prefix and suffix
        aes_oracle.prefix = prefix;
        aes_oracle.suffix = suffix;

        Ok(OracleChallenge13 { aes_oracle })
    }

    pub fn verify(&self, _: &[u8]) -> Result<bool> {
        Ok(true)
    }
}

impl Oracle for OracleChallenge13 {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        // Check that data (email) is ascii and does not contain cheating characters '&' or '='
        if data
            .iter()
            .any(|&c| !c.is_ascii() || c == b'&' || c == b'=')
        {
            panic!("Invalid input");
        }
        self.aes_oracle.encrypt(data)
    }
}

pub struct OracleChallenge14 {
    aes_oracle: AesOracle,
}

impl OracleChallenge14 {
    pub fn new() -> Result<Self> {
        let mut rng = rand::thread_rng();

        let mode = aes::MODE::ECB;

        let mut key = [0u8; 16];
        for i in 0..16 {
            key[i] = rng.gen();
        }

        let suffix = base64::string_to_vec_u8("Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK")?;

        let prefix_len = rng.gen_range(5..25);
        let mut prefix = vec![0u8; prefix_len];
        for i in 0..prefix_len {
            prefix[i] = rng.gen();
        }

        Ok(OracleChallenge14 {
            aes_oracle: AesOracle {
                mode,
                key,
                iv: None,
                prefix: Some(prefix),
                suffix: Some(suffix),
            },
        })
    }
}

impl Oracle for OracleChallenge14 {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        self.aes_oracle.encrypt(data)
    }
}

/*               SET 3                   */

const CHALL17_STRINGS: [&str; 10] = [
    "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=",
    "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=",
    "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==",
    "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==",
    "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl",
    "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==",
    "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==",
    "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=",
    "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=",
    "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93",
];

pub struct OracleChallenge17 {
    aes_oracle: AesOracle,
}

impl OracleChallenge17 {
    pub fn new() -> Result<Self> {
        let mut aes_oracle = AesOracle::new(Some(aes::MODE::CBC));

        let mut rng = rand::thread_rng();

        let i = rng.gen_range(0..10);
        let mut s = base64::string_to_vec_u8(CHALL17_STRINGS[i])?;
        padding_pkcs7(&mut s, 16)?;

        aes_oracle.suffix = Some(s);

        Ok(OracleChallenge17 { aes_oracle })
    }

    pub fn check_cipher_padding(&self, cipher: &[u8]) -> Result<bool> {
        let clear = self.aes_oracle.decrypt(cipher)?;

        Ok(aes::padding_is_valid(&clear, 16))
    }
}

impl Oracle for OracleChallenge17 {
    fn encrypt(&self, _: &[u8]) -> Result<Vec<u8>> {
        self.aes_oracle.encrypt(&[])
    }
}
