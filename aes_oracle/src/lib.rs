extern crate aes;
extern crate base64;
extern crate hex;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

use oracle::Oracle;
use rand::Rng;
use std::fmt;

pub struct AesOracle {
    pub mode: aes::MODE,
    key: [u8; 16],
    iv: Option<[u8; 16]>,
    suffix: Option<Vec<u8>>,
    prefix: Option<Vec<u8>>,
}

pub fn new(fixed_mode: Option<aes::MODE>, fixed_suffix: Option<&[u8]>) -> AesOracle {
    let mut rng = rand::thread_rng();

    let mode: aes::MODE;
    let mut key = [0u8; 16];
    let iv: Option<[u8; 16]>;
    // let mut suffix = Vec::new();
    // let mut prefix = Vec::new();
    let mut prefix: Option<Vec<u8>>;
    let mut suffix: Option<Vec<u8>>;

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

    match fixed_suffix {
        // If no suffix given, generate 5 to 10 random bytes as prefix and suffix.
        None => {
            let suffix_len = rng.gen_range(5..10);
            suffix = Some(Vec::new());
            for _ in 0..suffix_len {
                suffix.as_mut().unwrap().push(rng.gen::<u8>());
            }
            let prefix_len = rng.gen_range(5..10);
            prefix = Some(Vec::new());
            for _ in 0..prefix_len {
                prefix.as_mut().unwrap().push(rng.gen::<u8>());
            }
        }
        // Otherwise, put the given suffix and do not put any prefix.
        _ => {
            suffix = Some(fixed_suffix.unwrap().to_vec());
            prefix = None;
        }
    }

    return AesOracle {
        key,
        iv,
        mode,
        suffix,
        prefix,
    };
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
