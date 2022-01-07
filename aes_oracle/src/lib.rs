extern crate aes;
extern crate hex;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

use rand::Rng;
use std::fmt;

#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

pub struct AES_Oracle {
    pub mode: aes::MODE,
    key: [u8; 16],
    iv: Option<[u8; 16]>,
    suffix: Option<Vec<u8>>,
    prefix: Option<Vec<u8>>,
}

pub trait Oracle {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>>;
}

pub fn new(fixed_mode: Option<aes::MODE>, fixed_suffix: Option<&[u8]>) -> AES_Oracle {
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
            iv = some(val);
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

    return AES_Oracle {
        key,
        iv,
        mode,
        suffix,
        prefix,
    };
}

impl Oracle for AES_Oracle {
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

impl fmt::Display for AES_Oracle {
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
