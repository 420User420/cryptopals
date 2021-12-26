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
    pub key: [u8; 16],
    pub iv: Option<[u8; 16]>,
}

pub trait Oracle {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>>;
}

pub fn new() -> AES_Oracle {
    let mut rng = rand::thread_rng();

    let mode: aes::MODE;
    let mut key = [0u8; 16];
    let iv: Option<[u8; 16]>;

    for i in 0..16 {
        key[i] = rng.gen();
    }

    match rng.gen_range(0..2) {
        0u32 => mode = aes::MODE::ECB,
        1u32 => mode = aes::MODE::CBC,
        _ => panic!("Expected random value to be either 0 or 1."),
    }

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

    return AES_Oracle { key, iv, mode };
}
impl Oracle for AES_Oracle {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>> {
        match self.mode {
            aes::MODE::ECB => return aes::encrypt_aes_128_ecb(data, &self.key),
            aes::MODE::CBC => return aes::encrypt_aes_128_cbc(data, &self.key, &self.iv.unwrap()),
        }
    }
}

impl fmt::Display for AES_Oracle {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.mode {
            aes::MODE::ECB => write!(
                f,
                "KEY: {}\nMODE: {}\n",
                hex::vec_u8_to_string(self.key.to_vec()),
                self.mode
            ),
            aes::MODE::CBC => write!(
                f,
                "KEY: {}\nIV: {}\nMODE: {}\n",
                hex::vec_u8_to_string(self.key.to_vec()),
                hex::vec_u8_to_string(self.iv.unwrap().to_vec()),
                self.mode
            ),
        }
    }
}
