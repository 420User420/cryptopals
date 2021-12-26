// mod set1;
extern crate aes;
extern crate aes_oracle;
extern crate hex;

use aes_oracle::*;

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

pub fn challenge11() -> Result<()> {
    let oracle = aes_oracle::new();

    println!("Oracle:\n{}", oracle);

    Ok(())
}
