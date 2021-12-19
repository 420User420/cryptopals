extern crate base64;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_challenge1() -> Result<()> {
        assert_eq!("SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t".to_string().to_owned(), challenge1(&"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d".to_string())?);

        Ok(())
    }

    #[test]
    fn test_challenge2() -> Result<()> {
        assert_eq!(
            "746865206b696420646f6e277420706c6179"
                .to_string()
                .to_owned(),
            challenge2(
                &"1c0111001f010100061a024b53535009181c".to_string(),
                &"686974207468652062756c6c277320657965".to_string()
            )?
        );

        Ok(())
    }
}

pub fn challenge1(input: &String) -> Result<String> {
    return base64::vec_u8_to_string(hex::string_to_vec_u8(input)?);
}

pub fn challenge2(left: &String, right: &String) -> Result<String> {
    let in_left = hex::string_to_vec_u8(left)?;
    let in_right = hex::string_to_vec_u8(right)?;

    if in_left.len() != in_right.len() {
        panic!("Not same length {} - {}", in_left.len(), in_right.len());
    }

    let mut out_bytes: Vec<u8> = Vec::with_capacity(in_left.len());

    for i in 0..in_left.len() {
        out_bytes.push(in_left[i] ^ in_right[i]);
    }

    return hex::vec_u8_to_string(out_bytes);
}
