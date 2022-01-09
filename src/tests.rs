type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

#[cfg(test)]
mod tests_set1 {
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

    #[test]
    fn test_challenge3() -> Result<()> {
        let decrypted =
            challenge3("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")?;

        println!("Decrypted: {}", decrypted);
        Ok(())
    }

    #[test]
    fn test_challenge5() -> Result<()> {
        assert_eq!("0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f", challenge5(&"Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal".as_bytes().to_vec(), &"ICE".as_bytes().to_vec())?);
        Ok(())
    }

    #[test]
    fn test_hamming_distance() -> Result<()> {
        assert_eq!(hamming_distance(b"this is a test", b"wokka wokka!!!")?, 37);

        Ok(())
    }
}

#[cfg(test)]
mod tests_set2 {
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
