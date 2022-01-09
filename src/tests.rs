use rust_cryptopals::*;
mod set1;
mod set2;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

#[cfg(test)]
mod tests_set1 {
    use super::*;

    #[test]
    fn test_hamming_distance() -> Result<()> {
        assert_eq!(hamming_distance(b"this is a test", b"wokka wokka!!!")?, 37);

        Ok(())
    }
}

#[cfg(test)]
mod tests_set2 {
    use super::*;
}
