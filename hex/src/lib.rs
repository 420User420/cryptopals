use std::char;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn test_string_to_vec_u8() -> Result<()> {
        assert_eq!(vec![1, 2, 3], string_to_vec_u8("010203")?);
        assert_eq!(vec![128, 255], string_to_vec_u8("80ff")?);

        Ok(())
    }
}

pub fn string_to_vec_u8(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(format!("Input length is odd, should be even {}", s.len()).into());
    }

    let mut as_bytes = Vec::with_capacity(s.len());
    for c in s.chars() {
        as_bytes.push(hexchar_to_u8(c)?);
    }

    Ok(as_bytes
        .chunks(2)
        .map(|p| (p[0] << 4) | p[1])
        .collect::<Vec<u8>>())
}

fn hexchar_to_u8(c: char) -> Result<u8> {
    match c.to_digit(16) {
        Some(i) => Ok(i as u8),
        _ => Err(format!("Invalid character (not hex): {}", c).into()),
    }
}

pub fn vec_u8_to_string(vec: Vec<u8>) -> Result<String> {
    let mut out_string = String::with_capacity(vec.len() * 2);
    for b in vec {
        out_string.push((b >> 4) as char);
        out_string.push((b & 0x0f) as char);
    }

    Ok(out_string)
}
