type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

use std::fs::File;
use std::io::{prelude::*, BufReader};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_string_to_vec_u8() -> Result<()> {
        assert_eq!(
            "Bonjour\n",
            String::from_utf8(string_to_vec_u8("Qm9uam91cgo=")?).unwrap()
        );

        Ok(())
    }

    #[test]
    fn test_vec_u8_to_string() -> Result<()> {
        assert_eq!(
            vec_u8_to_string(vec![66, 111, 110, 106, 111, 117, 114, 10])?,
            "Qm9uam91cgo="
        );

        Ok(())
    }
}

pub fn string_to_vec_u8(s: &str) -> Result<Vec<u8>> {
    if s.len() % 4 != 0 {
        return Err(format!(
            "Input base64 string length must be a multiple of 4, is: {}",
            s.len()
        )
        .into());
    }

    let mut out_length = s.len();
    if s.as_bytes()[out_length - 1] == b'=' {
        if s.as_bytes()[out_length - 2] == b'=' {
            out_length -= 1;
        }
        out_length -= 1;
    }

    let mut as_bytes = Vec::with_capacity(out_length);

    for c in s.chars().take(out_length) {
        as_bytes.push(b64char_to_u8(c)?);
    }

    let mut out_vec = Vec::with_capacity((out_length * 6) / 8);
    for chunk_of_4 in as_bytes.chunks(4) {
        // First byte is the 6 bits of the first char | the 2 first bits of the 2nd char
        out_vec.push((chunk_of_4[0] << 2) | (chunk_of_4[1] >> 4));
        if chunk_of_4.len() == 2 {
            if (chunk_of_4[1] << 4) != 0 {
                return Err("Input not padded with zeros.".into());
            }
            break;
        }

        // Second byte is 4 last bits of the 2nd char | the 4 first bits of the 3rd char
        out_vec.push((chunk_of_4[1] << 4) | (chunk_of_4[2] >> 2));
        if chunk_of_4.len() == 3 {
            if (chunk_of_4[2] << 6) != 0 {
                return Err("Input not padded with zeros.".into());
            }
            break;
        }

        // Third byte is 2 last bits of the 3rd char | the 6 bits of the 4th char
        out_vec.push((chunk_of_4[2] << 6) | chunk_of_4[3]);
    }

    Ok(out_vec)
}

fn b64char_to_u8(c: char) -> Result<u8> {
    match c {
        'A'..='Z' => Ok(c as u8 - b'A'),
        'a'..='z' => Ok(26 + (c as u8 - b'a')),
        '0'..='9' => Ok(52 + (c as u8 - b'0')),
        '+' => Ok(62),
        '/' => Ok(63),
        _ => Err(format!("Invalid base64 character {}", c).into()),
    }
}

pub fn vec_u8_to_string(vec: Vec<u8>) -> Result<String> {
    let mut out_string = String::with_capacity(vec.len() + (4 - vec.len() % 4));

    for chunk_of_3 in vec.chunks(3) {
        out_string.push(u8_to_b64char(chunk_of_3[0] >> 2)?);
        if chunk_of_3.len() == 1 {
            out_string.push(u8_to_b64char((chunk_of_3[0] & 0x03) << 4)?);
            out_string.push('=');
            out_string.push('=');
            break;
        }

        out_string.push(u8_to_b64char(
            ((chunk_of_3[0] & 0x03) << 4) | (chunk_of_3[1] >> 4),
        )?);
        if chunk_of_3.len() == 2 {
            out_string.push(u8_to_b64char((chunk_of_3[1] & 0x0f) << 2)?);
            out_string.push('=');
            break;
        }

        out_string.push(u8_to_b64char(
            (chunk_of_3[1] & 0x0f) << 2 | (chunk_of_3[2] >> 6),
        )?);
        out_string.push(u8_to_b64char(chunk_of_3[2] & 0x3f)?);
    }

    Ok(out_string)
}

fn u8_to_b64char(b: u8) -> Result<char> {
    match b {
        0..=25 => Ok((b + b'A') as char),
        26..=51 => Ok(((b - 26) + b'a') as char),
        52..=61 => Ok(((b - 52) + b'0') as char),
        62 => Ok('+'),
        63 => Ok('/'),
        _ => Err(format!("Invalid byte {}.", b).into()),
    }
}

pub fn file_to_vec_u8(path: &str) -> Result<Vec<u8>> {
    let mut content = String::new();
    let file = File::open(&path)?;
    let reader = BufReader::new(file);
    for line in reader.lines() {
        content.push_str(line.unwrap().trim());
    }

    return string_to_vec_u8(&content);
}
