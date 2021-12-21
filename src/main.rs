mod set1;

use crate::set1::*;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

fn main() -> Result<()> {
    let set1_chall1 = challenge1(&"49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d".to_string())?;
    println!("Answer of Set1 challenge1: {}", set1_chall1);

    let set1_chall2 = challenge2(
        &"1c0111001f010100061a024b53535009181c".to_string(),
        &"686974207468652062756c6c277320657965".to_string(),
    )?;
    println!("Answer of Set1 challenge2: {}", set1_chall2);

    let set1_chall3 =
        challenge3("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736")?;
    println!("Answer of Set1 challenge3: {}", set1_chall3);

    let (line_number, line, key) = challenge4("data/set_1_challenge_4.txt")?;
    println!(
        "Answer of Set1 challenge4: #{} - {} - Key: {}",
        line_number, line, key
    );
    println!("Decoded of Set1 challenge4: {}", challenge3(&line)?);

    let set1_chall5 = challenge5(
        &"Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal"
            .as_bytes()
            .to_vec(),
        &"ICE".as_bytes().to_vec(),
    )?;
    println!("Answer of Set1 challenge5: {}", set1_chall5);

    let set1_chall6 = challenge6()?;

    let set1_chall7  = challenge7()?;

    let set1_chall8 = challenge8()?;

    Ok(())
}
