mod set1;
mod set2;

use crate::set1::*;
use crate::set2::*;

type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

fn main() -> Result<()> {
    set1()?;
    set2()?;

    Ok(())
}

fn set1() -> Result<()> {
    challenge1()?;
    challenge2()?;
    challenge3()?;
    challenge4()?;
    challenge5()?;
    challenge6()?;
    challenge7()?;
    challenge8()?;

    Ok(())
}

fn set2() -> Result<()> {
    challenge09()?;
    challenge10()?;
    challenge11()?;
    challenge12()?;
    challenge13()?;

    Ok(())
}
