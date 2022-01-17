type Result<T> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync + 'static>>;

pub trait Oracle {
    fn encrypt(&self, data: &[u8]) -> Result<Vec<u8>>;
}
